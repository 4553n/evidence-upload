package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"evidence-upload/internal/alerts"
	"evidence-upload/internal/config"
	"evidence-upload/internal/custody"
	"evidence-upload/internal/models"
	"evidence-upload/internal/server"
	"evidence-upload/internal/storage"
	"evidence-upload/internal/tlsutil"
	"evidence-upload/internal/tunnel"
)

func main() {
	cfg := config.Load()

	if cfg.ShowVersion {
		fmt.Printf("evidence-upload v%s\n", Version)
		os.Exit(0)
	}

	sessions := models.NewSessionManager(cfg.SecretKey)

	adminToken := cfg.AdminToken
	if adminToken == "" {
		var err error
		adminToken, err = models.NewToken(16)
		if err != nil {
			log.Fatalf("Failed to generate admin token: %v", err)
		}
	}

	tlsCert, tlsKey := cfg.TLSCert, cfg.TLSKey
	tlsFingerprint := ""
	if (tlsCert == "") != (tlsKey == "") {
		log.Fatal("Both -tls-cert and -tls-key are required to serve HTTPS")
	}
	if cfg.TLSSelfSigned && tlsCert == "" {
		extra := []string{}
		if h, err := os.Hostname(); err == nil {
			extra = append(extra, h)
		}
		if cfg.ExternalIP != "" {
			extra = append(extra, cfg.ExternalIP)
		}
		certPath, keyPath, fp, err := tlsutil.EnsureSelfSigned(filepath.Join(cfg.StoragePath, ".tls"), extra)
		if err != nil {
			log.Fatalf("Failed to prepare self-signed TLS certificate: %v", err)
		}
		tlsCert, tlsKey, tlsFingerprint = certPath, keyPath, fp
	}
	// Cloudflare tunnels terminate TLS at the edge and forward to a plain HTTP
	// origin on loopback; an auto-generated self-signed certificate would only
	// break that hop (cloudflared cannot verify it). Keep the origin plain
	// unless the user configured certificates explicitly.
	if cfg.Tunnel == "cloudflare" && cfg.TLSCert == "" && tlsCert != "" {
		fmt.Println("TLS: disabled on the Cloudflare tunnel origin (the edge already serves HTTPS to uploaders)")
		tlsCert, tlsKey, tlsFingerprint = "", "", ""
	}

	store, err := storage.New(cfg.StoragePath, cfg.BackupPath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Sessions persist to disk so upload links survive server restarts.
	sessions.SetPersistence(filepath.Join(cfg.StoragePath, ".sessions.json"))
	if n, err := sessions.Load(); err != nil {
		log.Printf("Warning: failed to restore sessions: %v", err)
	} else if n > 0 {
		log.Printf("Restored %d active session(s) from previous run", n)
	}

	alertMgr := alerts.NewManager(cfg.AlertEmail, cfg.AlertWebhook, cfg.AlertLogFile, cfg.AlertDesktop)

	srvConfig := &server.Config{
		Port:            cfg.Port,
		MaxUploadSize:   cfg.MaxUploadSize,
		SessionDuration: cfg.SessionDuration,
		BaseURL:         cfg.BaseURL,
		Version:         Version,
		AdminToken:      adminToken,
		ExternalIP:      cfg.ExternalIP,
	}

	srv := server.NewServer(srvConfig, sessions, store, alertMgr)

	var boreTunnel *tunnel.BoreTunnel
	var cloudflareTunnel *tunnel.CloudflareTunnel

	if cfg.Tunnel == "bore" {
		boreTunnel = tunnel.NewBoreTunnel()

		publicURL, err := boreTunnel.Start(cfg.Port)
		if err != nil {
			log.Fatalf("Failed to start bore tunnel: %v", err)
		}
		cfg.BaseURL = publicURL
		srvConfig.BaseURL = publicURL
	} else if cfg.Tunnel == "cloudflare" {
		cloudflareTunnel = tunnel.NewCloudflareTunnel(cfg.CloudflarePath, cfg.TunnelName, cfg.CloudflareDomain, cfg.CloudflareToken)

		if !cloudflareTunnel.IsInstalled() {
			if err := cloudflareTunnel.Install("."); err != nil {
				log.Fatalf("Failed to install cloudflared: %v", err)
			}
		}

		publicURL, err := cloudflareTunnel.Start(cfg.Port)
		if err != nil {
			log.Fatalf("Failed to start cloudflare tunnel: %v", err)
		}
		cfg.BaseURL = publicURL
		srvConfig.BaseURL = publicURL
	} else if cfg.Tunnel == "external" {
		if cfg.TunnelURL == "" {
			log.Fatal("External tunnel mode requires -tunnel-url flag")
		}
		cfg.BaseURL = cfg.TunnelURL
		srvConfig.BaseURL = cfg.TunnelURL
		fmt.Printf("Using external tunnel: %s\n", cfg.TunnelURL)
	}

	// With TLS enabled, generated links must use https (tunnel URLs arrive as http).
	scheme := "http"
	if tlsCert != "" {
		scheme = "https"
		if strings.HasPrefix(cfg.BaseURL, "http://") {
			cfg.BaseURL = "https://" + strings.TrimPrefix(cfg.BaseURL, "http://")
			srvConfig.BaseURL = cfg.BaseURL
		}
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Printf("Evidence Upload Server v%s starting on %s\n", Version, addr)
	fmt.Printf("Storage: %s\n", cfg.StoragePath)
	fmt.Printf("Base URL: %s\n", cfg.BaseURL)
	fmt.Printf("Admin token: %s  (keep private; set via -admin-token or ADMIN_TOKEN)\n", adminToken)
	if tlsCert != "" {
		fmt.Printf("TLS: HTTPS enabled (cert: %s)\n", tlsCert)
		if tlsFingerprint != "" {
			fmt.Printf("TLS fingerprint (SHA-256): %s\n", tlsFingerprint)
		}
	}
	if cfg.BackupPath != "" {
		fmt.Printf("Backup: %s\n", cfg.BackupPath)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		if boreTunnel != nil {
			boreTunnel.Stop()
		}
		if cloudflareTunnel != nil {
			cloudflareTunnel.Stop()
		}
		os.Exit(0)
	}()

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			expired := sessions.CleanupExpired()
			for _, s := range expired {
				cocPath, err := custody.GenerateCoC(s, "System (expired)", cfg.StoragePath, Version)
				if err != nil {
					log.Printf("Failed to generate CoC for expired session %s: %v", s.Token[:16], err)
				} else {
					log.Printf("Generated CoC for expired session: %s", cocPath)
				}
			}
		}
	}()

	if !cfg.NoBrowser {
		go func() {
			time.Sleep(1 * time.Second)
			base := cfg.BaseURL
			if base == "" {
				base = fmt.Sprintf("%s://localhost:%d", scheme, cfg.Port)
			}
			adminURL := base + "/admin?key=" + adminToken
			fmt.Println("Opening admin interface...")
			openBrowser(adminURL)
		}()
	}

	log.Fatal(srv.ListenAndServe(addr, tlsCert, tlsKey))
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("Failed to open browser: %v", err)
	}
}
