package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"evidence-upload/internal/alerts"
	"evidence-upload/internal/config"
	"evidence-upload/internal/custody"
	"evidence-upload/internal/models"
	"evidence-upload/internal/server"
	"evidence-upload/internal/storage"
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

	store, err := storage.New(cfg.StoragePath, cfg.BackupPath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	alertMgr := alerts.NewManager(cfg.AlertEmail, cfg.AlertWebhook, cfg.AlertLogFile, cfg.AlertDesktop)

	srvConfig := &server.Config{
		Port:            cfg.Port,
		MaxUploadSize:   cfg.MaxUploadSize,
		SessionDuration: cfg.SessionDuration,
		BaseURL:         cfg.BaseURL,
		Version:         Version,
		AdminToken:      adminToken,
	}

	srv := server.NewServer(srvConfig, sessions, store, alertMgr)

	var boreTunnel *tunnel.BoreTunnel
	var cloudflareTunnel *tunnel.CloudflareTunnel

	if cfg.Tunnel == "bore" {
		boreTunnel = tunnel.NewBoreTunnel(cfg.BorePath)

		if !boreTunnel.IsInstalled() {
			if err := boreTunnel.Install("."); err != nil {
				log.Fatalf("Failed to install bore: %v", err)
			}
		}

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

	addr := fmt.Sprintf(":%d", cfg.Port)
	fmt.Printf("Evidence Upload Server v%s starting on %s\n", Version, addr)
	fmt.Printf("Storage: %s\n", cfg.StoragePath)
	fmt.Printf("Base URL: %s\n", cfg.BaseURL)
	fmt.Printf("Admin token: %s  (keep private; set via -admin-token or ADMIN_TOKEN)\n", adminToken)
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
				cocPath, err := custody.GenerateCoC(s, "System (expired)", cfg.StoragePath)
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
				base = fmt.Sprintf("http://localhost:%d", cfg.Port)
			}
			adminURL := base + "/admin?key=" + adminToken
			fmt.Println("Opening admin interface...")
			openBrowser(adminURL)
		}()
	}

	log.Fatal(srv.ListenAndServe(addr))
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
