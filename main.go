package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"evidence-upload/internal/alerts"
	"evidence-upload/internal/config"
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

	log.Fatal(srv.ListenAndServe(addr))
}
