package config

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	Port             int
	StoragePath      string
	BackupPath       string
	SessionDuration  time.Duration
	SecretKey        string
	MaxUploadSize    int64
	AlertEmail       string
	AlertWebhook     string
	AlertDesktop     bool
	AlertLogFile     string
	ExternalIP       string
	BaseURL          string
	Tunnel           string
	BorePath         string
	CloudflarePath   string
	CloudflareDomain string
	CloudflareToken  string
	TunnelName       string
	TunnelURL        string
	ShowVersion      bool
}

func Load() *Config {
	cfg := &Config{}

	configFile := loadConfigFile()

	flag.IntVar(&cfg.Port, "port", getEnvOrConfigInt(configFile, "PORT", 8443), "Server port")
	flag.StringVar(&cfg.StoragePath, "storage", getEnvOrConfig(configFile, "STORAGE", "./evidence"), "Local storage path for uploaded files")
	flag.StringVar(&cfg.BackupPath, "backup", getEnvOrConfig(configFile, "BACKUP", ""), "Network share backup path (optional)")
	flag.DurationVar(&cfg.SessionDuration, "expire", 24*time.Hour, "Default session expiration duration")
	flag.StringVar(&cfg.SecretKey, "secret", getEnvOrConfig(configFile, "SECRET", ""), "HMAC secret key (auto-generated if empty)")
	flag.Int64Var(&cfg.MaxUploadSize, "max-size", 10<<30, "Maximum upload size in bytes (default 10GB)")
	flag.StringVar(&cfg.AlertEmail, "alert-email", getEnvOrConfig(configFile, "ALERT_EMAIL", ""), "Email address for unauthorized access alerts")
	flag.StringVar(&cfg.AlertWebhook, "alert-webhook", getEnvOrConfig(configFile, "ALERT_WEBHOOK", ""), "Webhook URL for alerts (Slack/Discord/etc)")
	flag.BoolVar(&cfg.AlertDesktop, "alert-desktop", true, "Enable desktop notifications")
	flag.StringVar(&cfg.AlertLogFile, "alert-log", "./alerts.log", "Log file for security alerts")
	flag.StringVar(&cfg.ExternalIP, "external-ip", getEnvOrConfig(configFile, "EXTERNAL_IP", ""), "External/public IP for internet access (auto-detected if empty)")
	flag.StringVar(&cfg.BaseURL, "base-url", getEnvOrConfig(configFile, "BASE_URL", ""), "Base URL for generated links (e.g., https://myhost:8443)")
	flag.StringVar(&cfg.Tunnel, "tunnel", getEnvOrConfig(configFile, "TUNNEL", ""), "Tunnel provider: 'bore', 'cloudflare', or 'external'")
	flag.StringVar(&cfg.BorePath, "bore-path", getEnvOrConfig(configFile, "BORE_PATH", ""), "Path to bore binary (auto-detected if empty)")
	flag.StringVar(&cfg.CloudflarePath, "cloudflare-path", getEnvOrConfig(configFile, "CLOUDFLARE_PATH", ""), "Path to cloudflared binary (auto-detected if empty)")
	flag.StringVar(&cfg.CloudflareDomain, "cloudflare-domain", getEnvOrConfig(configFile, "CLOUDFLARE_DOMAIN", ""), "Custom domain for Cloudflare tunnel (e.g., sabicirdf.com)")
	flag.StringVar(&cfg.CloudflareToken, "cloudflare-token", getEnvOrConfig(configFile, "CLOUDFLARE_TOKEN", ""), "Cloudflare tunnel token (from dashboard)")
	flag.StringVar(&cfg.TunnelName, "tunnel-name", getEnvOrConfig(configFile, "TUNNEL_NAME", ""), "Named tunnel for Cloudflare (creates if missing)")
	flag.StringVar(&cfg.TunnelURL, "tunnel-url", getEnvOrConfig(configFile, "TUNNEL_URL", ""), "External tunnel URL (for multi-analyst mode)")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Show version and exit")

	flag.Parse()

	if cfg.SecretKey == "" {
		cfg.SecretKey = generateSecretKey()
	}

	if cfg.StoragePath == "" {
		cfg.StoragePath = "./evidence"
	}

	if cfg.ExternalIP == "" {
		cfg.ExternalIP = detectExternalIP()
	}

	if cfg.BaseURL == "" {
		if cfg.ExternalIP != "" {
			cfg.BaseURL = fmt.Sprintf("http://%s:%d", cfg.ExternalIP, cfg.Port)
		} else {
			cfg.BaseURL = fmt.Sprintf("http://localhost:%d", cfg.Port)
		}
	}

	return cfg
}

func loadConfigFile() map[string]string {
	config := make(map[string]string)

	var configPath string
	if runtime.GOOS == "windows" {
		configPath = filepath.Join(os.Getenv("USERPROFILE"), ".evidence-upload.conf")
	} else {
		configPath = filepath.Join(os.Getenv("HOME"), ".evidence-upload.conf")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return config
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			value = strings.Trim(value, "\"'")
			config[key] = value
		}
	}

	return config
}

func getEnvOrConfig(config map[string]string, key, defaultValue string) string {
	if envVal := os.Getenv("EVIDENCE_" + key); envVal != "" {
		return envVal
	}
	if configVal, ok := config[key]; ok {
		return configVal
	}
	return defaultValue
}

func getEnvOrConfigInt(config map[string]string, key string, defaultValue int) int {
	if envVal := os.Getenv("EVIDENCE_" + key); envVal != "" {
		var val int
		if _, err := fmt.Sscanf(envVal, "%d", &val); err == nil {
			return val
		}
	}
	if configVal, ok := config[key]; ok {
		var val int
		if _, err := fmt.Sscanf(configVal, "%d", &val); err == nil {
			return val
		}
	}
	return defaultValue
}

func detectExternalIP() string {
	services := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
		"https://ipecho.net/plain",
	}

	client := &http.Client{Timeout: 5 * time.Second}

	for _, service := range services {
		resp, err := client.Get(service)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if ip != "" {
			fmt.Printf("Detected external IP: %s\n", ip)
			return ip
		}
	}

	fmt.Println("Warning: Could not detect external IP. Use -external-ip flag to set manually.")
	return ""
}

func generateSecretKey() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		panic("failed to generate secret key: " + err.Error())
	}
	return hex.EncodeToString(b)
}
