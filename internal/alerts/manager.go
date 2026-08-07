package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

type AlertType string

const (
	AlertUnauthorizedAccess AlertType = "UNAUTHORIZED_ACCESS"
	AlertSessionExpired     AlertType = "SESSION_EXPIRED"
	AlertSessionCreated     AlertType = "SESSION_CREATED"
	AlertFileUploaded       AlertType = "FILE_UPLOADED"
)

type Alert struct {
	Type      AlertType  `json:"type"`
	Token     string     `json:"token"`
	IP        string     `json:"ip"`
	UserAgent string     `json:"user_agent"`
	Timestamp time.Time  `json:"timestamp"`
	Message   string     `json:"message"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

type Manager struct {
	email    string
	webhook  string
	desktop  bool
	logFile  string
	client   *http.Client
	mu       sync.Mutex
}

func NewManager(email, webhook, logFile string, desktop bool) *Manager {
	return &Manager{
		email:   email,
		webhook: webhook,
		desktop: desktop,
		logFile: logFile,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (m *Manager) SendAlert(alertType AlertType, token, ip, userAgent, message string, details map[string]interface{}) {
	alert := Alert{
		Type:      alertType,
		Token:     token,
		IP:        ip,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Message:   message,
		Details:   details,
	}

	if m.email != "" {
		go m.sendEmailAlert(alert)
	}

	if m.webhook != "" {
		go m.sendWebhookAlert(alert)
	}

	if m.desktop {
		go m.sendDesktopAlert(alert)
	}

	if m.logFile != "" {
		go m.logAlertToFile(alert)
	}
}

func (m *Manager) sendEmailAlert(alert Alert) {
	subject := fmt.Sprintf("[%s] Security Alert - Evidence Upload", alert.Type)
	body := fmt.Sprintf(
		"Type: %s\nToken: %s\nIP: %s\nUser Agent: %s\nTime: %s\nMessage: %s",
		alert.Type, alert.Token, alert.IP, alert.UserAgent,
		alert.Timestamp.Format(time.RFC3339), alert.Message,
	)

	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", m.email, subject, body))

	auth := smtp.PlainAuth("", "", "", "localhost")
	err := smtp.SendMail("localhost:25", auth, "evidence-upload@localhost", []string{m.email}, msg)
	if err != nil {
		log.Printf("Failed to send email alert: %v", err)
	}
}

func (m *Manager) sendWebhookAlert(alert Alert) {
	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("Failed to marshal alert: %v", err)
		return
	}

	resp, err := m.client.Post(m.webhook, "application/json", bytes.NewBuffer(data))
	if err != nil {
		log.Printf("Failed to send webhook alert: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Webhook returned status %d", resp.StatusCode)
	}
}

func (m *Manager) sendDesktopAlert(alert Alert) {
	title := fmt.Sprintf("Evidence Upload - %s", alert.Type)
	message := fmt.Sprintf("IP: %s\n%s", alert.IP, alert.Message)

	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("notify-send", title, message)
		cmd.Run()
	case "windows":
		cmd := exec.Command("msg", "*", "/time:10", message)
		cmd.Run()
	}
}

func (m *Manager) logAlertToFile(alert Alert) {
	m.mu.Lock()
	defer m.mu.Unlock()

	file, err := os.OpenFile(m.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open alert log: %v", err)
		return
	}
	defer file.Close()

	logEntry := fmt.Sprintf("[%s] %s | Token: %s | IP: %s | UA: %s | %s\n",
		alert.Timestamp.Format(time.RFC3339),
		alert.Type,
		alert.Token,
		alert.IP,
		alert.UserAgent,
		alert.Message,
	)

	file.WriteString(logEntry)
}
