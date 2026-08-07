package models

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ActivityEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent,omitempty"`
	Details   string    `json:"details,omitempty"`
}

type Session struct {
	Token         string           `json:"token"`
	Secret        string           `json:"secret"`
	CreatedAt     time.Time        `json:"created_at"`
	ExpiresAt     time.Time        `json:"expires_at"`
	Description   string           `json:"description"`
	FolderName    string           `json:"folder_name"`
	UploaderIP    string           `json:"uploader_ip,omitempty"`
	IsLocked      bool             `json:"is_locked"`
	UploadedFiles []UploadedFile   `json:"uploaded_files"`
	TotalSize     int64            `json:"total_size"`
	Activity      []ActivityEvent  `json:"activity"`
}

type UploadedFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Hash string `json:"hash,omitempty"`
}

type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	secret   []byte
}

func NewSessionManager(secret string) *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
		secret:   []byte(secret),
	}
}

var invalidChars = regexp.MustCompile(`[^\w\-\.]`)

func SanitizeFolderName(name string) string {
	name = strings.TrimSpace(name)
	name = invalidChars.ReplaceAllString(name, "_")
	name = strings.ReplaceAll(name, "__", "_")
	name = strings.Trim(name, "_.")
	if name == "" {
		name = "unnamed"
	}
	return name
}

func (sm *SessionManager) CreateSession(duration time.Duration, description string) (*Session, error) {
	token, err := generateToken(32)
	if err != nil {
		return nil, err
	}
	secret, err := generateToken(32)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Token:         token,
		Secret:        secret,
		CreatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(duration),
		Description:   description,
		FolderName:    SanitizeFolderName(description),
		UploadedFiles: make([]UploadedFile, 0),
		Activity:      make([]ActivityEvent, 0),
	}

	sm.mu.Lock()
	sm.sessions[token] = session
	sm.mu.Unlock()

	return session, nil
}

func (sm *SessionManager) GetSession(token string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[token]
	if !ok {
		return nil, false
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

func (sm *SessionManager) CleanupExpired() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for token, session := range sm.sessions {
		if time.Now().After(session.ExpiresAt) {
			delete(sm.sessions, token)
		}
	}
}

func (sm *SessionManager) ValidateToken(token, secret string) bool {
	session, ok := sm.GetSession(token)
	if !ok {
		return false
	}

	return hmac.Equal([]byte(session.Secret), []byte(secret))
}

func (sm *SessionManager) LockSession(token, ip string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[token]
	if !ok {
		return false
	}

	if session.IsLocked && session.UploaderIP != ip {
		return false
	}

	session.UploaderIP = ip
	session.IsLocked = true
	return true
}

func (sm *SessionManager) AddUploadedFile(token, filename, hash string, size int64) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[token]
	if !ok {
		return
	}

	session.UploadedFiles = append(session.UploadedFiles, UploadedFile{
		Name: filename,
		Size: size,
		Hash: hash,
	})
	session.TotalSize += size
}

func (sm *SessionManager) AddActivity(token, action, ip, userAgent, details string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[token]
	if !ok {
		return
	}

	session.Activity = append(session.Activity, ActivityEvent{
		Timestamp: time.Now(),
		Action:    action,
		IP:        ip,
		UserAgent: userAgent,
		Details:   details,
	})
}

func (sm *SessionManager) GetSessionDetail(token string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[token]
	if !ok {
		return nil, false
	}

	return session, true
}

func (sm *SessionManager) ListSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		if time.Now().Before(s.ExpiresAt) {
			sessions = append(sessions, s)
		}
	}
	return sessions
}

func (sm *SessionManager) RevokeSession(token string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	_, ok := sm.sessions[token]
	if ok {
		delete(sm.sessions, token)
	}
	return ok
}

func generateToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
