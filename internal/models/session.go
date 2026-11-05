package models

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
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
	Token          string           `json:"token"`
	Secret         string           `json:"secret"`
	ShortCode      string           `json:"short_code,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	ExpiresAt      time.Time        `json:"expires_at"`
	Description    string           `json:"description"`
	FolderName     string           `json:"folder_name"`
	UploaderIP     string           `json:"uploader_ip,omitempty"`
	IsLocked       bool             `json:"is_locked"`
	UploadedFiles  []UploadedFile   `json:"uploaded_files"`
	TotalSize      int64            `json:"total_size"`
	Activity       []ActivityEvent  `json:"activity"`
	TriagePackage  string           `json:"triage_package,omitempty"`
}

type UploadedFile struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	Hash string `json:"hash,omitempty"`
}

// snapshot returns a deep copy of the session, safe to JSON-encode while
// concurrent uploads may be mutating the original.
func (s *Session) snapshot() *Session {
	cp := *s
	cp.UploadedFiles = make([]UploadedFile, len(s.UploadedFiles))
	copy(cp.UploadedFiles, s.UploadedFiles)
	cp.Activity = make([]ActivityEvent, len(s.Activity))
	copy(cp.Activity, s.Activity)
	return &cp
}

// Clone returns a deep copy of the session.
func (s *Session) Clone() *Session {
	return s.snapshot()
}

type SessionManager struct {
	sessions     map[string]*Session
	revoked      map[string]time.Time
	revokedCodes map[string]string // short code -> token, kept after revocation
	mu           sync.RWMutex
	secret       []byte
	persist      string // path of the state file; empty disables persistence
}

type managerState struct {
	Sessions     map[string]*Session  `json:"sessions"`
	Revoked      map[string]time.Time `json:"revoked"`
	RevokedCodes map[string]string    `json:"revoked_codes"`
}

func NewSessionManager(secret string) *SessionManager {
	return &SessionManager{
		sessions:     make(map[string]*Session),
		revoked:      make(map[string]time.Time),
		revokedCodes: make(map[string]string),
		secret:       []byte(secret),
	}
}

// SetPersistence enables durable session storage at path. Sessions survive
// server restarts — without this, every restart silently invalidates every
// outstanding upload link.
func (sm *SessionManager) SetPersistence(path string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.persist = path
}

// Load restores persisted sessions and revocation records. Expired sessions
// are dropped. Returns the number of active sessions restored.
func (sm *SessionManager) Load() (int, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	data, err := os.ReadFile(sm.persist)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var st managerState
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, fmt.Errorf("parse session state: %w", err)
	}
	restored := 0
	now := time.Now()
	if st.Revoked != nil {
		for t, at := range st.Revoked {
			sm.revoked[t] = at
		}
	}
	if st.RevokedCodes != nil {
		for c, t := range st.RevokedCodes {
			sm.revokedCodes[c] = t
		}
	}
	for token, s := range st.Sessions {
		if s == nil || now.After(s.ExpiresAt) {
			continue
		}
		// Sessions created before short codes existed get one on load.
		if s.ShortCode == "" {
			code, err := sm.newUniqueCodeLocked()
			if err != nil {
				return restored, err
			}
			s.ShortCode = code
		}
		sm.sessions[token] = s
		restored++
	}
	sm.saveLocked()
	return restored, nil
}

// newUniqueCodeLocked generates a code not used by any active or revoked
// session. Callers must hold sm.mu.
func (sm *SessionManager) newUniqueCodeLocked() (string, error) {
	for attempts := 0; attempts < 100; attempts++ {
		code, err := generateShortCode()
		if err != nil {
			return "", err
		}
		taken := false
		for _, s := range sm.sessions {
			if s.ShortCode == code {
				taken = true
				break
			}
		}
		if _, ok := sm.revokedCodes[code]; ok {
			taken = true
		}
		if !taken {
			return code, nil
		}
	}
	return "", fmt.Errorf("could not allocate a unique short code")
}

// TokenByShortCode resolves a (possibly dashed/lowercase) short code to its
// session token. Comparison is constant-time over the code table so the
// response timing does not reveal which codes exist.
func (sm *SessionManager) TokenByShortCode(code string) (string, bool) {
	code = NormalizeShortCode(code)
	if code == "" {
		return "", false
	}
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	found := false
	token := ""
	target := []byte(code)
	for t, s := range sm.sessions {
		if subtle.ConstantTimeCompare([]byte(s.ShortCode), target) == 1 && !found {
			found, token = true, t
		}
	}
	for c, t := range sm.revokedCodes {
		if subtle.ConstantTimeCompare([]byte(c), target) == 1 && !found {
			found, token = true, t
		}
	}
	return token, found
}

// saveLocked persists the current state. Callers must hold sm.mu.
// The write is atomic (temp file + rename) and owner-readable only.
func (sm *SessionManager) saveLocked() {
	if sm.persist == "" {
		return
	}
	st := managerState{Sessions: sm.sessions, Revoked: sm.revoked, RevokedCodes: sm.revokedCodes}
	data, err := json.MarshalIndent(st, "", " ")
	if err != nil {
		log.Printf("Failed to serialize session state: %v", err)
		return
	}
	tmp := sm.persist + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("Failed to write session state: %v", err)
		return
	}
	if err := os.Rename(tmp, sm.persist); err != nil {
		log.Printf("Failed to save session state: %v", err)
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
	// Keep well under the 255-byte filesystem limit for path components.
	// The result is pure ASCII ([^\w\-.] is replaced), so runes == bytes here.
	if len(name) > 64 {
		name = strings.Trim(name[:64], "_.")
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
	code, err := sm.newUniqueCodeLocked()
	if err != nil {
		sm.mu.Unlock()
		return nil, err
	}
	session.ShortCode = code
	sm.sessions[token] = session
	sm.saveLocked()
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

	return session.snapshot(), true
}

func (sm *SessionManager) CleanupExpired() []*Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	var expired []*Session
	for token, session := range sm.sessions {
		if time.Now().After(session.ExpiresAt) {
			expired = append(expired, session)
			delete(sm.sessions, token)
		}
	}
	sm.saveLocked()
	return expired
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
	sm.saveLocked()
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
	sm.saveLocked()
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
	sm.saveLocked()
}

func (sm *SessionManager) GetSessionDetail(token string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[token]
	if !ok {
		return nil, false
	}

	return session.snapshot(), true
}

func (sm *SessionManager) ListSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		if time.Now().Before(s.ExpiresAt) {
			sessions = append(sessions, s.snapshot())
		}
	}
	return sessions
}

func (sm *SessionManager) RevokeSession(token string) (*Session, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[token]
	if ok {
		delete(sm.sessions, token)
		sm.revoked[token] = time.Now()
		if session.ShortCode != "" {
			sm.revokedCodes[session.ShortCode] = token
		}
		sm.saveLocked()
	}
	return session, ok
}

// SessionProblem reports why a token cannot be used: "" (fine), "revoked",
// "expired", or "unknown". This lets clients tell an uploader whose session was
// closed apart from a malformed or stale link.
func (sm *SessionManager) SessionProblem(token string) string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if session, ok := sm.sessions[token]; ok {
		if time.Now().After(session.ExpiresAt) {
			return "expired"
		}
		return ""
	}
	if _, ok := sm.revoked[token]; ok {
		return "revoked"
	}
	return "unknown"
}

func (sm *SessionManager) SetTriagePackage(token, filename string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session, ok := sm.sessions[token]
	if !ok {
		return
	}

	session.TriagePackage = filename
	sm.saveLocked()
}

func generateToken(length int) (string, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewToken returns a cryptographically random hex token (length in bytes).
func NewToken(length int) (string, error) {
	return generateToken(length)
}

// shortAlphabet is Crockford base32: no vowels (avoiding words) and no
// visually ambiguous characters (I, L, O, U excluded).
const shortAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ShortCodeLen is the length of hand-typable session codes (~40 bits of entropy).
const ShortCodeLen = 8

// generateShortCode returns a random hand-typable code like "K7M3Q9P2".
// The alphabet is 32 symbols, so masking a random byte with 0x1f is unbiased.
func generateShortCode() (string, error) {
	b := make([]byte, ShortCodeLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, ShortCodeLen)
	for i, c := range b {
		out[i] = shortAlphabet[int(c)&0x1f]
	}
	return string(out), nil
}

// NormalizeShortCode canonicalizes user input: uppercase, dashes and spaces
// removed. "k7m3-q9p2" and "K7M3 Q9P2" both become "K7M3Q9P2".
func NormalizeShortCode(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}

// FormatShortCode renders a code for display: "K7M3-Q9P2".
func FormatShortCode(code string) string {
	if len(code) == ShortCodeLen {
		return code[:4] + "-" + code[4:]
	}
	return code
}
