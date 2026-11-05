package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"evidence-upload/internal/alerts"
	"evidence-upload/internal/custody"
	"evidence-upload/internal/models"
	"evidence-upload/internal/storage"
)

type Server struct {
	cfg      *Config
	sessions *models.SessionManager
	storage  *storage.Storage
	alerts   *alerts.Manager
	mux      *http.ServeMux
	shortLim *shortLimiter
}

type Config struct {
	Port            int
	MaxUploadSize   int64
	SessionDuration time.Duration
	BaseURL         string
	Version         string
	AdminToken      string
	ExternalIP      string
}

func NewServer(cfg *Config, sessions *models.SessionManager, storage *storage.Storage, alertMgr *alerts.Manager) *Server {
	s := &Server{
		cfg:      cfg,
		sessions: sessions,
		storage:  storage,
		alerts:   alertMgr,
		mux:      http.NewServeMux(),
		shortLim: newShortLimiter(shortFailLimit, shortFailWindow),
	}

	s.routes()
	return s
}

// requireAdmin gates the admin API behind the admin token, sent either as
// X-Admin-Token or Authorization: Bearer. The /admin HTML shell is public (it
// contains no data); every data endpoint behind it is protected. Upload (/api)
// and triage download (/triage) endpoints keep their existing session-based auth.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.AdminToken == "" {
			writeJSONError(w, http.StatusServiceUnavailable, "admin token not configured; set -admin-token or ADMIN_TOKEN")
			return
		}
		got := r.Header.Get("X-Admin-Token")
		if got == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				got = strings.TrimPrefix(auth, "Bearer ")
			}
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminToken)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "invalid or missing admin token")
			return
		}
		next(w, r)
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", s.handleUpload)
	s.mux.HandleFunc("/api/upload", s.handleUploadFile)
	s.mux.HandleFunc("/api/upload/init", s.handleUploadInit)
	s.mux.HandleFunc("/api/upload/chunk", s.handleUploadChunk)
	s.mux.HandleFunc("/api/upload/complete", s.handleUploadComplete)
	s.mux.HandleFunc("/api/files", s.handleListFiles)
	s.mux.HandleFunc("/api/baseurl", s.handleBaseURL)
	s.mux.HandleFunc("/api/my-ip", s.handleMyIP)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/admin", s.handleAdmin)
	s.mux.HandleFunc("/admin/api/sessions", s.requireAdmin(s.handleAdminSessions))
	s.mux.HandleFunc("/admin/api/session", s.requireAdmin(s.handleAdminSessionDetail))
	s.mux.HandleFunc("/admin/api/revoke", s.requireAdmin(s.handleAdminRevoke))
	s.mux.HandleFunc("/admin/api/create", s.requireAdmin(s.handleAdminCreate))
	s.mux.HandleFunc("/admin/api/triage-package", s.requireAdmin(s.handleAdminTriagePackage))
	s.mux.HandleFunc("/triage/", s.handleTriageDownload)
	s.mux.HandleFunc("/e/", s.handleShortUpload)
	s.mux.HandleFunc("/t/", s.handleShortTriage)
}

// ListenAndServe serves plain HTTP, or HTTPS when certFile/keyFile are set.
func (s *Server) ListenAndServe(addr, certFile, keyFile string) error {
	if certFile != "" && keyFile != "" {
		log.Printf("Evidence Upload Server starting on %s (TLS)", addr)
		return http.ListenAndServeTLS(addr, certFile, keyFile, s.withRecovery(s.mux))
	}
	log.Printf("Evidence Upload Server starting on %s", addr)
	return http.ListenAndServe(addr, s.withRecovery(s.mux))
}

// statusRecorder captures the response status for request logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// withRecovery logs every request and converts handler panics into a proper
// 500 response instead of silently killing the connection (which surfaces in
// browsers as an opaque "Load failed" / "Failed to fetch").
// Only the URL path is logged; query strings may carry tokens and secrets.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if err := recover(); err != nil {
				log.Printf("PANIC on %s %s: %v\n%s", r.Method, r.URL.Path, err, debug.Stack())
				if rec.status == http.StatusOK {
					writeJSONError(rec, http.StatusInternalServerError, "internal server error")
				}
			}
			log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
		}()
		next.ServeHTTP(rec, r)
	})
}

// writeJSONError sends a JSON error body so admin UI fetches can surface the
// message instead of failing to parse plain-text responses.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   msg,
	})
}

// Short codes are ~40-bit bearer credentials; brute-force attempts are capped
// per client IP with a sliding window and reported through the alert channel.
const (
	shortFailLimit  = 5
	shortFailWindow = 5 * time.Minute
)

type shortLimiter struct {
	mu       sync.Mutex
	failures map[string][]time.Time
	limit    int
	window   time.Duration
}

func newShortLimiter(limit int, window time.Duration) *shortLimiter {
	return &shortLimiter{failures: make(map[string][]time.Time), limit: limit, window: window}
}

// blocked reports whether ip has exhausted its allowance within the window.
func (l *shortLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	kept := l.failures[ip][:0]
	for _, t := range l.failures[ip] {
		if now.Sub(t) < l.window {
			kept = append(kept, t)
		}
	}
	l.failures[ip] = kept
	return len(kept) >= l.limit
}

// fail records a failed attempt for ip.
func (l *shortLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[ip] = append(l.failures[ip], time.Now())
}

// resolveShortCode maps a short code to its session token, enforcing the
// per-IP rate limit and alerting on failed attempts. On failure a generic
// message is returned: the response never reveals whether a code exists.
func (s *Server) resolveShortCode(w http.ResponseWriter, r *http.Request, code string) (string, bool) {
	clientIP := getClientIP(r)
	if s.shortLim.blocked(clientIP) {
		http.Error(w, "Too many attempts - wait a few minutes and double-check the code", http.StatusTooManyRequests)
		return "", false
	}
	token, ok := s.sessions.TokenByShortCode(code)
	if !ok {
		s.shortLim.fail(clientIP)
		s.alerts.SendAlert(
			alerts.AlertUnauthorizedAccess,
			code,
			clientIP,
			r.UserAgent(),
			"Invalid short link access attempt",
			map[string]interface{}{"code": code, "path": r.URL.Path},
		)
		http.Error(w, "This link is invalid or expired", http.StatusNotFound)
		return "", false
	}
	return token, true
}

// handleShortUpload serves the upload page for /e/<code> links.
func (s *Server) handleShortUpload(w http.ResponseWriter, r *http.Request) {
	code := models.NormalizeShortCode(strings.TrimPrefix(r.URL.Path, "/e/"))
	token, ok := s.resolveShortCode(w, r, code)
	if !ok {
		return
	}
	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusUnauthorized)
		return
	}
	s.deliverUploadPage(w, r, session)
}

// handleShortTriage serves the triage package for /t/<code> links.
func (s *Server) handleShortTriage(w http.ResponseWriter, r *http.Request) {
	code := models.NormalizeShortCode(strings.TrimPrefix(r.URL.Path, "/t/"))
	token, ok := s.resolveShortCode(w, r, code)
	if !ok {
		return
	}
	s.serveTriage(w, r, token)
}

// deliverUploadPage applies IP binding and serves the uploader page. Used by
// both the long links (/) and the short links (/e/).
func (s *Server) deliverUploadPage(w http.ResponseWriter, r *http.Request, session *models.Session) {
	token := session.Token
	clientIP := getClientIP(r)
	if session.IsLocked && session.UploaderIP != clientIP {
		s.alerts.SendAlert(
			alerts.AlertUnauthorizedAccess,
			token,
			clientIP,
			r.UserAgent(),
			fmt.Sprintf("IP mismatch: expected %s, got %s", session.UploaderIP, clientIP),
			map[string]interface{}{
				"expected_ip": session.UploaderIP,
				"actual_ip":   clientIP,
			},
		)
		http.Error(w, "Unauthorized access detected", http.StatusForbidden)
		return
	}

	if !session.IsLocked {
		s.sessions.LockSession(token, clientIP)
		s.sessions.AddActivity(token, "page_access", clientIP, r.UserAgent(), "Upload page accessed")
	}

	w.Header().Set("Content-Type", "text/html")
	html := strings.Replace(uploadHTML, "{{TOKEN}}", session.Token, 1)
	html = strings.Replace(html, "{{SECRET}}", session.Secret, 1)
	html = strings.Replace(html, "{{DESCRIPTION}}", session.Description, 1)
	fmt.Fprint(w, html)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	if token == "" || secret == "" {
		http.Error(w, "Invalid upload link", http.StatusUnauthorized)
		return
	}

	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusUnauthorized)
		return
	}

	if !s.sessions.ValidateToken(token, secret) {
		s.alerts.SendAlert(
			alerts.AlertUnauthorizedAccess,
			token,
			r.RemoteAddr,
			r.UserAgent(),
			fmt.Sprintf("Invalid token/secret combination attempt"),
			nil,
		)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	s.deliverUploadPage(w, r, session)
}

func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxUploadSize)

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "File too large or bad request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	secret := r.FormValue("secret")

	if !s.sessions.ValidateToken(token, secret) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	clientIP := getClientIP(r)
	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusUnauthorized)
		return
	}

	if session.IsLocked && session.UploaderIP != clientIP {
		s.alerts.SendAlert(
			alerts.AlertUnauthorizedAccess,
			token,
			clientIP,
			r.UserAgent(),
			"IP mismatch during upload",
			nil,
		)
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "No files provided", http.StatusBadRequest)
		return
	}

	folderName := session.FolderName
	if folderName == "" {
		folderName = token
	}

	var uploadedFiles []map[string]interface{}

	for _, fileHeader := range files {
		file, err := fileHeader.Open()
		if err != nil {
			continue
		}

		sanitizedFilename := storage.SanitizeFilename(fileHeader.Filename)
		hash, size, err := s.storage.SaveFile(folderName, sanitizedFilename, file)
		file.Close()

		if err != nil {
			log.Printf("Failed to save file %s: %v", sanitizedFilename, err)
			continue
		}

		sessionDir := s.storage.GetSessionDir(folderName)
		finalPath := filepath.Join(sessionDir, sanitizedFilename)
		if err := storage.WriteHashFile(finalPath, hash); err != nil {
			log.Printf("Failed to write hash file for %s: %v", sanitizedFilename, err)
		}

		if s.storage.BackupPath() != "" {
			go s.backupFile(folderName, sanitizedFilename, finalPath)
		}

		s.sessions.AddUploadedFile(token, fileHeader.Filename, hash, size)
		s.sessions.AddActivity(token, "file_uploaded", clientIP, r.UserAgent(), fmt.Sprintf("File: %s (%d bytes)", fileHeader.Filename, size))

		uploadedFiles = append(uploadedFiles, map[string]interface{}{
			"filename":         fileHeader.Filename,
			"sanitized_filename": sanitizedFilename,
			"hash":             hash,
			"size":             size,
		})

		s.alerts.SendAlert(
			alerts.AlertFileUploaded,
			token,
			clientIP,
			r.UserAgent(),
			fmt.Sprintf("File uploaded: %s", fileHeader.Filename),
			map[string]interface{}{
				"filename": fileHeader.Filename,
				"size":     size,
				"hash":     hash,
			},
		)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"files":   uploadedFiles,
	})
}

type InitUploadRequest struct {
	Filename    string `json:"filename"`
	FileSize    int64  `json:"file_size"`
	ChunkSize   int64  `json:"chunk_size"`
	TotalChunks int    `json:"total_chunks"`
}

type InitUploadResponse struct {
	UploadID       string `json:"upload_id"`
	ExistingChunks []int  `json:"existing_chunks"`
	ResumeOffset   int64  `json:"resume_offset"`
}

func (s *Server) handleUploadInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	if !s.sessions.ValidateToken(token, secret) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	var req InitUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	uploadID := fmt.Sprintf("%s_%d", sanitizeFilename(req.Filename), req.FileSize)
	chunkDir := s.getChunkDir(token, uploadID)

	existingChunks := getExistingChunks(chunkDir)
	resumeOffset := int64(len(existingChunks)) * req.ChunkSize

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InitUploadResponse{
		UploadID:       uploadID,
		ExistingChunks: existingChunks,
		ResumeOffset:   resumeOffset,
	})
}

type ChunkUploadRequest struct {
	UploadID  string `json:"upload_id"`
	ChunkNum  int    `json:"chunk_num"`
	TotalChunks int  `json:"total_chunks"`
	Filename  string `json:"filename"`
}

func (s *Server) handleUploadChunk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	if !s.sessions.ValidateToken(token, secret) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	uploadID := r.FormValue("upload_id")
	chunkNum, _ := strconv.Atoi(r.FormValue("chunk_num"))

	file, _, err := r.FormFile("chunk")
	if err != nil {
		http.Error(w, "No chunk data", http.StatusBadRequest)
		return
	}
	defer file.Close()

	chunkDir := s.getChunkDir(token, uploadID)
	os.MkdirAll(chunkDir, 0755)

	chunkPath := filepath.Join(chunkDir, strconv.Itoa(chunkNum))
	outFile, err := os.Create(chunkPath)
	if err != nil {
		http.Error(w, "Failed to save chunk", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(outFile, hasher)
	written, err := io.Copy(writer, file)
	if err != nil {
		os.Remove(chunkPath)
		http.Error(w, "Failed to write chunk", http.StatusInternalServerError)
		return
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"chunk_num": chunkNum,
		"size":      written,
		"hash":      hash,
	})
}

type CompleteUploadRequest struct {
	UploadID    string `json:"upload_id"`
	Filename    string `json:"filename"`
	TotalChunks int    `json:"total_chunks"`
	FileSize    int64  `json:"file_size"`
}

func (s *Server) handleUploadComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	if !s.sessions.ValidateToken(token, secret) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusUnauthorized)
		return
	}

	var req CompleteUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	folderName := session.FolderName
	if folderName == "" {
		folderName = token
	}

	sanitizedFilename := storage.SanitizeFilename(req.Filename)
	chunkDir := s.getChunkDir(token, req.UploadID)
	sessionDir := s.storage.GetSessionDir(folderName)
	os.MkdirAll(sessionDir, 0755)

	finalPath := filepath.Join(sessionDir, sanitizedFilename)
	outFile, err := os.Create(finalPath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer outFile.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(outFile, hasher)

	for i := 0; i < req.TotalChunks; i++ {
		chunkPath := filepath.Join(chunkDir, strconv.Itoa(i))
		chunkData, err := os.ReadFile(chunkPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("Missing chunk %d", i), http.StatusBadRequest)
			return
		}
		writer.Write(chunkData)
	}

	hash := hex.EncodeToString(hasher.Sum(nil))
	os.RemoveAll(chunkDir)

	if err := storage.WriteHashFile(finalPath, hash); err != nil {
		log.Printf("Failed to write hash file for %s: %v", sanitizedFilename, err)
	}

	if s.storage.BackupPath() != "" {
		go s.backupFile(folderName, sanitizedFilename, finalPath)
	}

	s.sessions.AddUploadedFile(token, req.Filename, hash, req.FileSize)

	clientIP := getClientIP(r)
	s.sessions.AddActivity(token, "file_uploaded", clientIP, r.UserAgent(), fmt.Sprintf("File: %s (%d bytes)", req.Filename, req.FileSize))
	s.alerts.SendAlert(
		alerts.AlertFileUploaded,
		token,
		clientIP,
		r.UserAgent(),
		fmt.Sprintf("File uploaded: %s", req.Filename),
		map[string]interface{}{
			"filename": req.Filename,
			"size":     req.FileSize,
			"hash":     hash,
		},
	)

	if s.storage.BackupPath() != "" {
		go s.backupFile(token, req.Filename, finalPath)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"filename": req.Filename,
		"size":     req.FileSize,
		"hash":     hash,
	})
}

func (s *Server) getChunkDir(token, uploadID string) string {
	return filepath.Join(s.storage.BasePath(), ".chunks", token, uploadID)
}

func getExistingChunks(dir string) []int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []int{}
	}

	var chunks []int
	for _, entry := range entries {
		if !entry.IsDir() {
			if n, err := strconv.Atoi(entry.Name()); err == nil {
				chunks = append(chunks, n)
			}
		}
	}
	sort.Ints(chunks)
	return chunks
}

func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, " ", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	if len(name) > 50 {
		name = name[:50]
	}
	return name
}

func (s *Server) backupFile(token, filename, sourcePath string) {
	backupDir := filepath.Join(s.storage.BackupPath(), token)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return
	}
	defer sourceFile.Close()

	backupPath := filepath.Join(backupDir, filename)
	backupFile, err := os.Create(backupPath)
	if err != nil {
		return
	}
	defer backupFile.Close()

	io.Copy(backupFile, sourceFile)
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	if !s.sessions.ValidateToken(token, secret) {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusUnauthorized)
		return
	}

	folderName := session.FolderName
	if folderName == "" {
		folderName = token
	}

	type FileInfo struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
	}

	files, err := s.storage.ListFiles(folderName)
	if err != nil {
		http.Error(w, "Failed to list files", http.StatusInternalServerError)
		return
	}

	var fileInfos []FileInfo
	for _, name := range files {
		if strings.HasSuffix(name, ".sha256") {
			continue
		}
		size, _ := s.storage.GetFileSize(folderName, name)
		fileInfos = append(fileInfos, FileInfo{Name: name, Size: size})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": fileInfos,
	})
}

func (s *Server) handleBaseURL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"base_url": s.cfg.BaseURL,
	})
}

func (s *Server) handleMyIP(w http.ResponseWriter, r *http.Request) {
	ip := getClientIP(r)
	forwarded := r.Header.Get("X-Forwarded-For")
	realIP := r.Header.Get("X-Real-IP")
	proto := r.Proto

	publicIP := ""
	resp, err := http.Get("https://api.ipify.org?format=json")
	if err == nil {
		defer resp.Body.Close()
		var result struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
			publicIP = result.IP
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		// Uploader side (as observed by the server)
		"ip":          ip,
		"uploader_ip": ip,
		"forwarded":   forwarded,
		"real_ip":     realIP,
		// Server side
		"server_public_ip": serverPublicIP(publicIP, s.cfg.ExternalIP),
		"server_lan_ip":    serverLANIPs(),
		"public_ip":        publicIP, // legacy alias of the server's public IP
		"protocol":         proto,
		"user_agent":       r.UserAgent(),
	})
}

// serverPublicIP prefers the analyst-configured external IP over detection.
func serverPublicIP(detected, configured string) string {
	if configured != "" {
		return configured
	}
	return detected
}

// serverLANIPs lists the server's non-loopback IPv4 addresses.
func serverLANIPs() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "N/A"
	}
	var ips []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
			}
		}
	}
	if len(ips) == 0 {
		return "N/A"
	}
	return strings.Join(ips, ", ")
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, adminHTML)
}

func (s *Server) handleAdminSessions(w http.ResponseWriter, r *http.Request) {
	sessions := s.sessions.ListSessions()
	// Never expose upload secrets in the bulk list — a leaked list must not
	// hand out working upload links. The detail endpoint still provides the
	// secret for building a link for a specific session.
	for _, sess := range sessions {
		sess.Secret = ""
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

func (s *Server) handleAdminSessionDetail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeJSONError(w, http.StatusBadRequest, "Token required")
		return
	}

	session, ok := s.sessions.GetSessionDetail(token)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "Session not found")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Token       string `json:"token"`
		AnalystName string `json:"analyst_name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	session, ok := s.sessions.RevokeSession(req.Token)
	if !ok {
		writeJSONError(w, http.StatusNotFound, "Session not found or already revoked")
		return
	}

	analystName := req.AnalystName
	if analystName == "" {
		analystName = "Unknown Analyst"
	}

	cocPath, err := custody.GenerateCoC(session, analystName, s.storage.BasePath(), s.cfg.Version)
	if err != nil {
		log.Printf("Failed to generate CoC for session %s: %v", req.Token, err)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"warning": fmt.Sprintf("Session revoked but CoC generation failed: %v", err),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"coc_path": cocPath,
	})
}

func (s *Server) handleAdminCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Duration    time.Duration `json:"duration"`
		Description string        `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request: "+err.Error())
		return
	}

	session, err := s.sessions.CreateSession(req.Duration, req.Description)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Failed to create session: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

func (s *Server) handleAdminTriagePackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if !s.sessions.ValidateToken(token, "") {
		http.Error(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusUnauthorized)
		return
	}

	folderName := session.FolderName
	if folderName == "" {
		folderName = token
	}

	sanitizedFilename := storage.SanitizeFilename(header.Filename)
	triageFilename := "TRIAGE_PACKAGE_" + sanitizedFilename
	hash, size, err := s.storage.SaveFile(folderName, triageFilename, file)
	if err != nil {
		http.Error(w, "Failed to save triage package", http.StatusInternalServerError)
		return
	}

	sessionDir := s.storage.GetSessionDir(folderName)
	finalPath := filepath.Join(sessionDir, triageFilename)
	if err := storage.WriteHashFile(finalPath, hash); err != nil {
		log.Printf("Failed to write hash file for triage package: %v", err)
	}

	s.sessions.SetTriagePackage(token, triageFilename)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"filename": triageFilename,
		"size":     size,
	})
}

func (s *Server) handleTriageDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/triage/")
	if token == "" {
		http.Error(w, "Token required", http.StatusBadRequest)
		return
	}
	s.serveTriage(w, r, token)
}

// serveTriage delivers the session's triage package. Used by both /triage/
// (long link) and /t/ (short link).
func (s *Server) serveTriage(w http.ResponseWriter, r *http.Request, token string) {
	session, ok := s.sessions.GetSession(token)
	if !ok {
		s.rejectSession(w, token, http.StatusNotFound)
		return
	}

	if session.TriagePackage == "" {
		http.Error(w, "No triage package available for this session", http.StatusNotFound)
		return
	}

	folderName := session.FolderName
	if folderName == "" {
		folderName = token
	}

	filePath := filepath.Join(s.storage.GetSessionDir(folderName), session.TriagePackage)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "Triage package file not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\""+session.TriagePackage+"\"")
	http.ServeFile(w, r, filePath)
}

// sessionProblemMessage explains why a token is unusable, distinguishing a
// closed session from a stale or malformed link.
func sessionProblemMessage(problem string) string {
	switch problem {
	case "revoked":
		return "This session has been closed by the analyst"
	case "expired":
		return "This session has expired"
	default:
		return "Session not found - the link may be invalid or from a previous server run"
	}
}

// rejectSession writes the precise reason a token cannot be used.
func (s *Server) rejectSession(w http.ResponseWriter, token string, status int) {
	http.Error(w, sessionProblemMessage(s.sessions.SessionProblem(token)), status)
}

// handleStatus lets the uploader's page detect that its session was closed
// (revoked or expired) and stop collecting gracefully.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	secret := r.URL.Query().Get("secret")

	problem := s.sessions.SessionProblem(token)
	if problem == "" && !s.sessions.ValidateToken(token, secret) {
		problem = "unknown"
	}

	w.Header().Set("Content-Type", "application/json")
	if problem != "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid":  false,
			"reason": problem,
		})
		return
	}
	session, _ := s.sessions.GetSession(token)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":      true,
		"expires_at": session.ExpiresAt,
	})
}

func getClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return strings.TrimSpace(realIP)
	}

	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		addr = addr[:idx]
	}
	addr = strings.Trim(addr, "[]")
	return addr
}

var uploadHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Evidence Upload</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { max-width: 600px; width: 90` + `%; padding: 40px; background: #16213e; border-radius: 12px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }
        h1 { text-align: center; margin-bottom: 10px; color: #0f3460; font-size: 1.5em; }
        .case-info { text-align: center; margin-bottom: 25px; padding: 12px; background: #0f3460; border-radius: 6px; font-size: 0.95em; }
        .case-info .label { color: #888; font-size: 0.85em; }
        .case-info .value { color: #e94560; font-weight: bold; font-size: 1.1em; margin-top: 4px; }
        .ip-info { text-align: center; margin-bottom: 25px; padding: 12px; background: #0f3460; border-radius: 6px; font-size: 0.95em; }
        .ip-info .label { color: #888; font-size: 0.85em; }
        .ip-info .value { color: #4caf50; font-weight: bold; font-size: 1em; font-family: monospace; }
        .ip-info .ip-row { display: flex; justify-content: center; align-items: center; gap: 8px; margin-top: 6px; }
        .ip-info .ip-label { color: #888; font-size: 0.9em; }
        .btn-small { padding: 6px 12px; background: #2196F3; color: white; border: none; border-radius: 4px; font-size: 12px; cursor: pointer; margin-top: 8px; }
        .btn-small:hover { background: #1976D2; }
        .drop-zone { border: 3px dashed #0f3460; border-radius: 8px; padding: 60px 20px; text-align: center; cursor: pointer; transition: all 0.3s; }
        .drop-zone:hover, .drop-zone.dragover { border-color: #e94560; background: rgba(233,69,96,0.1); }
        .drop-zone p { color: #888; margin-bottom: 15px; }
        .btn { display: block; width: 100` + `%; padding: 15px; background: #e94560; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; margin-top: 20px; }
        .btn:hover { background: #c73e54; }
        .btn:disabled { background: #555; cursor: not-allowed; }
        #fileList { margin-top: 20px; max-height: 200px; overflow-y: auto; }
        .file-item { padding: 10px; background: #0f3460; border-radius: 4px; margin-bottom: 5px; display: flex; justify-content: space-between; align-items: center; }
        .file-item .name { flex: 1; }
        .file-item .size { color: #888; margin-left: 10px; white-space: nowrap; }
        .progress { margin-top: 20px; display: none; }
        .progress-bar { height: 6px; background: #333; border-radius: 3px; overflow: hidden; }
        .progress-fill { height: 100` + `%; background: #e94560; width: 0` + `%; transition: width 0.3s; }
        .progress-text { font-size: 0.85em; color: #888; margin-top: 8px; text-align: center; }
        .status { margin-top: 15px; text-align: center; }
        .success { color: #4caf50; }
        .error { color: #f44336; }
        .closed-banner { display: none; background: #7f1d1d; color: #fecaca; padding: 18px 22px; border-radius: 8px; margin-bottom: 22px; font-size: 15px; line-height: 1.6; }
        .closed-banner.visible { display: block; }
        input[type="file"] { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <div class="closed-banner" id="closedBanner"></div>
        <h1>Secure Evidence Upload</h1>
        <div class="case-info">
            <div class="label">Case Reference</div>
            <div class="value">{{DESCRIPTION}}</div>
        </div>
        <div class="ip-info" id="ipInfo">
            <div class="label">IP Detection</div>
            <div class="ip-row">
                <span class="ip-label">Your IP (as seen by server):</span>
                <span class="value" id="ipAddress">Detecting...</span>
            </div>
            <div class="ip-row">
                <span class="ip-label">Your local IPs:</span>
                <span class="value" id="localIps">Detecting...</span>
            </div>
            <div class="ip-row">
                <span class="ip-label">Server public IP:</span>
                <span class="value" id="serverIp">Detecting...</span>
            </div>
            <button class="btn-small" id="sendIpBtn" style="display:none;">Send IP Info</button>
            <div id="ipStatus" style="margin-top: 8px; font-size: 0.85em;"></div>
        </div>
        <div class="drop-zone" id="dropZone">
            <p>Drag & drop files or folders here</p>
            <p>or click to select</p>
        </div>
        <input type="file" id="fileInput" multiple>
        <button class="btn" id="uploadBtn" disabled>Upload Files</button>
        <div class="progress" id="progress">
            <div class="progress-bar"><div class="progress-fill" id="progressFill"></div></div>
            <div class="progress-text" id="progressText"></div>
        </div>
        <div id="status" class="status"></div>
        <div id="fileList"></div>
    </div>
    <script>
        const CHUNK_SIZE = 5 * 1024 * 1024;
        const dropZone = document.getElementById('dropZone');
        const fileInput = document.getElementById('fileInput');
        const uploadBtn = document.getElementById('uploadBtn');
        const fileList = document.getElementById('fileList');
        const progress = document.getElementById('progress');
        const progressFill = document.getElementById('progressFill');
        const progressText = document.getElementById('progressText');
        const status = document.getElementById('status');
        const token = '{{TOKEN}}';
        const secret = '{{SECRET}}';
        let selectedFiles = [];
        let uploading = false;
        let myIpData = null;

        // Browser-observed local interface addresses (WebRTC host candidates).
        async function browserLocalIPs() {
            try {
                const pc = new RTCPeerConnection({iceServers: []});
                pc.createDataChannel('x');
                const ips = new Set();
                pc.onicecandidate = (e) => {
                    if (!e.candidate || !e.candidate.candidate) return;
                    const parts = e.candidate.candidate.split(' ');
                    if (parts.length > 4 && parts[4] && parts[4] !== '0.0.0.0') ips.add(parts[4]);
                };
                await pc.setLocalDescription(await pc.createOffer());
                await new Promise(r => setTimeout(r, 1500));
                pc.close();
                return Array.from(ips).join(', ') || 'N/A';
            } catch (e) {
                return 'N/A';
            }
        }

        async function fetchMyIP() {
            try {
                const resp = await fetch('/api/my-ip');
                myIpData = await resp.json();
                myIpData.local_ips = await browserLocalIPs();
                document.getElementById('ipAddress').textContent = myIpData.uploader_ip || myIpData.ip || 'Unable to detect';
                document.getElementById('localIps').textContent = myIpData.local_ips;
                document.getElementById('serverIp').textContent = myIpData.server_public_ip || myIpData.public_ip || 'Unable to detect';
                document.getElementById('sendIpBtn').style.display = 'inline-block';
            } catch (e) {
                document.getElementById('ipAddress').textContent = 'Unable to detect';
                document.getElementById('localIps').textContent = 'Unable to detect';
                document.getElementById('serverIp').textContent = 'Unable to detect';
            }
        }

        // Watch the session: when the analyst revokes it (or it expires), tell
        // the uploader and stop collecting.
        let sessionClosed = false;
        function closeSessionUI(reason) {
            if (sessionClosed) return;
            sessionClosed = true;
            const banner = document.getElementById('closedBanner');
            banner.innerHTML = reason === 'expired'
                ? '<strong>This upload session has expired.</strong><br>Evidence collection has ended. Please contact the analyst if you still need to send files.'
                : '<strong>This upload session has been closed by the analyst.</strong><br>Evidence collection has ended. Thank you for your cooperation.';
            banner.classList.add('visible');
            setUploadEnabled(false);
            uploading = true; // blocks any further drop/click handling
            const btn = document.getElementById('sendIpBtn');
            if (btn) btn.style.display = 'none';
        }

        async function checkSessionStatus() {
            if (sessionClosed) return;
            try {
                const resp = await fetch('/api/status?token=' + token + '&secret=' + secret);
                const data = await resp.json();
                if (!data.valid) closeSessionUI(data.reason);
            } catch (e) {
                // transient network issue - keep trying
            }
        }
        setInterval(checkSessionStatus, 10000);
        checkSessionStatus();

        function setUploadEnabled(enabled) {
            dropZone.style.opacity = enabled ? '1' : '0.5';
            dropZone.style.pointerEvents = enabled ? 'auto' : 'none';
            fileInput.disabled = !enabled;
            uploadBtn.disabled = !enabled || selectedFiles.length === 0;
        }

        setUploadEnabled(false);

        document.getElementById('sendIpBtn').addEventListener('click', async () => {
            if (!myIpData) return;
            const btn = document.getElementById('sendIpBtn');
            const ipStatus = document.getElementById('ipStatus');
            btn.disabled = true;
            btn.textContent = 'Sending...';
            ipStatus.innerHTML = '';

            const content = [
                'IP Detection Report',
                '===================',
                'Date: ' + new Date().toISOString(),
                'Uploader IP (as seen by server): ' + (myIpData.uploader_ip || myIpData.ip || 'N/A'),
                'Uploader Local IP: ' + (myIpData.local_ips || 'N/A'),
                'Server Public IP: ' + (myIpData.server_public_ip || myIpData.public_ip || 'N/A'),
                'Server LAN IP: ' + (myIpData.server_lan_ip || 'N/A'),
                'Forwarded For: ' + (myIpData.forwarded || 'N/A'),
                'Real IP Header: ' + (myIpData.real_ip || 'N/A'),
                'Protocol: ' + myIpData.protocol,
                'User Agent: ' + myIpData.user_agent
            ].join('\n');

            const filename = 'ip_detection_' + (myIpData.uploader_ip || myIpData.ip || 'unknown').replace(/[^a-zA-Z0-9]/g, '_') + '.txt';
            const blob = new Blob([content], {type: 'text/plain'});
            const file = new File([blob], filename, {type: 'text/plain'});

            try {
                await uploadFile(file);
                btn.textContent = 'IP Info Sent';
                btn.style.background = '#4caf50';
                ipStatus.innerHTML = '<span class="success">IP information uploaded successfully.</span>';
                setUploadEnabled(true);
                loadExistingFiles();
            } catch (e) {
                btn.disabled = false;
                btn.textContent = 'Send IP Info';
                ipStatus.innerHTML = '<span class="error">Failed to send IP info: ' + e.message + '</span>';
            }
        });

        fetchMyIP();

        dropZone.addEventListener('click', () => { if (!uploading && !fileInput.disabled) fileInput.click(); });
        dropZone.addEventListener('dragover', (e) => { e.preventDefault(); if (!uploading) dropZone.classList.add('dragover'); });
        dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (!uploading) handleFiles(e.dataTransfer.files);
        });
        fileInput.addEventListener('change', (e) => handleFiles(e.target.files));

        function handleFiles(files) {
            selectedFiles = Array.from(files);
            fileList.innerHTML = '';
            selectedFiles.forEach(f => {
                const div = document.createElement('div');
                div.className = 'file-item';
                div.innerHTML = '<span class="name">' + f.name + '</span><span class="size">' + formatSize(f.size) + '</span>';
                fileList.appendChild(div);
            });
            uploadBtn.disabled = selectedFiles.length === 0;
        }

        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
            if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
            return (bytes / 1073741824).toFixed(2) + ' GB';
        }

        function updateProgress(loaded, total, text) {
            if (total > 0) {
                progressFill.style.width = (loaded / total * 100) + '` + `%';
            }
            progressText.textContent = text || '';
        }

        async function uploadFile(file) {
            const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
            const initResp = await fetch('/api/upload/init?token=' + token + '&secret=' + secret, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    filename: file.name,
                    file_size: file.size,
                    chunk_size: CHUNK_SIZE,
                    total_chunks: totalChunks
                })
            });
            const initData = await initResp.json();
            const uploadId = initData.upload_id;
            const existingChunks = new Set(initData.existing_chunks || []);

            let uploadedBytes = 0;
            for (let i = 0; i < totalChunks; i++) {
                if (existingChunks.has(i)) {
                    const chunkEnd = Math.min((i + 1) * CHUNK_SIZE, file.size);
                    uploadedBytes += chunkEnd - (i * CHUNK_SIZE);
                    continue;
                }

                const start = i * CHUNK_SIZE;
                const end = Math.min(start + CHUNK_SIZE, file.size);
                const chunk = file.slice(start, end);

                const formData = new FormData();
                formData.append('upload_id', uploadId);
                formData.append('chunk_num', i);
                formData.append('total_chunks', totalChunks);
                formData.append('filename', file.name);
                formData.append('chunk', chunk, file.name);

                const resp = await fetch('/api/upload/chunk?token=' + token + '&secret=' + secret, {
                    method: 'POST',
                    body: formData
                });

                if (!resp.ok) throw new Error('Chunk upload failed');

                const chunkData = await resp.json();
                uploadedBytes += chunkData.size || (end - start);
                updateProgress(uploadedBytes, file.size, file.name + ': ' + formatSize(uploadedBytes) + ' / ' + formatSize(file.size));
            }

            const completeResp = await fetch('/api/upload/complete?token=' + token + '&secret=' + secret, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    upload_id: uploadId,
                    filename: file.name,
                    total_chunks: totalChunks,
                    file_size: file.size
                })
            });

            if (!completeResp.ok) throw new Error('Failed to finalize upload');
            return await completeResp.json();
        }

        uploadBtn.addEventListener('click', async () => {
            if (selectedFiles.length === 0 || uploading) return;
            uploading = true;
            uploadBtn.disabled = true;
            progress.style.display = 'block';
            status.innerHTML = '';

            let totalBytes = 0;
            let loadedBytes = 0;
            selectedFiles.forEach(f => totalBytes += f.size);

            try {
                for (const file of selectedFiles) {
                    updateProgress(loadedBytes, totalBytes, 'Uploading ' + file.name + '...');
                    await uploadFile(file);
                    loadedBytes += file.size;
                }
                status.innerHTML = '<span class="success">All files uploaded successfully!</span>';
                selectedFiles = [];
                fileList.innerHTML = '';
                progressFill.style.width = '0` + `%';
                progressText.textContent = '';
                progress.style.display = 'none';
                loadExistingFiles();
            } catch (e) {
                status.innerHTML = '<span class="error">Upload failed: ' + e.message + '</span>';
            } finally {
                uploading = false;
                uploadBtn.disabled = selectedFiles.length === 0;
            }
        });

        async function loadExistingFiles() {
            try {
                const resp = await fetch('/api/files?token=' + token + '&secret=' + secret);
                const data = await resp.json();
                if (data.files && data.files.length > 0) {
                    fileList.innerHTML = '<h3 style="margin: 15px 0 10px; color: #0f3460;">Uploaded Files:</h3>';
                    data.files.forEach(f => {
                        const div = document.createElement('div');
                        div.className = 'file-item';
                        div.innerHTML = '<span class="name">' + f.name + '</span><span class="size">' + formatSize(f.size) + '</span>';
                        fileList.appendChild(div);
                    });
                }
            } catch (e) {}
        }

        loadExistingFiles();
    </script>
</body>
</html>`

var adminHTML = `<!DOCTYPE html>
<html>
<head>
    <title>Evidence Upload - Admin</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; padding: 40px; }
        .container { max-width: 1000px; margin: 0 auto; }
        h1 { margin-bottom: 5px; color: #0f3460; }
        .version { color: #888; font-size: 0.9em; margin-bottom: 25px; }
        .token-bar { background: #16213e; border: 1px solid #2a3a5c; border-radius: 6px; padding: 10px 14px; margin-bottom: 25px; font-size: 0.9em; color: #aaa; display: flex; align-items: center; gap: 10px; }
        .token-bar code { color: #7fd4ff; font-size: 0.95em; word-break: break-all; flex: 1; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
        .card h2 { margin-bottom: 15px; color: #0f3460; font-size: 1.2em; }
        table { width: 100` + `%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background: #0f3460; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        .btn-primary { background: #e94560; color: white; }
        .btn-danger { background: #f44336; color: white; }
        .btn-info { background: #2196F3; color: white; }
        .btn:hover { opacity: 0.8; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #888; }
        .form-group input, .form-group select { width: 100` + `%; padding: 10px; background: #0f3460; border: 1px solid #333; border-radius: 4px; color: white; }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.8); align-items: center; justify-content: center; z-index: 1000; }
        .modal.active { display: flex; }
        .modal-content { background: #16213e; padding: 30px; border-radius: 8px; width: 600px; max-height: 80` + `%; overflow-y: auto; }
        .modal-content h2 { margin-bottom: 20px; color: #0f3460; }
        .detail-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333; }
        .detail-label { color: #888; }
        .detail-value { color: #eee; font-family: monospace; word-break: break-all; }
        .activity-item { padding: 10px; background: #0f3460; border-radius: 4px; margin-bottom: 8px; font-size: 0.9em; }
        .activity-time { color: #888; font-size: 0.85em; }
        .activity-action { color: #e94560; font-weight: bold; }
        .activity-details { color: #ccc; margin-top: 4px; }
        .link-box { background: #0f3460; padding: 10px; border-radius: 4px; word-break: break-all; margin-top: 10px; font-family: monospace; font-size: 12px; }
        .short-link { font-family: "DejaVu Sans Mono", monospace; font-size: 1.15em; font-weight: bold; color: #7fd4ff; background: #0f3460; padding: 14px; border-radius: 6px; word-break: break-all; margin: 12px 0 8px; }
        .code-row { color: #888; margin: 8px 0; display: flex; align-items: center; gap: 10px; }
        .code-row code { color: #eee; font-size: 1.15em; letter-spacing: 3px; }
        .token-link { color: #2196F3; cursor: pointer; text-decoration: underline; }
        .token-link:hover { color: #64B5F6; }
        .refresh-info { float: right; font-size: 0.6em; color: #888; font-weight: normal; }
        .file-list { margin-top: 4px; }
        .file-name { font-size: 0.78em; color: #aaa; font-family: monospace; word-break: break-all; }
        .file-hash { font-size: 0.72em; color: #666; font-family: monospace; }
        .file-item { padding: 10px; background: #0f3460; border-radius: 4px; margin-bottom: 8px; }
        .file-item-name { color: #eee; font-weight: bold; word-break: break-all; }
        .file-item-meta { color: #888; font-size: 0.85em; margin-top: 4px; }
        .hash-row { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
        .hash-value { color: #8bc34a; font-family: monospace; font-size: 0.78em; word-break: break-all; flex: 1; }
        .btn-small { padding: 4px 10px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Evidence Upload - Admin Panel</h1>
        <div class="version" id="appVersion"></div>
        <div class="token-bar">
            <span>Admin token:</span>
            <code id="tokenValue">(loading...)</code>
            <button class="btn btn-info btn-small" onclick="copyAdminToken()">Copy</button>
        </div>
        <div class="card">
            <h2>Active Sessions <span class="refresh-info" id="refreshInfo"></span></h2>
            <table id="sessionsTable">
                <thead>
                    <tr><th>Token</th><th>Description</th><th>Created</th><th>Expires</th><th>Files</th><th>Actions</th></tr>
                </thead>
                <tbody id="sessionsBody"></tbody>
            </table>
            <button class="btn btn-primary" onclick="showCreateModal()" style="margin-top: 15px;">Create New Session</button>
        </div>
    </div>

    <div class="modal" id="createModal">
        <div class="modal-content">
            <h2>Create Upload Session</h2>
            <div class="form-group">
                <label>Duration (hours)</label>
                <input type="number" id="duration" value="24" min="1">
            </div>
            <div class="form-group">
                <label>Description</label>
                <input type="text" id="description" placeholder="Case number, etc.">
            </div>
            <button class="btn btn-primary" onclick="createSession()">Generate Link</button>
            <button class="btn" onclick="closeModal()" style="margin-left: 10px;">Cancel</button>
        </div>
    </div>

    <div class="modal" id="linkModal">
        <div class="modal-content">
            <h2>Upload Link Generated</h2>
            <p>Share this short link with the uploader — it can also be typed by hand:</p>
            <div class="short-link" id="generatedShortLink"></div>
            <div class="code-row">Short code: <code id="generatedShortCode"></code>
                <button class="btn btn-info btn-small" onclick="copyText(document.getElementById('generatedShortCode').textContent)">Copy Code</button>
            </div>
            <button class="btn btn-primary" onclick="copyLink()" style="margin-top: 15px;">Copy Short Link</button>
            <button class="btn" onclick="closeLinkModal()" style="margin-left: 10px;">Close</button>
            <details style="margin-top: 15px;">
                <summary style="cursor: pointer; color: #888;">Full link (also works)</summary>
                <div class="link-box" id="generatedLink"></div>
                <button class="btn" onclick="copyFullLink()" style="margin-top: 10px;">Copy Full Link</button>
            </details>
        </div>
    </div>

    <div class="modal" id="detailModal">
        <div class="modal-content">
            <h2>Session Details</h2>
            <div id="sessionDetails"></div>
            <button class="btn" onclick="closeDetailModal()" style="margin-top: 20px;">Close</button>
        </div>
    </div>

    <div class="modal" id="revokeModal">
        <div class="modal-content">
            <h2>Revoke Session</h2>
            <p style="margin-bottom: 15px; color: #ccc;">This will end the session and generate a Chain of Custody PDF in the case folder.</p>
            <div class="form-group">
                <label>Analyst Name (for CoC document)</label>
                <input type="text" id="analystName" placeholder="Enter your name">
            </div>
            <button class="btn btn-danger" onclick="confirmRevoke()">Revoke & Generate CoC</button>
            <button class="btn" onclick="closeRevokeModal()" style="margin-left: 10px;">Cancel</button>
        </div>
    </div>

    <div class="modal" id="triageLinkModal">
        <div class="modal-content">
            <h2>Triage Package Link</h2>
            <p>Share this short link with the remote party to download the triage package:</p>
            <div class="short-link" id="triageShortLink"></div>
            <div class="code-row">Short code: <code id="triageShortCode"></code></div>
            <button class="btn btn-primary" onclick="copyTriageLink()" style="margin-top: 15px;">Copy Short Link</button>
            <button class="btn" onclick="closeTriageLinkModal()" style="margin-left: 10px;">Close</button>
            <details style="margin-top: 15px;">
                <summary style="cursor: pointer; color: #888;">Full link (also works)</summary>
                <div class="link-box" id="triageLink"></div>
            </details>
        </div>
    </div>

    <input type="file" id="triageFileInput" style="display: none;">

    <script>
        var baseUrl = '';
        var adminToken = '';
        try {
            adminToken = sessionStorage.getItem('adminToken') || '';
            var urlKey = new URLSearchParams(location.search).get('key');
            if (urlKey) {
                adminToken = urlKey;
                sessionStorage.setItem('adminToken', adminToken);
                history.replaceState({}, '', location.pathname);
            }
        } catch(e) {}

        function promptAdminToken() {
            var t = prompt('Enter admin token (printed at server startup):');
            if (t && t.trim()) {
                adminToken = t.trim();
                try { sessionStorage.setItem('adminToken', adminToken); } catch(e) {}
                renderAdminToken();
                return true;
            }
            return false;
        }

        function renderAdminToken() {
            var el = document.getElementById('tokenValue');
            if (el) {
                el.textContent = adminToken || '(unknown - open the ?key= link from the server startup, or reload to enter it)';
            }
        }

        function copyAdminToken() {
            if (!adminToken) { promptAdminToken(); }
            if (adminToken) {
                copyText(adminToken);
                alert('Admin token copied to clipboard');
            }
        }

        async function loadBaseUrl() {
            try {
                var resp = await fetch('/api/baseurl');
                var data = await resp.json();
                baseUrl = data.base_url;
            } catch(e) { baseUrl = location.origin; }
        }

        function formatSize(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
            if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
            return (bytes / 1073741824).toFixed(2) + ' GB';
        }

        function escapeHtml(s) {
            return String(s == null ? '' : s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }

        function shortHash(hash) {
            return hash ? hash.substring(0, 12) + '...' : '';
        }

        function updateTimestamp() {
            var el = document.getElementById('refreshInfo');
            if (el) el.textContent = 'auto-refreshes every 5s - updated ' + new Date().toLocaleTimeString();
        }

        // fetch wrapper: separates "server unreachable" from "server said no",
        // so the UI shows an actionable message instead of "Load failed".
        // Attaches the admin token; prompts for it once on 401.
        async function apiFetch(url, opts, retried) {
            opts = opts || {};
            opts.headers = Object.assign({}, opts.headers || {}, {'X-Admin-Token': adminToken});
            var resp;
            try {
                resp = await fetch(url, opts);
            } catch(e) {
                throw new Error('Could not reach the server (' + e.message + '). Check that the server (and any tunnel) is still running, then try again.');
            }
            if (resp.status === 401 && !retried && promptAdminToken()) {
                return apiFetch(url, opts, true);
            }
            var text = await resp.text();
            var data = null;
            try { data = text ? JSON.parse(text) : null; } catch(e) {}
            if (!resp.ok) {
                throw new Error('Server error (HTTP ' + resp.status + '): ' + (data && data.error ? data.error : (text ? text.substring(0, 200) : 'no details')));
            }
            if (data === null) {
                throw new Error('Server returned an empty or invalid response (HTTP ' + resp.status + ')');
            }
            return data;
        }

        var lastSessionsJSON = '';

        async function loadSessions() {
            try {
                var sessions = await apiFetch('/admin/api/sessions');
                var raw = JSON.stringify(sessions);
                if (raw !== lastSessionsJSON) {
                    lastSessionsJSON = raw;
                    var tbody = document.getElementById('sessionsBody');
                    tbody.innerHTML = sessions.map(function(s) {
                        var files = s.uploaded_files || [];
                        var fileList = files.length > 0
                            ? '<div class="file-list">' + files.map(function(f) {
                                return '<div class="file-name">' + escapeHtml(f.name) + '</div>' +
                                       '<div class="file-hash">sha256: ' + escapeHtml(shortHash(f.hash)) + '</div>';
                            }).join('') + '</div>'
                            : '';
                        return '<tr><td><span class="token-link" onclick="showSessionDetail(\'' + escapeHtml(s.token) + '\')">' + escapeHtml(s.token.substring(0, 16)) + '...</span></td><td>' + escapeHtml(s.description || '-') + '</td><td>' + new Date(s.created_at).toLocaleString() + '</td><td>' + new Date(s.expires_at).toLocaleString() + '</td><td>' + files.length + fileList + '</td><td><button class="btn btn-danger" onclick="revokeSession(\'' + escapeHtml(s.token) + '\')">Revoke</button></td></tr>';
                    }).join('');
                }
                updateTimestamp();
            } catch(e) { console.error('Failed to load sessions:', e); }
        }

        var currentDetailToken = null;

        function showSessionDetail(token) {
            currentDetailToken = token;
            renderSessionDetail(token, true);
        }

        async function renderSessionDetail(token, openModal) {
            try {
                var session = await apiFetch('/admin/api/session?token=' + encodeURIComponent(token));
                if (currentDetailToken !== token) return;
                if (session.short_code) shortCodeByToken[session.token] = session.short_code;
                var modalContent = document.querySelector('#detailModal .modal-content');
                var keepScroll = modalContent.scrollTop;
                var html = '';
                html += '<div class="detail-row"><span class="detail-label">Token:</span><span class="detail-value">' + escapeHtml(session.token) + '</span></div>';
                html += '<div class="detail-row"><span class="detail-label">Secret:</span><span class="detail-value">' + escapeHtml(session.secret) + '</span></div>';
                if (session.short_code) {
                    html += '<div class="detail-row"><span class="detail-label">Short Link:</span><span class="detail-value">' + escapeHtml(baseUrl + '/e/' + session.short_code) + ' (' + escapeHtml(formatCode(session.short_code)) + ')</span></div>';
                }
                html += '<div class="detail-row"><span class="detail-label">Description:</span><span class="detail-value">' + escapeHtml(session.description || '-') + '</span></div>';
                html += '<div class="detail-row"><span class="detail-label">Created:</span><span class="detail-value">' + new Date(session.created_at).toLocaleString() + '</span></div>';
                html += '<div class="detail-row"><span class="detail-label">Expires:</span><span class="detail-value">' + new Date(session.expires_at).toLocaleString() + '</span></div>';
                html += '<div class="detail-row"><span class="detail-label">Status:</span><span class="detail-value">' + (session.is_locked ? 'Locked to IP: ' + escapeHtml(session.uploader_ip) : 'Not yet accessed') + '</span></div>';
                html += '<div class="detail-row"><span class="detail-label">Total Size:</span><span class="detail-value">' + formatSize(session.total_size) + '</span></div>';
                html += '<div class="detail-row"><span class="detail-label">Files:</span><span class="detail-value">' + session.uploaded_files.length + '</span></div>';
                if (session.uploaded_files && session.uploaded_files.length > 0) {
                    html += '<h3 style="margin: 20px 0 10px; color: #0f3460;">Uploaded Files</h3>';
                    session.uploaded_files.forEach(function(f) {
                        html += '<div class="file-item">';
                        html += '<div class="file-item-name">' + escapeHtml(f.name) + '</div>';
                        html += '<div class="file-item-meta">' + formatSize(f.size) + '</div>';
                        if (f.hash) {
                            html += '<div class="hash-row"><span class="detail-label">SHA256:</span><code class="hash-value">' + escapeHtml(f.hash) + '</code><button class="btn btn-info btn-small" onclick="copyHash(this, \'' + escapeHtml(f.hash) + '\')">Copy</button></div>';
                        } else {
                            html += '<div class="file-item-meta">SHA256 not yet available</div>';
                        }
                        html += '</div>';
                    });
                }
                if (session.activity && session.activity.length > 0) {
                    html += '<h3 style="margin: 20px 0 10px; color: #0f3460;">Activity History</h3>';
                    session.activity.reverse().forEach(function(a) {
                        html += '<div class="activity-item"><div><span class="activity-time">' + new Date(a.timestamp).toLocaleString() + '</span> <span class="activity-action">' + escapeHtml(a.action) + '</span></div><div class="activity-details">IP: ' + escapeHtml(a.ip) + (a.details ? ' - ' + escapeHtml(a.details) : '') + '</div></div>';
                    });
                }
                html += '<h3 style="margin: 20px 0 10px; color: #0f3460;">Triage Package</h3>';
                if (session.triage_package) {
                    var triageLink = baseUrl + '/triage/' + session.token;
                    html += '<div class="activity-item"><span class="activity-action">Package: ' + escapeHtml(session.triage_package) + '</span></div>';
                    html += '<div class="link-box" style="margin-top: 10px;">' + escapeHtml(triageLink) + '</div>';
                    html += '<button class="btn btn-primary" onclick="showTriageLink(\'' + escapeHtml(session.token) + '\')" style="margin-top: 10px;">Copy Link</button>';
                    html += '<button class="btn" onclick="uploadTriagePackage(\'' + escapeHtml(session.token) + '\')" style="margin-top: 10px; margin-left: 10px;">Replace</button>';
                } else {
                    html += '<p style="color: #888; margin-bottom: 10px;">No triage package uploaded for this session.</p>';
                    html += '<button class="btn btn-primary" onclick="uploadTriagePackage(\'' + escapeHtml(session.token) + '\')">Send Triage Package</button>';
                }
                document.getElementById('sessionDetails').innerHTML = html;
                if (openModal) {
                    modalContent.scrollTop = 0;
                    document.getElementById('detailModal').classList.add('active');
                } else {
                    modalContent.scrollTop = keepScroll;
                }
            } catch(e) { if (openModal) alert('Failed to load session details'); }
        }

        function showCreateModal() { document.getElementById('createModal').classList.add('active'); }
        function closeModal() { document.getElementById('createModal').classList.remove('active'); }
        function closeLinkModal() { document.getElementById('linkModal').classList.remove('active'); }
        function closeDetailModal() {
            document.getElementById('detailModal').classList.remove('active');
            currentDetailToken = null;
        }

        var shortCodeByToken = {};

        function formatCode(code) {
            return code && code.length === 8 ? code.substring(0, 4) + '-' + code.substring(4) : (code || '');
        }

        async function createSession() {
            var duration = parseInt(document.getElementById('duration').value) || 24;
            var description = document.getElementById('description').value;
            var session = await apiFetch('/admin/api/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({duration: duration * 3600000000000, description: description})
            });
            if (session.short_code) shortCodeByToken[session.token] = session.short_code;
            var shortLink = baseUrl + '/e/' + (session.short_code || '');
            var link = baseUrl + '/?token=' + session.token + '&secret=' + session.secret;
            document.getElementById('generatedShortLink').textContent = shortLink;
            document.getElementById('generatedShortCode').textContent = formatCode(session.short_code);
            document.getElementById('generatedLink').textContent = link;
            closeModal();
            document.getElementById('linkModal').classList.add('active');
            loadSessions();
        }

        var pendingRevokeToken = null;

        function revokeSession(token) {
            pendingRevokeToken = token;
            document.getElementById('analystName').value = '';
            document.getElementById('revokeModal').classList.add('active');
        }

        function closeRevokeModal() {
            document.getElementById('revokeModal').classList.remove('active');
            pendingRevokeToken = null;
        }

        async function confirmRevoke() {
            var analystName = document.getElementById('analystName').value || 'Unknown Analyst';
            var token = pendingRevokeToken;
            closeRevokeModal();
            try {
                var result = await apiFetch('/admin/api/revoke', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({token: token, analyst_name: analystName})
                });
                if (result.coc_path) {
                    alert('Session revoked. Chain of Custody PDF saved to:\\n' + result.coc_path);
                } else if (result.warning) {
                    alert(result.warning);
                }
            } catch(e) {
                alert('Failed to revoke session: ' + e.message);
            }
            loadSessions();
        }

        function copyText(text) {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text);
                return;
            }
            var ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }

        function copyHash(btn, hash) {
            copyText(hash);
            var original = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(function() { btn.textContent = original; }, 1200);
        }

        function copyLink() {
            copyText(document.getElementById('generatedShortLink').textContent);
            alert('Short link copied to clipboard!');
        }

        function copyFullLink() {
            copyText(document.getElementById('generatedLink').textContent);
            alert('Full link copied to clipboard!');
        }

        var pendingTriageToken = null;

        function uploadTriagePackage(token) {
            pendingTriageToken = token;
            document.getElementById('triageFileInput').click();
        }

        document.getElementById('triageFileInput').addEventListener('change', async function(e) {
            var file = e.target.files[0];
            if (!file || !pendingTriageToken) return;

            var formData = new FormData();
            formData.append('token', pendingTriageToken);
            formData.append('file', file);

            try {
                var result = await apiFetch('/admin/api/triage-package', {
                    method: 'POST',
                    body: formData
                });
                if (result.success) {
                    showTriageLink(pendingTriageToken);
                    showSessionDetail(pendingTriageToken);
                } else {
                    alert('Failed to upload triage package');
                }
            } catch(e) {
                alert('Failed to upload triage package: ' + e.message);
            }

            e.target.value = '';
            pendingTriageToken = null;
        });

        function showTriageLink(token) {
            var code = shortCodeByToken[token] || '';
            document.getElementById('triageShortLink').textContent = baseUrl + '/t/' + code;
            document.getElementById('triageShortCode').textContent = formatCode(code);
            document.getElementById('triageLink').textContent = baseUrl + '/triage/' + token;
            document.getElementById('triageLinkModal').classList.add('active');
        }

        function closeTriageLinkModal() {
            document.getElementById('triageLinkModal').classList.remove('active');
        }

        function copyTriageLink() {
            copyText(document.getElementById('triageShortLink').textContent);
            alert('Triage link copied to clipboard!');
        }

        function startAutoRefresh() {
            setInterval(function() {
                if (document.hidden) return;
                loadSessions();
                if (currentDetailToken) renderSessionDetail(currentDetailToken, false);
            }, 5000);
        }

        renderAdminToken();
        loadBaseUrl().then(function() { loadSessions(); startAutoRefresh(); });
    </script>
</body>
</html>`
