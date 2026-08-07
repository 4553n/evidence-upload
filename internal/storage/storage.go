package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type Storage struct {
	basePath   string
	backupPath string
	mu         sync.Mutex
}

func New(basePath, backupPath string) (*Storage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, err
	}

	if backupPath != "" {
		if err := os.MkdirAll(backupPath, 0755); err != nil {
			return nil, err
		}
	}

	return &Storage{
		basePath:   basePath,
		backupPath: backupPath,
	}, nil
}

func (s *Storage) SaveFile(token, filename string, reader io.Reader) (string, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionDir := filepath.Join(s.basePath, token)
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		return "", 0, err
	}

	filePath := filepath.Join(sessionDir, filepath.Base(filename))
	outFile, err := os.Create(filePath)
	if err != nil {
		return "", 0, err
	}
	defer outFile.Close()

	hasher := sha256.New()
	writer := io.MultiWriter(outFile, hasher)

	written, err := io.Copy(writer, reader)
	if err != nil {
		os.Remove(filePath)
		return "", 0, err
	}

	hash := hex.EncodeToString(hasher.Sum(nil))

	if s.backupPath != "" {
		go s.backupFile(token, filename, filePath)
	}

	return hash, written, nil
}

func (s *Storage) backupFile(token, filename, sourcePath string) {
	backupDir := filepath.Join(s.backupPath, token)
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return
	}
	defer sourceFile.Close()

	backupPath := filepath.Join(backupDir, filepath.Base(filename))
	backupFile, err := os.Create(backupPath)
	if err != nil {
		return
	}
	defer backupFile.Close()

	io.Copy(backupFile, sourceFile)
}

func (s *Storage) ListFiles(token string) ([]string, error) {
	sessionDir := filepath.Join(s.basePath, token)
	entries, err := os.ReadDir(sessionDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

func (s *Storage) GetSessionSize(token string) (int64, error) {
	sessionDir := filepath.Join(s.basePath, token)
	var totalSize int64

	err := filepath.Walk(sessionDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	return totalSize, err
}

func (s *Storage) BasePath() string {
	return s.basePath
}

func (s *Storage) BackupPath() string {
	return s.backupPath
}

func (s *Storage) GetFileSize(token, filename string) (int64, error) {
	filePath := filepath.Join(s.basePath, token, filename)
	info, err := os.Stat(filePath)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

var invalidChars = regexp.MustCompile(`[^\w\-\.]`)

func SanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	name = invalidChars.ReplaceAllString(name, "_")
	name = strings.ReplaceAll(name, "__", "_")
	name = strings.Trim(name, "_.")
	if name == "" {
		name = "unnamed"
	}
	return name
}

func WriteHashFile(filePath, hash string) error {
	hashPath := filePath + ".sha256"
	content := fmt.Sprintf("%s  %s\n", hash, filepath.Base(filePath))
	return os.WriteFile(hashPath, []byte(content), 0644)
}

func (s *Storage) GetSessionDir(folderName string) string {
	return filepath.Join(s.basePath, folderName)
}

func (s *Storage) GetBackupSessionDir(folderName string) string {
	if s.backupPath == "" {
		return ""
	}
	return filepath.Join(s.backupPath, folderName)
}
