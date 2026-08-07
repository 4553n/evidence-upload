package tunnel

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	boreVersion = "v0.6.0"
	boreBaseURL = "https://github.com/ekzhang/bore/releases/download/" + boreVersion
)

type BoreTunnel struct {
	binaryPath string
	process    *exec.Cmd
	publicURL  string
}

func NewBoreTunnel(binaryPath string) *BoreTunnel {
	return &BoreTunnel{
		binaryPath: binaryPath,
	}
}

func (b *BoreTunnel) IsInstalled() bool {
	if b.binaryPath != "" {
		_, err := os.Stat(b.binaryPath)
		return err == nil
	}

	_, err := exec.LookPath("bore")
	if err == nil {
		b.binaryPath = "bore"
		return true
	}

	localPath := filepath.Join(".", "bore")
	if runtime.GOOS == "windows" {
		localPath += ".exe"
	}
	if _, err := os.Stat(localPath); err == nil {
		b.binaryPath = localPath
		return true
	}

	return false
}

func (b *BoreTunnel) Install(workDir string) error {
	fmt.Println("bore not found. Installing...")

	archiveName, err := getArchiveName()
	if err != nil {
		return fmt.Errorf("unsupported platform: %w", err)
	}

	url := boreBaseURL + "/" + archiveName
	downloadPath := filepath.Join(workDir, archiveName)

	fmt.Printf("Downloading bore %s from %s\n", boreVersion, url)
	if err := downloadFile(url, downloadPath); err != nil {
		return fmt.Errorf("failed to download bore: %w", err)
	}

	binaryName := "bore"
	if runtime.GOOS == "windows" {
		binaryName = "bore.exe"
	}
	binaryPath := filepath.Join(workDir, binaryName)

	if err := extractArchive(downloadPath, binaryPath); err != nil {
		os.Remove(downloadPath)
		return fmt.Errorf("failed to extract bore: %w", err)
	}

	os.Remove(downloadPath)

	if runtime.GOOS != "windows" {
		os.Chmod(binaryPath, 0755)
	}

	b.binaryPath = binaryPath
	fmt.Printf("bore installed to %s\n", binaryPath)
	return nil
}

func (b *BoreTunnel) Start(localPort int) (string, error) {
	if b.binaryPath == "" {
		return "", fmt.Errorf("bore binary not found")
	}

	absPath, err := filepath.Abs(b.binaryPath)
	if err != nil {
		absPath = b.binaryPath
	}

	b.process = exec.Command(absPath, "local", fmt.Sprintf("%d", localPort), "--to", "bore.pub")

	stdout, err := b.process.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	b.process.Stderr = os.Stderr

	if err := b.process.Start(); err != nil {
		return "", fmt.Errorf("failed to start bore: %w", err)
	}

	publicPort := b.parseBoreOutput(stdout)
	if publicPort == 0 {
		time.Sleep(3 * time.Second)
		publicPort = localPort
	}

	publicURL := fmt.Sprintf("http://bore.pub:%d", publicPort)
	b.publicURL = publicURL

	fmt.Printf("Tunnel established: %s -> localhost:%d\n", publicURL, localPort)
	return publicURL, nil
}

func (b *BoreTunnel) parseBoreOutput(stdout io.ReadCloser) int {
	scanner := bufio.NewScanner(stdout)
	re := regexp.MustCompile(`bore\.pub:(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)

		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			var port int
			fmt.Sscanf(matches[1], "%d", &port)
			return port
		}
	}
	return 0
}

func (b *BoreTunnel) Stop() {
	if b.process != nil && b.process.Process != nil {
		b.process.Process.Kill()
		b.process.Wait()
		b.process = nil
	}
}

func (b *BoreTunnel) PublicURL() string {
	return b.publicURL
}

func getArchiveName() (string, error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch goos {
	case "linux":
		switch goarch {
		case "amd64":
			return "bore-" + boreVersion + "-x86_64-unknown-linux-musl.tar.gz", nil
		case "arm64":
			return "bore-" + boreVersion + "-aarch64-unknown-linux-musl.tar.gz", nil
		case "arm":
			return "bore-" + boreVersion + "-arm-unknown-linux-musleabi.tar.gz", nil
		}
	case "windows":
		switch goarch {
		case "amd64":
			return "bore-" + boreVersion + "-x86_64-pc-windows-msvc.zip", nil
		case "386":
			return "bore-" + boreVersion + "-i686-pc-windows-msvc.zip", nil
		}
	case "darwin":
		switch goarch {
		case "amd64":
			return "bore-" + boreVersion + "-x86_64-apple-darwin.tar.gz", nil
		case "arm64":
			return "bore-" + boreVersion + "-aarch64-apple-darwin.tar.gz", nil
		}
	}

	return "", fmt.Errorf("no bore binary available for %s/%s", goos, goarch)
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func extractArchive(archivePath, destPath string) error {
	if strings.HasSuffix(archivePath, ".tar.gz") {
		return extractTarGz(archivePath, destPath)
	} else if strings.HasSuffix(archivePath, ".zip") {
		return extractZip(archivePath, destPath)
	}
	return fmt.Errorf("unsupported archive format")
}

func extractTarGz(archivePath, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		name := filepath.Base(header.Name)
		if name == "bore" || name == "bore.exe" {
			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, tr)
			return err
		}
	}
	return fmt.Errorf("bore binary not found in archive")
}

func extractZip(archivePath, destPath string) error {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		name := filepath.Base(f.Name)
		if name == "bore" || name == "bore.exe" {
			out, err := os.Create(destPath)
			if err != nil {
				return err
			}
			defer out.Close()

			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			_, err = io.Copy(out, rc)
			return err
		}
	}
	return fmt.Errorf("bore binary not found in archive")
}
