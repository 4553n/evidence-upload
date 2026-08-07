package tunnel

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type CloudflareTunnel struct {
	binaryPath string
	process    *exec.Cmd
	publicURL  string
	tunnelName string
	domain     string
	token      string
}

func NewCloudflareTunnel(binaryPath, tunnelName, domain, token string) *CloudflareTunnel {
	return &CloudflareTunnel{
		binaryPath: binaryPath,
		tunnelName: tunnelName,
		domain:     domain,
		token:      token,
	}
}

func (c *CloudflareTunnel) IsInstalled() bool {
	if c.binaryPath != "" {
		_, err := os.Stat(c.binaryPath)
		return err == nil
	}

	_, err := exec.LookPath("cloudflared")
	if err == nil {
		c.binaryPath = "cloudflared"
		return true
	}

	localPath := filepath.Join(".", "cloudflared")
	if runtime.GOOS == "windows" {
		localPath += ".exe"
	}
	if _, err := os.Stat(localPath); err == nil {
		c.binaryPath = localPath
		return true
	}

	return false
}

func (c *CloudflareTunnel) Install(workDir string) error {
	fmt.Println("cloudflared not found. Please install it manually:")
	fmt.Println("  Linux:   curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared && chmod +x /usr/local/bin/cloudflared")
	fmt.Println("  Windows: https://github.com/cloudflare/cloudflared/releases")
	fmt.Println("  macOS:   brew install cloudflared")
	fmt.Println("")
	fmt.Println("After installation, run: cloudflared tunnel login")
	return fmt.Errorf("cloudflared not installed")
}

func (c *CloudflareTunnel) Start(localPort int) (string, error) {
	if c.binaryPath == "" {
		return "", fmt.Errorf("cloudflared binary not found")
	}

	absPath, err := filepath.Abs(c.binaryPath)
	if err != nil {
		absPath = c.binaryPath
	}

	var args []string

	if c.token != "" {
		args = []string{"tunnel", "run", "--token", c.token}
	} else if c.tunnelName != "" {
		args = []string{"tunnel", "run", "--url", fmt.Sprintf("http://localhost:%d", localPort), "--no-autoupdate", c.tunnelName}
	} else {
		args = []string{"tunnel", "--url", fmt.Sprintf("http://localhost:%d", localPort), "--no-autoupdate"}
	}

	c.process = exec.Command(absPath, args...)

	stdout, err := c.process.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	c.process.Stderr = os.Stderr

	if err := c.process.Start(); err != nil {
		return "", fmt.Errorf("failed to start cloudflared: %w", err)
	}

	publicURL := c.parseCloudflaredOutput(stdout)
	if publicURL == "" {
		return "", fmt.Errorf("failed to get tunnel URL from cloudflared")
	}

	c.publicURL = publicURL

	fmt.Printf("Tunnel established: %s -> localhost:%d\n", publicURL, localPort)
	return publicURL, nil
}

func (c *CloudflareTunnel) parseCloudflaredOutput(stdout io.ReadCloser) string {
	scanner := bufio.NewScanner(stdout)
	re := regexp.MustCompile(`https://[a-zA-Z0-9\-]+\.trycloudflare\.com`)
	namedRe := regexp.MustCompile(`https://[a-zA-Z0-9\-]+\.` + regexp.QuoteMeta(c.domain))

	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)

		if c.domain != "" {
			if matches := namedRe.FindString(line); matches != "" {
				return matches
			}
		}

		if matches := re.FindString(line); matches != "" {
			return matches
		}
	}
	return ""
}

func (c *CloudflareTunnel) Stop() {
	if c.process != nil && c.process.Process != nil {
		c.process.Process.Kill()
		c.process.Wait()
		c.process = nil
	}
}

func (c *CloudflareTunnel) PublicURL() string {
	return c.publicURL
}

func (c *CloudflareTunnel) IsAuthenticated() bool {
	credPath := filepath.Join(os.Getenv("HOME"), ".cloudflared", "cert.pem")
	if runtime.GOOS == "windows" {
		credPath = filepath.Join(os.Getenv("USERPROFILE"), ".cloudflared", "cert.pem")
	}
	_, err := os.Stat(credPath)
	return err == nil
}

func (c *CloudflareTunnel) CreateTunnel(name string) error {
	if c.binaryPath == "" {
		return fmt.Errorf("cloudflared binary not found")
	}

	absPath, err := filepath.Abs(c.binaryPath)
	if err != nil {
		absPath = c.binaryPath
	}

	cmd := exec.Command(absPath, "tunnel", "create", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *CloudflareTunnel) RouteDNS(tunnelName, hostname string) error {
	if c.binaryPath == "" {
		return fmt.Errorf("cloudflared binary not found")
	}

	absPath, err := filepath.Abs(c.binaryPath)
	if err != nil {
		absPath = c.binaryPath
	}

	cmd := exec.Command(absPath, "tunnel", "route", "dns", tunnelName, hostname)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (c *CloudflareTunnel) ListTunnels() ([]string, error) {
	if c.binaryPath == "" {
		return nil, fmt.Errorf("cloudflared binary not found")
	}

	absPath, err := filepath.Abs(c.binaryPath)
	if err != nil {
		absPath = c.binaryPath
	}

	out, err := exec.Command(absPath, "tunnel", "list").Output()
	if err != nil {
		return nil, err
	}

	var tunnels []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "-") && len(line) > 36 {
			tunnels = append(tunnels, line[:36])
		}
	}
	return tunnels, nil
}
