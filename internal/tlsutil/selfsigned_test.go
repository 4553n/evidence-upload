package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSelfSigned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".tls")
	certPath, keyPath, fp, err := EnsureSelfSigned(dir, []string{"192.0.2.10", "evidence.example.com", "192.0.2.10"})
	if err != nil {
		t.Fatalf("EnsureSelfSigned: %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key missing: %v", err)
	}
	if fp == "" {
		t.Fatal("empty fingerprint")
	}

	data, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Errorf("localhost not in SANs: %v", err)
	}
	if err := cert.VerifyHostname("evidence.example.com"); err != nil {
		t.Errorf("extra hostname not in SANs: %v", err)
	}
	if err := cert.VerifyHostname("192.0.2.10"); err != nil {
		t.Errorf("extra IP not in SANs: %v", err)
	}
	if len(cert.DNSNames) != 2 {
		t.Errorf("expected 2 unique DNS names (dedupe), got %v", cert.DNSNames)
	}

	// Second call must reuse the same certificate (stable fingerprint).
	_, _, fp2, err := EnsureSelfSigned(dir, nil)
	if err != nil {
		t.Fatalf("EnsureSelfSigned (2nd): %v", err)
	}
	if fp2 != fp {
		t.Errorf("certificate not stable across calls: %s != %s", fp, fp2)
	}

	// Key file must not be world-readable.
	st, _ := os.Stat(keyPath)
	if perm := st.Mode().Perm(); perm&0077 != 0 {
		t.Errorf("key file permissions too broad: %v", perm)
	}
}
