package models

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestShortCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		code, err := generateShortCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != ShortCodeLen {
			t.Fatalf("code %q length %d", code, len(code))
		}
		for _, r := range code {
			if !stringsContainsRune(shortAlphabet, r) {
				t.Fatalf("code %q contains %q outside the alphabet", code, r)
			}
		}
		if seen[code] {
			t.Fatalf("duplicate code %q in 500 draws", code)
		}
		seen[code] = true
	}
}

func stringsContainsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func TestShortCodeNormalization(t *testing.T) {
	cases := map[string]string{
		"K7M3Q9P2": "K7M3Q9P2",
		"k7m3q9p2": "K7M3Q9P2",
		"k7m3-q9p2": "K7M3Q9P2",
		"K7M3 Q9P2": "K7M3Q9P2",
		" k7m3-q9p2 ": "K7M3Q9P2",
		"":          "",
	}
	for in, want := range cases {
		if got := NormalizeShortCode(in); got != want {
			t.Errorf("NormalizeShortCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := FormatShortCode("K7M3Q9P2"); got != "K7M3-Q9P2" {
		t.Errorf("FormatShortCode = %q", got)
	}
}

func TestTokenByShortCode(t *testing.T) {
	sm := NewSessionManager("s3cret")
	sess, err := sm.CreateSession(time.Hour, "short code case")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ShortCode == "" {
		t.Fatal("session has no short code")
	}

	for _, variant := range []string{sess.ShortCode, FormatShortCode(sess.ShortCode), "  " + NormalizeShortCode(sess.ShortCode) + " "} {
		token, ok := sm.TokenByShortCode(variant)
		if !ok || token != sess.Token {
			t.Fatalf("resolve %q = %q/%v", variant, token, ok)
		}
	}

	if _, ok := sm.TokenByShortCode("ZZZZZZZZ"); ok {
		t.Fatal("unknown code resolved")
	}
	if _, ok := sm.TokenByShortCode(""); ok {
		t.Fatal("empty code resolved")
	}

	// Revoked sessions keep their code resolvable so visitors see the proper
	// "closed" message instead of a generic error.
	sm.RevokeSession(sess.Token)
	token, ok := sm.TokenByShortCode(sess.ShortCode)
	if !ok || token != sess.Token {
		t.Fatal("revoked session's code no longer resolves")
	}

	// New sessions never reuse a revoked code.
	for i := 0; i < 50; i++ {
		s, err := sm.CreateSession(time.Hour, "x")
		if err != nil {
			t.Fatal(err)
		}
		if s.ShortCode == sess.ShortCode {
			t.Fatal("revoked short code was reused")
		}
	}
}

func TestShortCodeMigrationAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sessions.json")

	// A legacy state file: session without a short code.
	legacy := map[string]interface{}{
		"sessions": map[string]interface{}{
			"tok": map[string]interface{}{
				"token": "tok", "secret": "sec",
				"created_at":  time.Now().Add(-time.Hour).Format(time.RFC3339Nano),
				"expires_at":  time.Now().Add(time.Hour).Format(time.RFC3339Nano),
				"description": "legacy", "folder_name": "legacy",
				"uploaded_files": []interface{}{}, "activity": []interface{}{},
			},
		},
		"revoked": map[string]interface{}{},
	}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	sm := NewSessionManager("s3cret")
	sm.SetPersistence(path)
	n, err := sm.Load()
	if err != nil || n != 1 {
		t.Fatalf("Load = %d, %v", n, err)
	}
	got, ok := sm.GetSession("tok")
	if !ok {
		t.Fatal("legacy session not restored")
	}
	if got.ShortCode == "" {
		t.Fatal("legacy session did not get a short code on load")
	}
	if token, ok := sm.TokenByShortCode(got.ShortCode); !ok || token != "tok" {
		t.Fatal("migrated code does not resolve")
	}

	// The migrated code is persisted for the next start.
	sm2 := NewSessionManager("s3cret")
	sm2.SetPersistence(path)
	if _, err := sm2.Load(); err != nil {
		t.Fatal(err)
	}
	got2, _ := sm2.GetSession("tok")
	if got2.ShortCode != got.ShortCode {
		t.Fatal("short code not stable across restarts")
	}
}
