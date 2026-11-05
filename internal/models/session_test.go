package models

import (
	"path/filepath"
	"testing"
	"time"
)

func TestSessionPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sessions.json")

	sm := NewSessionManager("s3cret")
	sm.SetPersistence(path)

	sess, err := sm.CreateSession(time.Hour, "CASE-1 persistence")
	if err != nil {
		t.Fatal(err)
	}
	sm.AddUploadedFile(sess.Token, "evidence.bin", "abc123", 42)
	sm.AddActivity(sess.Token, "file_uploaded", "192.0.2.1", "ua", "d")
	sm.LockSession(sess.Token, "192.0.2.1")

	// A fresh manager must see the same session after Load.
	sm2 := NewSessionManager("s3cret")
	sm2.SetPersistence(path)
	n, err := sm2.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n != 1 {
		t.Fatalf("restored %d sessions, want 1", n)
	}
	got, ok := sm2.GetSession(sess.Token)
	if !ok {
		t.Fatal("session lost across restart")
	}
	if len(got.UploadedFiles) != 1 || got.UploadedFiles[0].Hash != "abc123" {
		t.Fatalf("uploaded files not restored: %+v", got.UploadedFiles)
	}
	if got.TotalSize != 42 {
		t.Fatalf("total size not restored: %d", got.TotalSize)
	}
	if !got.IsLocked {
		t.Fatal("uploader lock not restored")
	}
	if len(got.Activity) != 1 {
		t.Fatalf("activity not restored: %+v", got.Activity)
	}

	// Revocation must survive too, and be reported as "revoked".
	sm2.RevokeSession(sess.Token)
	sm3 := NewSessionManager("s3cret")
	sm3.SetPersistence(path)
	if _, err := sm3.Load(); err != nil {
		t.Fatalf("Load after revoke: %v", err)
	}
	if p := sm3.SessionProblem(sess.Token); p != "revoked" {
		t.Fatalf("SessionProblem = %q, want revoked", p)
	}
	if _, ok := sm3.GetSession(sess.Token); ok {
		t.Fatal("revoked session resurfaced after restart")
	}
}

func TestSessionProblemReasons(t *testing.T) {
	sm := NewSessionManager("s3cret")

	sess, _ := sm.CreateSession(time.Hour, "active")
	if p := sm.SessionProblem(sess.Token); p != "" {
		t.Fatalf("active session problem = %q", p)
	}
	if p := sm.SessionProblem("nonexistent"); p != "unknown" {
		t.Fatalf("unknown session problem = %q", p)
	}

	expired, _ := sm.CreateSession(-time.Minute, "already expired")
	if p := sm.SessionProblem(expired.Token); p != "expired" {
		t.Fatalf("expired session problem = %q", p)
	}

	sm.RevokeSession(sess.Token)
	if p := sm.SessionProblem(sess.Token); p != "revoked" {
		t.Fatalf("revoked session problem = %q", p)
	}
}

func TestLoadDropsExpiredSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sessions.json")
	sm := NewSessionManager("s3cret")
	sm.SetPersistence(path)
	live, _ := sm.CreateSession(time.Hour, "live")
	dead, _ := sm.CreateSession(-time.Minute, "dead")

	sm2 := NewSessionManager("s3cret")
	sm2.SetPersistence(path)
	n, err := sm2.Load()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("restored %d, want 1 (expired must be dropped)", n)
	}
	if _, ok := sm2.GetSession(live.Token); !ok {
		t.Fatal("live session missing")
	}
	if _, ok := sm2.GetSession(dead.Token); ok {
		t.Fatal("expired session was restored")
	}
}
