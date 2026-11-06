package models

import (
	"path/filepath"
	"testing"
	"time"
)

func TestKillSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sessions.json")
	sm := NewSessionManager("s3cret")
	sm.SetPersistence(path)

	sess, _ := sm.CreateSession(time.Hour, "failed session")

	rec, ok := sm.KillSession(sess.Token, "Link lost / needs reissue", "smoke note", true)
	if !ok || rec == nil {
		t.Fatal("KillSession failed")
	}
	if _, ok := sm.GetSession(sess.Token); ok {
		t.Fatal("killed session still available")
	}
	// External message is the same as revoke; the tombstone keeps the reason.
	if p := sm.SessionProblem(sess.Token); p != "revoked" {
		t.Fatalf("SessionProblem = %q, want revoked", p)
	}
	kr, ok := sm.KillRecordFor(sess.Token)
	if !ok || kr.Reason != "Link lost / needs reissue" || kr.Note != "smoke note" || !kr.Purged {
		t.Fatalf("tombstone wrong: %+v", kr)
	}
	// The short code is retired and never reused.
	if _, ok := sm.TokenByShortCode(sess.ShortCode); !ok {
		t.Fatal("killed code should still resolve (to show the closed message)")
	}

	// Tombstone survives restart.
	sm2 := NewSessionManager("s3cret")
	sm2.SetPersistence(path)
	if _, err := sm2.Load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := sm2.KillRecordFor(sess.Token); !ok {
		t.Fatal("tombstone lost across restart")
	}
	if _, ok := sm2.GetSession(sess.Token); ok {
		t.Fatal("killed session resurrected after restart")
	}
	// A second kill is refused.
	if _, ok := sm2.KillSession(sess.Token, "again", "", false); ok {
		t.Fatal("double kill succeeded")
	}
}

func TestLegacyMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".sessions.json")
	sm := NewSessionManager("s3cret")
	sm.SetPersistence(path)

	sess, _ := sm.CreateSession(time.Hour, "legacy")
	// Simulate pre-2.3.0 state: triage package field, no collector package,
	// no ip_shared_at, but an ip_detection upload in the activity trail.
	sm.mu.Lock()
	sess.TriagePackage = "TRIAGE_PACKAGE_tool.zip"
	sess.CollectorPackage = nil
	sess.IPSharedAt = time.Time{}
	sess.Activity = append(sess.Activity, ActivityEvent{
		Timestamp: time.Now().Add(-30 * time.Minute),
		Action:    "file_uploaded",
		Details:   "File: ip_detection_203.0.113.7.txt (200 bytes)",
	})
	sm.saveLocked()
	sm.mu.Unlock()

	sm2 := NewSessionManager("s3cret")
	sm2.SetPersistence(path)
	if _, err := sm2.Load(); err != nil {
		t.Fatal(err)
	}
	got, ok := sm2.GetSession(sess.Token)
	if !ok {
		t.Fatal("legacy session not restored")
	}
	if got.CollectorPackage == nil || got.CollectorPackage.Name != "TRIAGE_PACKAGE_tool.zip" {
		t.Fatalf("triage package not migrated: %+v", got.CollectorPackage)
	}
	if !got.IPShared() {
		t.Fatal("ip_detection upload not treated as IP-shared")
	}
}
