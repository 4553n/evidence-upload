package server

import (
	"testing"
	"time"
)

func TestShortLimiterWindow(t *testing.T) {
	l := newShortLimiter(5, 200*time.Millisecond)

	// Five failures fill the allowance; the sixth request is blocked.
	for i := 0; i < 5; i++ {
		if l.blocked("1.2.3.4") {
			t.Fatalf("blocked too early at attempt %d", i+1)
		}
		l.fail("1.2.3.4")
	}
	if !l.blocked("1.2.3.4") {
		t.Fatal("not blocked after limit failures")
	}

	// Other addresses are unaffected.
	if l.blocked("5.6.7.8") {
		t.Fatal("unrelated IP blocked")
	}

	// The window slides: after it passes, the address is allowed again.
	time.Sleep(250 * time.Millisecond)
	if l.blocked("1.2.3.4") {
		t.Fatal("still blocked after window elapsed")
	}
}

func TestShortLimiterSliding(t *testing.T) {
	l := newShortLimiter(3, 300*time.Millisecond)
	l.fail("ip")
	l.fail("ip")
	time.Sleep(200 * time.Millisecond)
	l.fail("ip") // 3rd failure, all inside the window
	if !l.blocked("ip") {
		t.Fatal("expected block with 3 failures in window")
	}
	time.Sleep(150 * time.Millisecond) // the two oldest age out, one remains
	if l.blocked("ip") {
		t.Fatal("expected unblocked once failures drop below the limit")
	}
	l.fail("ip")
	l.fail("ip") // 3 in the window again
	if !l.blocked("ip") {
		t.Fatal("expected re-block after two more failures")
	}
}
