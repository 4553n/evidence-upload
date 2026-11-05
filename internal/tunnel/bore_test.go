package tunnel

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestWriteFrame(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrame(&buf, map[string]any{"Hello": 0}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "{\"Hello\":0}\x00" {
		t.Errorf("got %q", got)
	}
	buf.Reset()
	if err := writeFrame(&buf, map[string]any{"Accept": "550e8400-e29b-41d4-a716-446655440000"}); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "{\"Accept\":\"550e8400-e29b-41d4-a716-446655440000\"}\x00" {
		t.Errorf("got %q", got)
	}
}

func TestReadFrameDoesNotOverread(t *testing.T) {
	// Payload after the NUL must remain unread: on Accept streams it is
	// proxied traffic.
	r := strings.NewReader("frame-one\x00frame-two\x00leftover")
	f1, err := readFrame(r)
	if err != nil || string(f1) != "frame-one" {
		t.Fatalf("f1 = %q, %v", f1, err)
	}
	f2, err := readFrame(r)
	if err != nil || string(f2) != "frame-two" {
		t.Fatalf("f2 = %q, %v", f2, err)
	}
	rest, _ := io.ReadAll(r)
	if string(rest) != "leftover" {
		t.Fatalf("rest = %q", rest)
	}
}

func TestReadFrameTooLong(t *testing.T) {
	if _, err := readFrame(strings.NewReader(strings.Repeat("a", 300))); err == nil {
		t.Fatal("expected frame-too-long error")
	}
}

func TestParseServerMessage(t *testing.T) {
	cases := []struct {
		frame string
		kind  string
		port  uint16
		id    string
		text  string
	}{
		{`{"Hello":41739}`, "Hello", 41739, "", ""},
		{`"Heartbeat"`, "Heartbeat", 0, "", ""},
		{`{"Connection":"550e8400-e29b-41d4-a716-446655440000"}`, "Connection", 0, "550e8400-e29b-41d4-a716-446655440000", ""},
		{`{"Challenge":"550e8400-e29b-41d4-a716-446655440000"}`, "Challenge", 0, "550e8400-e29b-41d4-a716-446655440000", ""},
		{`{"Error":"port taken"}`, "Error", 0, "", "port taken"},
	}
	for _, c := range cases {
		m, err := parseServerMessage([]byte(c.frame))
		if err != nil {
			t.Errorf("parse %s: %v", c.frame, err)
			continue
		}
		if m.Kind != c.kind || m.Port != c.port || m.ID != c.id || m.Text != c.text {
			t.Errorf("parse %s = %+v", c.frame, m)
		}
	}
	if _, err := parseServerMessage([]byte(`nonsense`)); err == nil {
		t.Error("expected error for invalid frame")
	}
}
