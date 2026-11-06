package custody

import (
	"os"
	"strings"
	"testing"
	"time"

	"evidence-upload/internal/models"
)

func TestSanitizePDFText(t *testing.T) {
	rep := string(replacementRune)
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"кириллица", "кириллица"},       // Cyrillic must survive
		{"em—dash – en", "em—dash – en"}, // punctuation must survive
		{"Jörg (SOC)", "Jörg (SOC)"},
		{"ﬀ ligature Œ œ", "ﬀ ligature Œ œ"},
		{"emoji 😀 end", "emoji " + rep + " end"}, // unsupported -> replacement
		{"中文", rep + rep},                        // unsupported -> replacement
		{"a\x00b\x1fc", "a b c"},                 // controls -> spaces
		{"line\nbreak\ttab", "line\nbreak\ttab"}, // layout kept
		{"carriage\rreturn", "carriage return"},
	}
	for _, c := range cases {
		if got := sanitizePDFText(c.in); got != c.want {
			t.Errorf("sanitizePDFText(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	// Invariant across the whole BMP: output runes are supported, the
	// replacement, or layout/blank.
	var sb strings.Builder
	for r := rune(0x20); r <= 0xFFFF; r++ {
		sb.WriteRune(r)
	}
	for _, r := range sanitizePDFText(sb.String()) {
		if r != '\n' && r != '\t' && r != ' ' && r != replacementRune && !supportedRunes[r] {
			t.Fatalf("sanitize emitted unsupported rune %U", r)
		}
	}
}

// TestGenerateCoCCodepointSweep draws a sampled sweep of the whole BMP in every
// text position of the PDF. Generation must succeed for any input — nothing the
// writer cannot render may ever fail the document.
func TestGenerateCoCCodepointSweep(t *testing.T) {
	var sb strings.Builder
	for r := rune(0x20); r <= 0xFFFF; r += 13 {
		if r >= 0xD800 && r <= 0xDFFF {
			continue // surrogates are not valid runes
		}
		sb.WriteRune(r)
	}
	text := sb.String()

	sess := &models.Session{
		Token:         "aabbccddeeff00112233445566778899",
		Secret:        "11223344556677889900112233445566",
		CreatedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:     time.Now().Add(time.Hour),
		Description:   text,
		FolderName:    "codepoint-sweep",
		UploadedFiles: []models.UploadedFile{{Name: text, Size: 1, Hash: text}},
		Activity: []models.ActivityEvent{{
			Timestamp: time.Now(), Action: text, IP: text, UserAgent: text, Details: text,
		}},
	}
	p, err := GenerateCoC(sess, text, t.TempDir(), "test", nil, "", 0, 0)
	if err != nil {
		t.Fatalf("codepoint sweep failed: %v", err)
	}
	if st, err := os.Stat(p); err != nil || st.Size() == 0 {
		t.Fatalf("no PDF written (err=%v)", err)
	}
}
