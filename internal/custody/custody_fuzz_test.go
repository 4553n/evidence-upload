package custody

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"evidence-upload/internal/models"
)

// nastyStrings are the kinds of values real sessions carry: macOS typographic
// punctuation, parens (unescaped in PDF string literals), control chars,
// multi-byte runes at truncation boundaries, and very long unbroken runs.
var nastyStrings = []string{
	"",
	" ",
	"plain",
	"Case (urgent)",
	"a)b(c",
	"back\\slash",
	"quote\"double 'single",
	"newline\ninside",
	"carriage\rreturn",
	"tab\there",
	"em—dash – en",
	"smart ‘quote’s “double”",
	"emoji 😀🧑‍💻 family",
	"кириллица 中文 العربية",
	"ﬀ ligature Œ œ",
	"control\x00\x01\x1f",
	"end with paren)",
	"(((((",
	")))))",
	strings.Repeat("A", 500),
	strings.Repeat("word ", 200),
	strings.Repeat("😀", 50),
	"a" + strings.Repeat("́", 30), // combining marks
}

func sessionWith(name, desc string, files []models.UploadedFile, acts []models.ActivityEvent) *models.Session {
	return &models.Session{
		Token:         "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
		Secret:        "1122334455667788990011223344556677889900112233445566778899001122",
		CreatedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:     time.Now().Add(time.Hour),
		Description:   desc,
		FolderName:    name,
		UploadedFiles: files,
		Activity:      acts,
	}
}

func TestGenerateCoCNastyInputs(t *testing.T) {
	base := t.TempDir()
	analysts := []string{
		"",
		"plain",
		"Jörg (SOC) — Œ",
		"emoji 😀 кириллицa \"quoted\" (x)",
	}
	idx := 0
	for _, s := range nastyStrings {
		for _, analyst := range analysts {
			idx++
			desc := "desc " + s
			name := models.SanitizeFolderName(desc)
			sess := sessionWith(name, desc,
				[]models.UploadedFile{
					{Name: "file " + s + ".bin", Size: 1234, Hash: "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
					{Name: s, Size: 0, Hash: ""},
				},
				[]models.ActivityEvent{
					{Timestamp: time.Now(), Action: "file_uploaded " + s, IP: "10.0.0.1 " + s, UserAgent: "UA " + s, Details: "Details " + s},
				})
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("PANIC for analyst=%q desc=%q: %v", analyst, desc, r)
					}
				}()
				p, err := GenerateCoC(sess, analyst, base, "test", nil, "", 0, 0)
				if err != nil {
					t.Errorf("error for analyst=%q desc=%q: %v", analyst, desc, err)
					return
				}
				if st, err := os.Stat(p); err != nil || st.Size() == 0 {
					t.Errorf("no PDF written for analyst=%q desc=%q (err=%v)", analyst, desc, err)
				}
			}()
		}
	}
	_ = filepath.Join
	_ = fmt.Sprintf
}
