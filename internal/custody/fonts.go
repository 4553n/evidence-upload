package custody

import (
	_ "embed"
	"encoding/binary"
	"strings"

	"github.com/jung-kurt/gofpdf"
)

// DejaVu faces (Bitstream Vera license, see fonts/LICENSE-DejaVu.txt) provide
// real UTF-8 coverage — core PDF fonts are Latin-1 only and garble anything else.
//
//go:embed fonts/DejaVuSans.ttf
var dejavuSans []byte

//go:embed fonts/DejaVuSans-Bold.ttf
var dejavuSansBold []byte

//go:embed fonts/DejaVuSans-Oblique.ttf
var dejavuSansOblique []byte

//go:embed fonts/DejaVuSansMono.ttf
var dejavuSansMono []byte

// supportedRunes is the intersection of the cmap coverage of the three DejaVu
// faces used for proportional text, capped to the Basic Multilingual Plane —
// gofpdf indexes glyph widths by codepoint and rejects anything beyond the BMP
// with "character outside the supported range". Every other rune (emoji, CJK,
// scripts the font family lacks) is replaced before drawing, so CoC generation
// never fails on hostile or exotic input. Mono is not included: it only ever
// draws hex strings.
var supportedRunes = filterBMP(intersectCoverage(
	parseCmapCoverage(dejavuSans),
	parseCmapCoverage(dejavuSansBold),
	parseCmapCoverage(dejavuSansOblique),
))

// filterBMP drops codepoints gofpdf cannot draw at all (outside U+0000..U+FFFF).
func filterBMP(m map[rune]bool) map[rune]bool {
	for r := range m {
		if r > 0xFFFF {
			delete(m, r)
		}
	}
	return m
}

// replacementRune marks text the fonts cannot render. U+FFFD when available,
// plain '?' otherwise.
var replacementRune = pickReplacement()

func pickReplacement() rune {
	for _, r := range []rune{'\uFFFD', '?'} {
		if supportedRunes[r] {
			return r
		}
	}
	return '?'
}

// setupFonts registers the embedded DejaVu faces. Must run before any text is drawn.
func setupFonts(pdf *gofpdf.Fpdf) {
	pdf.AddUTF8FontFromBytes("DejaVu", "", dejavuSans)
	pdf.AddUTF8FontFromBytes("DejaVu", "B", dejavuSansBold)
	pdf.AddUTF8FontFromBytes("DejaVu", "I", dejavuSansOblique)
	pdf.AddUTF8FontFromBytes("DejaVuMono", "", dejavuSansMono)
}

// sanitizePDFText keeps every rune the embedded fonts can render and replaces
// the rest with replacementRune. Control characters become spaces (they would
// corrupt the PDF content stream); newlines and tabs are kept. This guarantees
// CoC generation never fails on hostile or exotic input.
func sanitizePDFText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			b.WriteRune(' ')
		case supportedRunes[r]:
			b.WriteRune(r)
		default:
			b.WriteRune(replacementRune)
		}
	}
	return b.String()
}

func intersectCoverage(maps ...map[rune]bool) map[rune]bool {
	out := make(map[rune]bool, len(maps[0]))
	for r := range maps[0] {
		keep := true
		for _, m := range maps[1:] {
			if !m[r] {
				keep = false
				break
			}
		}
		if keep {
			out[r] = true
		}
	}
	return out
}

// parseCmapCoverage extracts the codepoints a TrueType font can render by
// reading its cmap table (formats 4 and 12). Enough for DejaVu, dependency-free.
func parseCmapCoverage(ttf []byte) map[rune]bool {
	covered := make(map[rune]bool)
	u16 := func(off int) uint16 { return binary.BigEndian.Uint16(ttf[off:]) }
	u32 := func(off int) uint32 { return binary.BigEndian.Uint32(ttf[off:]) }

	if len(ttf) < 12 {
		return covered
	}
	cmapOff := -1
	numTables := int(u16(4))
	for i := 0; i < numTables; i++ {
		rec := 12 + i*16
		if rec+16 > len(ttf) {
			return covered
		}
		if string(ttf[rec:rec+4]) == "cmap" {
			cmapOff = int(u32(rec + 8))
			break
		}
	}
	if cmapOff < 0 || cmapOff+4 > len(ttf) {
		return covered
	}

	// Prefer the richest Unicode subtable: (3,10) > (3,1) > (0,x).
	best, bestScore := -1, -1
	nSub := int(u16(cmapOff + 2))
	for i := 0; i < nSub; i++ {
		rec := cmapOff + 4 + i*8
		if rec+8 > len(ttf) {
			return covered
		}
		plat, enc := u16(rec), u16(rec+2)
		off := cmapOff + int(u32(rec+4))
		score := -1
		switch {
		case plat == 3 && enc == 10:
			score = 3
		case plat == 3 && enc == 1:
			score = 2
		case plat == 0:
			score = 1
		}
		if score > bestScore {
			bestScore, best = score, off
		}
	}
	if best < 0 || best+4 > len(ttf) {
		return covered
	}

	switch u16(best) {
	case 4:
		segX2 := int(u16(best + 6))
		seg := segX2 / 2
		endOff := best + 14
		startOff := endOff + segX2 + 2
		for i := 0; i < seg; i++ {
			if startOff+i*2+2 > len(ttf) {
				break
			}
			end := int(u16(endOff + i*2))
			start := int(u16(startOff + i*2))
			if start == 0xffff {
				continue
			}
			for c := start; c <= end && c <= 0xffff; c++ {
				covered[rune(c)] = true
			}
		}
	case 12:
		nGroups := int(u32(best + 12))
		for i := 0; i < nGroups; i++ {
			g := best + 16 + i*12
			if g+12 > len(ttf) {
				break
			}
			start, end := int(u32(g)), int(u32(g+4))
			for c := start; c <= end; c++ {
				covered[rune(c)] = true
			}
		}
	}
	return covered
}
