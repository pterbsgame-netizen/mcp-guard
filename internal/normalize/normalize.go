// Package normalize reveals what a piece of text is hiding.
//
// Signature matching against raw text is close to worthless: the same
// instruction survives base64, percent-encoding, an HTML comment, a span with
// display:none, a Cyrillic "а" in the middle of a Latin word, or a zero-width
// space between two letters. Every one of those reaches the model intact and
// none of them match a pattern written in plain English.
//
// So the text is unfolded into layers first, and everything downstream is
// matched against all of them. This is the cheap half of content inspection —
// it costs a pass over a few kilobytes and removes the most common evasions —
// and it is worth having even though what sits on top of it, by design, never
// blocks anything.
package normalize

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits. Tool results run to megabytes and nothing here is worth that: an
// instruction aimed at a model has to be short enough for the model to act on.
const (
	MaxInput    = 256 << 10
	maxLayers   = 64
	maxDepth    = 2 // base64 inside base64 happens; three deep does not
	minDecoded  = 8
	maxLayerLen = 64 << 10
)

// Layer is one view of the same content.
type Layer struct {
	// Name says how this view was obtained: "text", "base64", "html-comment".
	Name string

	// Hidden marks a layer that was not visible in the original. The fact that
	// an instruction was only reachable after decoding says more than the words
	// in it do.
	Hidden bool

	Text string
}

// Reveal returns the text as it arrived, folded to remove disguises, plus
// everything extractable from inside it.
func Reveal(s string) []Layer {
	if len(s) > MaxInput {
		s = s[:MaxInput]
	}
	layers := []Layer{{Name: "text", Text: Fold(s)}}
	reveal(s, 0, &layers)
	return layers
}

func reveal(s string, depth int, out *[]Layer) {
	if depth > maxDepth || len(*out) >= maxLayers {
		return
	}
	for _, e := range extractors {
		for _, found := range e.extract(s) {
			if len(*out) >= maxLayers {
				return
			}
			if len(found) > maxLayerLen {
				found = found[:maxLayerLen]
			}
			*out = append(*out, Layer{Name: e.name, Hidden: e.hidden, Text: Fold(found)})
			reveal(found, depth+1, out)
		}
	}
}

// Fold removes the disguises that survive inside a single string: characters
// that render as nothing, characters that render as something else, and the
// bidirectional overrides that make text read in an order it is not stored in.
func Fold(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inSpace := false
	for _, r := range s {
		switch {
		case isInvisible(r):
			// Dropped, not replaced: a zero-width space between "ig" and
			// "nore" is there precisely so the word does not match.
		case isSpace(r):
			// Runs collapse to one space, or "previous\r\ninstructions" would
			// fold to two spaces and still miss a pattern written with one.
			if !inSpace {
				b.WriteByte(' ')
				inSpace = true
			}
		default:
			inSpace = false
			b.WriteRune(confusable(r))
		}
	}
	return strings.TrimSpace(b.String())
}

// isInvisible covers characters that occupy no space when rendered, and the
// bidirectional controls behind the Trojan Source trick.
func isInvisible(r rune) bool {
	switch r {
	case 0x00AD, // soft hyphen
		0x180E,                                 // Mongolian vowel separator
		0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // zero width space/joiners/marks
		0x2060, 0x2061, 0x2062, 0x2063, 0x2064, // word joiner and invisible operators
		0xFEFF: // zero width no-break space
		return true
	}
	// Bidirectional embedding, override and isolate controls.
	if (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
		return true
	}
	// Variation selectors and tag characters, which can carry a whole hidden
	// message that renders as nothing at all.
	if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0000 && r <= 0xE007F) {
		return true
	}
	return false
}

func isSpace(r rune) bool {
	return unicode.IsSpace(r) || r == 0x00A0
}

// confusables maps the lookalikes that matter to their Latin equivalents.
//
// This is not a complete confusables table and is not meant to be: the point is
// that "іgnore" with a Cyrillic і, or "ѕystem" with a Cyrillic ѕ, folds to
// something a pattern written in English can match. A full table would be
// thousands of entries and would start folding legitimate text together.
var confusables = map[rune]rune{
	// Cyrillic that renders identically to Latin.
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'У': 'Y', 'Х': 'X',
	'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'о': 'o', 'р': 'p',
	'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
	'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
	// Greek.
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
	'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X',
	'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ι': 'i',
}

func confusable(r rune) rune {
	if c, ok := confusables[r]; ok {
		return unicode.ToLower(c)
	}
	// Fullwidth forms map back to ASCII by a fixed offset, and still need
	// case folding afterwards: Ｉ becomes I, not i, without it.
	if r >= 0xFF01 && r <= 0xFF5E {
		return unicode.ToLower(r - 0xFEE0)
	}
	return unicode.ToLower(r)
}

type extractor struct {
	name    string
	hidden  bool
	extract func(string) []string
}

var extractors = []extractor{
	{"base64", true, extractBase64},
	{"hex", true, extractHex},
	{"percent-encoded", true, extractPercent},
	{"html-comment", true, extractHTMLComments},
	{"hidden-markup", true, extractHiddenMarkup},
}

var (
	base64Run  = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	hexRun     = regexp.MustCompile(`(?:[0-9a-fA-F]{2}){16,}`)
	htmlNote   = regexp.MustCompile(`(?s)<!--(.*?)-->`)
	percentEsc = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}){3,}`)

	// Go's regexp has no backreferences, so the closing tag cannot be matched
	// in the pattern. The opening tag is found here and its partner is located
	// by hand below.
	openTag = regexp.MustCompile(`(?is)<([a-z][a-z0-9]*)\b([^>]*)>`)

	// hidesContent recognises the ways markup renders something invisible while
	// leaving it in the text a model reads.
	//
	// "hidden" must not be preceded by a hyphen, or aria-hidden="false" would
	// count as hiding its own contents.
	hidesContent = regexp.MustCompile(`(?is)` +
		`style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)` +
		`|(?:^|[^-\w])hidden(?:[\s=>]|$)` +
		`|aria-hidden\s*=\s*["']\s*true\s*["']`)
)

func extractBase64(s string) []string {
	var out []string
	for _, m := range base64Run.FindAllString(s, 16) {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding,
			base64.URLEncoding, base64.RawURLEncoding,
		} {
			decoded, err := enc.DecodeString(m)
			if err != nil || len(decoded) < minDecoded {
				continue
			}
			if text, ok := printable(decoded); ok {
				out = append(out, text)
				break
			}
		}
	}
	return out
}

func extractHex(s string) []string {
	var out []string
	for _, m := range hexRun.FindAllString(s, 16) {
		decoded, err := hex.DecodeString(m)
		if err != nil || len(decoded) < minDecoded {
			continue
		}
		if text, ok := printable(decoded); ok {
			out = append(out, text)
		}
	}
	return out
}

func extractPercent(s string) []string {
	var out []string
	for _, m := range percentEsc.FindAllString(s, 16) {
		if decoded, err := url.QueryUnescape(m); err == nil && len(decoded) >= minDecoded {
			out = append(out, decoded)
		}
	}
	return out
}

func extractHTMLComments(s string) []string {
	var out []string
	for _, m := range htmlNote.FindAllStringSubmatch(s, 16) {
		if strings.TrimSpace(m[1]) != "" {
			out = append(out, m[1])
		}
	}
	return out
}

func extractHiddenMarkup(s string) []string {
	var out []string
	lower := strings.ToLower(s)
	for _, loc := range openTag.FindAllStringSubmatchIndex(s, 64) {
		if len(out) >= 16 {
			break
		}
		attrs := s[loc[4]:loc[5]]
		if !hidesContent.MatchString(attrs) {
			continue
		}
		body := s[loc[1]:]
		if end := strings.Index(lower[loc[1]:], "</"+strings.ToLower(s[loc[2]:loc[3]])); end >= 0 {
			body = body[:end]
		}
		if strings.TrimSpace(body) != "" {
			out = append(out, body)
		}
	}
	return out
}

// printable reports whether decoded bytes look like text a human wrote, which
// is what separates a hidden message from a thumbnail that happened to sit in a
// base64 field.
func printable(b []byte) (string, bool) {
	if !utf8.Valid(b) {
		return "", false
	}
	s := string(b)
	var good, letters int
	for _, r := range s {
		switch {
		case unicode.IsLetter(r):
			letters++
			good++
		case unicode.IsDigit(r), unicode.IsPunct(r), unicode.IsSpace(r), unicode.IsSymbol(r):
			good++
		}
	}
	total := utf8.RuneCountInString(s)
	if total == 0 {
		return "", false
	}
	// Mostly printable, and containing actual words rather than a run of
	// punctuation that happens to decode cleanly.
	return s, good*10 >= total*9 && letters*4 >= total
}
