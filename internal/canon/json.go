// Package canon produces the canonical form of a JSON value, following
// RFC 8785 (JCS), so that two encodings of the same value hash identically.
//
// Pinning stands or falls on this. A server is free to serialise its tool
// schemas differently between runs — reordered keys, a rewritten number, extra
// whitespace — without changing their meaning. Hashing the raw bytes would call
// that tampering, the tool would cry wolf on the first restart, and the user
// would remove it. Canonicalising first means a hash changes only when the
// schema actually changes.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// JSON returns the canonical encoding of raw.
func JSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are kept as text until the last moment so that parsing and
	// formatting are separate, testable steps.
	dec.UseNumber()

	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	// Reject trailing content: "{} garbage" must not canonicalise to "{}".
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("canon: trailing content after JSON value")
	}

	var b bytes.Buffer
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Hash returns the hex-encoded SHA-256 of the canonical form of raw.
func Hash(raw []byte) (string, error) {
	c, err := JSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// HashOf marshals v and hashes its canonical form.
func HashOf(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("canon: %w", err)
	}
	return Hash(raw)
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return parseObject(dec)
		case '[':
			return parseArray(dec)
		default:
			return nil, fmt.Errorf("canon: unexpected %q", t)
		}
	case json.Number, string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("canon: unexpected token %T", tok)
	}
}

func parseObject(dec *json.Decoder) (map[string]any, error) {
	obj := make(map[string]any)
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("canon: %w", err)
		}
		if d, ok := tok.(json.Delim); ok && d == '}' {
			return obj, nil
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("canon: object key is not a string")
		}
		// Duplicate keys are rejected rather than resolved. RFC 8785 requires
		// it, and here it is also a defence: parsers disagree about which
		// duplicate wins, so a server could ship a schema whose description
		// reads one way to the pinning code and another to the agent.
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("canon: duplicate object key %q", key)
		}
		v, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		obj[key] = v
	}
}

func parseArray(dec *json.Decoder) ([]any, error) {
	arr := []any{}
	for {
		if !dec.More() {
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, fmt.Errorf("canon: %w", err)
			}
			return arr, nil
		}
		v, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
	}
}

func writeValue(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, t)
	case json.Number:
		s, err := formatNumber(t)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// RFC 8785 orders keys by their UTF-16 code units, which is not the
		// same as Go's byte-wise string order: a character outside the BMP
		// encodes to surrogates in 0xD800-0xDBFF and so sorts below U+E000
		// and above, while in UTF-8 it sorts above everything in the BMP.
		sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeValue(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("canon: cannot encode %T", v)
	}
	return nil
}

// writeString emits a JSON string with the minimal escaping RFC 8785 requires.
//
// encoding/json is not usable here: it also escapes <, > and & as < and
// friends to be safe inside HTML, which is valid JSON but not the canonical
// form, so the hash would not match another implementation's.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// formatNumber renders a number the way ECMAScript's Number::toString does,
// which is what RFC 8785 mandates.
//
// Go's own formatting is close but not equal: strconv switches to exponential
// notation at different magnitudes than ECMAScript, so 1e21 and 0.0000001 would
// come out in the wrong shape and hash differently from every other JCS
// implementation.
func formatNumber(n json.Number) (string, error) {
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil {
		return "", fmt.Errorf("canon: %q is not a number: %w", n, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("canon: %v has no JSON representation", f)
	}
	if f == 0 {
		return "0", nil // also normalises -0
	}

	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}

	// strconv's 'e' form gives the shortest round-tripping digits plus a
	// decimal exponent: "1.234e+05" means digits "1234" scaled by 10^5.
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, expPart, _ := strings.Cut(sci, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp10, err := strconv.Atoi(expPart)
	if err != nil {
		return "", fmt.Errorf("canon: cannot parse exponent of %q", sci)
	}

	// ECMAScript's variables: k significant digits, value = digits x 10^(n-k).
	k := len(digits)
	n10 := exp10 + 1

	switch {
	case k <= n10 && n10 <= 21:
		return sign + digits + strings.Repeat("0", n10-k), nil
	case 0 < n10 && n10 <= 21:
		return sign + digits[:n10] + "." + digits[n10:], nil
	case -6 < n10 && n10 <= 0:
		return sign + "0." + strings.Repeat("0", -n10) + digits, nil
	}

	// Exponential form. The exponent is always signed and never zero-padded.
	e := n10 - 1
	esign := "+"
	if e < 0 {
		esign, e = "-", -e
	}
	if k == 1 {
		return sign + digits + "e" + esign + strconv.Itoa(e), nil
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + esign + strconv.Itoa(e), nil
}
