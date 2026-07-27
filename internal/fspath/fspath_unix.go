//go:build !windows

package fspath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// expandEnv expands $VAR and ${VAR}, but only for variables that are set.
//
// os.ExpandEnv is not usable here: it replaces an unset variable with an empty
// string, which turns $NOPE/.ssh into /.ssh and invents a path nobody asked
// about. A dollar sign is a legal filename character, so leaving unknown names
// alone is both safer and more honest.
func expandEnv(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); {
		if p[i] != '$' {
			b.WriteByte(p[i])
			i++
			continue
		}
		name, width := envName(p[i+1:])
		value, ok := os.LookupEnv(name)
		if name == "" || !ok {
			b.WriteByte('$')
			i++
			continue
		}
		b.WriteString(value)
		i += 1 + width
	}
	return b.String()
}

// envName reads a variable reference at the start of s, returning its name and
// how many bytes the reference occupies.
func envName(s string) (name string, width int) {
	if strings.HasPrefix(s, "{") {
		if end := strings.IndexByte(s, '}'); end > 0 {
			return s[1:end], end + 1
		}
		return "", 0
	}
	i := 0
	for i < len(s) && (s[i] == '_' ||
		('a' <= s[i] && s[i] <= 'z') ||
		('A' <= s[i] && s[i] <= 'Z') ||
		(i > 0 && '0' <= s[i] && s[i] <= '9')) {
		i++
	}
	return s[:i], i
}

// stripExtendedPrefix has no counterpart outside Windows.
func stripExtendedPrefix(p string) string { return p }

// splitStream has no counterpart outside NTFS; a colon is an ordinary
// filename character here.
func splitStream(p string) (string, string) { return p, "" }

// longName has no counterpart: there are no 8.3 aliases.
func longName(p string) string { return p }

// foldKey makes the comparison form.
//
// Linux filesystems are case-sensitive and the case must be kept. macOS is
// case-insensitive by default, so folding there is required or ~/.SSH walks
// straight past a rule protecting ~/.ssh.
func foldKey(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "darwin" {
		return strings.ToLower(p)
	}
	return p
}

// FoldSegment folds a single path component the same way.
func FoldSegment(s string) string {
	if runtime.GOOS == "darwin" {
		return strings.ToLower(s)
	}
	return s
}
