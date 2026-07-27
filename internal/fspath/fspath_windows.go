//go:build windows

package fspath

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// maxLongPath is the ceiling for a path with the \\?\ prefix.
const maxLongPath = 32768

// expandEnv expands %VAR%, but only for variables that are actually set.
//
// Windows APIs and most tooling expand these, so a path written as
// %USERPROFILE%\.ssh\id_rsa reaches the same file as the spelled-out form. A
// rule that only knows the spelled-out form is trivially side-stepped.
// Undefined variables are left alone rather than blanked, because a literal
// percent sign is legal in a filename.
func expandEnv(p string) string {
	var b strings.Builder
	for {
		start := strings.IndexByte(p, '%')
		if start < 0 {
			b.WriteString(p)
			return b.String()
		}
		end := strings.IndexByte(p[start+1:], '%')
		if end < 0 {
			b.WriteString(p)
			return b.String()
		}
		end += start + 1

		name := p[start+1 : end]
		value, ok := os.LookupEnv(name)
		b.WriteString(p[:start])
		if ok && name != "" {
			b.WriteString(value)
		} else {
			b.WriteString(p[start : end+1])
		}
		p = p[end+1:]
	}
}

// stripExtendedPrefix removes the \\?\ and \\?\UNC\ forms, which name the same
// object while looking nothing like it.
func stripExtendedPrefix(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		return `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		return p[len(`\\?\`):]
	case strings.HasPrefix(p, `\\.\`):
		return p[len(`\\.\`):]
	}
	return p
}

// splitStream separates an NTFS alternate data stream from the file it hangs
// off: "C:\x\.env:secret" is a stream on ".env", not a file called ".env:secret".
//
// The stream is stripped so that a rule protecting a file protects its streams
// too. Writing to one is a way to leave data in a place that ordinary directory
// listings do not show.
func splitStream(p string) (path, stream string) {
	// Skip the drive colon at index 1.
	search := p
	offset := 0
	if len(p) > 1 && p[1] == ':' {
		search = p[2:]
		offset = 2
	}
	i := strings.IndexByte(search, ':')
	if i < 0 {
		return p, ""
	}
	stream = search[i+1:]
	// A trailing ":$DATA" names the stream's type, not part of its name, so
	// "file:evil:$DATA" and "file:evil" are the same stream.
	if idx := strings.LastIndex(strings.ToUpper(stream), ":$DATA"); idx >= 0 {
		stream = stream[:idx]
	} else if strings.EqualFold(stream, "$DATA") {
		stream = ""
	}
	return p[:offset+i], stream
}

// longName expands 8.3 short names: C:\Users\ADMINI~1 and C:\Users\Administrator
// are the same directory, and only one of them matches a rule written by hand.
func longName(p string) string {
	u16, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, maxLongPath)
	n, err := windows.GetLongPathName(u16, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) >= len(buf) {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}

// foldKey makes the comparison form. NTFS is case-insensitive by default, so
// C:\Users\me\.SSH and C:\Users\me\.ssh are one directory.
func foldKey(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// FoldSegment folds a single path component the same way.
func FoldSegment(s string) string { return strings.ToLower(s) }
