// Package fspath resolves a path string into a form that can safely be compared
// against a policy.
//
// Every deny rule is only as good as the resolution in front of it. A rule that
// protects ~/.ssh is worthless if ../../.ssh/id_rsa, C:\Users\me\.SSH\id_rsa,
// C:\Users\ME~1\.ssh\id_rsa, \\?\C:\Users\me\.ssh\id_rsa and a symlink pointing
// at the same file all reach the filesystem while none of them match the rule.
// Comparison must happen after resolution, never before.
package fspath

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Resolved is a path reduced to a comparable form.
type Resolved struct {
	// Input is what was seen on the wire, kept for error messages.
	Input string

	// Abs is absolute, cleaned, with links and short names resolved as far as
	// the filesystem allows. This is what to show a human.
	Abs string

	// Key is Abs folded for comparison: lowercased on the platforms whose
	// filesystems are case-insensitive by default.
	Key string

	// Stream is an NTFS alternate data stream name, when the input named one.
	// It is stripped from Abs so that a rule protecting a file also protects
	// the streams hanging off it.
	Stream string
}

// ErrNotAPath reports that the string was not usable as a filesystem path.
var ErrNotAPath = errors.New("not a path")

// Resolve reduces input to a comparable form. Relative paths are taken against
// base, or the process working directory when base is empty.
//
// The path does not have to exist. A policy has to decide about writes to files
// that are not there yet, which is most of the interesting cases, so resolution
// takes the longest prefix that does exist and leaves the rest alone.
func Resolve(input, base string) (Resolved, error) {
	r := Resolved{Input: input}
	p := strings.TrimSpace(input)
	if p == "" {
		return r, ErrNotAPath
	}

	// Expanding is the safe direction. Anything left unexpanded is a way to
	// name a protected file without matching the rule that protects it, and a
	// literal %VAR% or ~ in a benign path is rare enough to be worth the trade.
	p = expandHome(p)
	p = expandEnv(p)

	p = stripExtendedPrefix(p)
	p, r.Stream = splitStream(p)
	if p == "" {
		return r, ErrNotAPath
	}

	if !filepath.IsAbs(p) {
		if base == "" {
			cwd, err := os.Getwd()
			if err != nil {
				return r, err
			}
			base = cwd
		}
		p = filepath.Join(base, p)
	}
	p = filepath.Clean(p)

	// Resolve links and short names over the part that exists. A symlink is
	// the oldest way to make one name mean another file.
	p = resolveExisting(p)

	r.Abs = p
	r.Key = foldKey(p)
	return r, nil
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(p string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`) {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, p[2:])
}

// resolveExisting resolves links and short names across the longest existing
// prefix of p, then re-attaches the components that do not exist yet.
func resolveExisting(p string) string {
	rest := ""
	cur := p
	for i := 0; i < 64; i++ { // bounded: a pathological path must not spin
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			real = longName(real)
			if rest == "" {
				return filepath.Clean(real)
			}
			return filepath.Clean(filepath.Join(real, rest))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break // reached the root and nothing existed
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
	return filepath.Clean(p)
}

// Under reports whether the resolved path is at or below dir.
//
// Comparison is component-wise on purpose: a plain string prefix test says
// /home/user-backup is under /home/user, which would let a rule leak onto paths
// it was never meant to cover.
func (r Resolved) Under(dir Resolved) bool {
	if r.Key == dir.Key {
		return true
	}
	prefix := dir.Key
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(r.Key, prefix)
}

func (r Resolved) String() string {
	if r.Stream != "" {
		return r.Abs + ":" + r.Stream
	}
	return r.Abs
}
