package policy

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/pterbsgame-netizen/effectgate/internal/fspath"
)

// A pattern names a set of paths. Three forms are supported, and no more:
//
//	~/.ssh/**            everything at or below a directory
//	~/.bashrc            exactly one file
//	**/.env              a file with this name, anywhere
//	**/.git/hooks/**     anything below these segments, wherever they appear
//
// This is deliberately not a glob library. Full glob syntax treats a backslash
// as an escape character, which makes every Windows path a minefield, and the
// extra expressiveness buys nothing: the rules that matter are "this directory",
// "this file", and "this name wherever it is".
type pattern struct {
	raw string

	// anchored patterns are resolved against the filesystem once, at load.
	anchored bool
	segs     []string // folded segments; for anchored, the absolute path
	prefix   bool     // pattern ended in /**
}

func compile(raw string) (pattern, error) {
	p := pattern{raw: raw}

	body := strings.TrimSpace(raw)
	// "**" on its own, with or without a trailing separator, would match every
	// path. Nobody means that, and it is a spectacular way to block a session.
	if body == "**" || body == "**/" || body == `**\` {
		return pattern{}, errPattern(raw, "matches every path")
	}
	if strings.HasSuffix(body, "/**") || strings.HasSuffix(body, `\**`) {
		p.prefix = true
		body = body[:len(body)-3]
	}
	if strings.HasPrefix(body, "**/") || strings.HasPrefix(body, `**\`) {
		body = body[3:]
	} else {
		p.anchored = true
	}
	if body == "" {
		// "**" on its own would match everything, which is never what someone
		// meant to write and is a spectacular way to block a whole session.
		return pattern{}, errPattern(raw, "matches every path")
	}

	if p.anchored {
		resolved, err := fspath.Resolve(body, "")
		if err != nil {
			return pattern{}, errPattern(raw, err.Error())
		}
		p.segs = segments(resolved.Abs)
		return p, nil
	}
	p.segs = foldAll(splitAny(body))
	if len(p.segs) == 0 {
		return pattern{}, errPattern(raw, "no path segments")
	}
	return p, nil
}

// match reports whether the pattern covers segs, which are the folded segments
// of a path.
func (p pattern) match(segs []string) bool {
	if p.anchored {
		if len(segs) < len(p.segs) {
			return false
		}
		if !equalSegs(segs[:len(p.segs)], p.segs) {
			return false
		}
		// Without /** the pattern names exactly one path, not a subtree.
		return p.prefix || len(segs) == len(p.segs)
	}

	// Unanchored: the segments may appear anywhere.
	for start := 0; start+len(p.segs) <= len(segs); start++ {
		if !equalSegs(segs[start:start+len(p.segs)], p.segs) {
			continue
		}
		if p.prefix || start+len(p.segs) == len(segs) {
			return true
		}
	}
	return false
}

func equalSegs(a, b []string) bool {
	for i := range b {
		if !matchSeg(b[i], a[i]) {
			return false
		}
	}
	return true
}

// matchSeg compares one path component against one pattern component.
//
// Wildcards inside a component are supported so that "**/*.sh" means what it
// looks like it means. Both sides are already folded, so the case-sensitive
// matcher underneath is the right one.
func matchSeg(pat, s string) bool {
	if !strings.ContainsAny(pat, "*?[") {
		return pat == s
	}
	ok, err := path.Match(pat, s)
	return err == nil && ok
}

// segments splits a resolved absolute path into folded components.
func segments(abs string) []string {
	return foldAll(splitAny(abs))
}

// splitAny splits on both separators: a path arriving over the wire may use
// either, whatever the platform underneath is.
func splitAny(p string) []string {
	fields := strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' })
	out := fields[:0]
	for _, f := range fields {
		if f == "" || f == "." {
			continue
		}
		out = append(out, f)
	}
	return out
}

func foldAll(segs []string) []string {
	out := make([]string, len(segs))
	for i, s := range segs {
		out[i] = fspath.FoldSegment(s)
	}
	return out
}

// matchName matches a tool name against a pattern such as "execute_*".
func matchName(pat, name string) bool {
	if pat == name {
		return true
	}
	ok, err := path.Match(pat, name)
	return err == nil && ok
}

// looksLikePath decides whether an argument value is worth resolving.
//
// It is a filter, not a decision: everything that survives is still matched
// against the rules, so a false positive here costs nothing but work. A false
// negative costs a bypass, so it errs towards saying yes.
func looksLikePath(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	if strings.ContainsAny(s, "/\\") {
		return true
	}
	if strings.HasPrefix(s, "~") || strings.HasPrefix(s, ".") {
		return true
	}
	// A bare drive-qualified name such as "C:".
	if len(s) >= 2 && s[1] == ':' {
		return true
	}
	return filepath.Ext(s) != ""
}
