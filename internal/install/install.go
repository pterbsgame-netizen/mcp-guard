// Package install wires effectgate into the client configuration files that
// launch MCP servers, and takes it back out again.
//
// The file is never re-serialised as a whole. Client configs keep caches,
// feature flags and window positions beside the server declarations, and a tool
// that reformats all of that to change two fields is a tool people undo by hand
// and never run again. Only the individual declarations that actually change
// are re-emitted, spliced back into the original bytes at the offsets they came
// from, so every byte this package does not understand survives untouched.
//
// A declaration it does rewrite comes back indented rather than in whatever
// shape it had, because the arguments it gains are longer than the line they
// were on. That is the one diff this leaves, it is confined to the servers that
// were wrapped, and it does not grow on a second run.
package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/pterbsgame-netizen/effectgate/internal/canon"
)

// Kind is what happened, or would happen, to one server declaration.
type Kind string

const (
	Wrap   Kind = "wrap"
	Unwrap Kind = "unwrap"
	Skip   Kind = "skip"
)

// Change is one server declaration and the decision made about it.
type Change struct {
	File   string
	Server string
	Kind   Kind
	Note   string // why, when Kind is Skip
	Before string
	After  string
}

// Options controls how a server command is wrapped.
type Options struct {
	// Guard is the path written into the config as the command to launch. It
	// has to be absolute and it has to keep working after this process exits,
	// so the caller resolves it rather than letting this package guess.
	Guard string

	// Args go between the guard and the "--" separator, e.g. --policy default.
	Args []string
}

// Result holds the decisions and the rewritten files they imply.
type Result struct {
	Changes []Change

	// files maps a path to its new content. Only files that actually change
	// appear: rewriting a file to the bytes it already had would still update
	// its mtime, and a config-integrity tool that disturbs mtimes for nothing
	// teaches people to ignore it.
	files map[string][]byte
}

// Files returns the paths this result would write, sorted as they were given.
func (r *Result) Files() []string {
	out := make([]string, 0, len(r.files))
	for _, c := range r.Changes {
		if _, ok := r.files[c.File]; ok && !contains(out, c.File) {
			out = append(out, c.File)
		}
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// PlanInstall works out what wrapping every stdio server in these files means,
// without writing anything.
func PlanInstall(paths []string, o Options) (*Result, error) {
	if o.Guard == "" {
		return nil, errors.New("install: no path to the effectgate binary")
	}
	return plan(paths, func(decl []byte) ([]byte, Kind, string, string, string) {
		return wrap(decl, o)
	})
}

// PlanUninstall works out what unwrapping means. It does not need to know where
// the binary is: a wrapped declaration carries the original command after the
// "--" separator, which is the whole reason the separator is written.
func PlanUninstall(paths []string) (*Result, error) {
	return plan(paths, unwrap)
}

type transform func(decl []byte) (out []byte, kind Kind, note, before, after string)

func plan(paths []string, fn transform) (*Result, error) {
	r := &Result{files: map[string][]byte{}}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("install: %w", err)
		}
		raw = canon.TrimBOM(raw)

		out, changes, err := rewrite(raw, fn)
		if err != nil {
			return nil, fmt.Errorf("install: %s: %w", path, err)
		}
		for i := range changes {
			changes[i].File = path
		}
		r.Changes = append(r.Changes, changes...)
		if !bytes.Equal(raw, out) {
			r.files[path] = out
		}
	}
	return r, nil
}

// Apply writes the planned files. Each one is copied to a timestamped backup
// first, then replaced through a temporary file in the same directory, so a
// crash between the two leaves either the old config or the new one and never
// half of either.
func (r *Result) Apply(backup bool) (backups []string, err error) {
	for _, path := range r.Files() {
		data := r.files[path]

		// Refusing to write JSON that will not parse is the one check worth
		// having here: the failure mode being guarded against is a client that
		// starts with no servers at all because this package produced a file
		// its own parser rejects.
		if !json.Valid(data) {
			return backups, fmt.Errorf("install: %s: the rewritten file is not valid JSON; nothing was written", path)
		}

		if backup {
			b, err := copyAside(path)
			if err != nil {
				return backups, fmt.Errorf("install: %w", err)
			}
			backups = append(backups, b)
		}
		if err := writeAtomic(path, data); err != nil {
			return backups, fmt.Errorf("install: %w", err)
		}
	}
	return backups, nil
}

func copyAside(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	// Timestamped rather than a single .bak: the second run of this command
	// would otherwise overwrite the copy of the file as it was before the
	// first, which is the copy anyone would actually want back.
	dst := path + ".effectgate-backup." + time.Now().Format("20060102-150405")
	return dst, os.WriteFile(dst, raw, 0o600)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op once the rename below has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ── locating the declarations ───────────────────────────────────────────────

// decl is the byte range of one server declaration inside a config file.
//
// The unit is the single declaration rather than the whole mcpServers object on
// purpose. Re-emitting the enclosing object would reformat every server in it,
// including the ones this run decided to leave alone, and a config that comes
// back with a diff nobody asked for is a config people restore from backup.
type decl struct {
	start, end int
	prefix     string // indentation of the line its key sits on
	name       string // label + the key it was declared under
}

// rewrite applies fn to every server declaration in raw and splices back only
// the ones that changed.
func rewrite(raw []byte, fn transform) ([]byte, []Change, error) {
	decls, err := findDecls(raw)
	if err != nil {
		return nil, nil, err
	}

	changes := make([]Change, 0, len(decls))
	replacements := make(map[int][]byte, len(decls))
	for i, d := range decls {
		out, kind, note, before, after := fn(raw[d.start:d.end])
		changes = append(changes, Change{
			Server: d.name,
			Kind:   kind,
			Note:   note,
			Before: before,
			After:  after,
		})
		if kind == Skip {
			continue
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, out, d.prefix, "  "); err != nil {
			return nil, nil, err
		}
		replacements[i] = buf.Bytes()
	}

	// Right to left, so an earlier declaration's offsets still describe the
	// bytes they were measured against.
	out := raw
	for i := len(decls) - 1; i >= 0; i-- {
		repl, ok := replacements[i]
		if !ok {
			continue
		}
		d := decls[i]
		merged := make([]byte, 0, len(out)-(d.end-d.start)+len(repl))
		merged = append(merged, out[:d.start]...)
		merged = append(merged, repl...)
		merged = append(merged, out[d.end:]...)
		out = merged
	}
	return out, changes, nil
}

func findDecls(raw []byte) ([]decl, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := expectOpen(dec); err != nil {
		return nil, err
	}

	var out []decl
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return nil, err
		}
		block, base, err := valueAt(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "mcpServers":
			ds, err := declsIn(raw, base, block, "")
			if err != nil {
				return nil, err
			}
			out = append(out, ds...)

		case "projects":
			// Claude Code keeps per-project declarations under projects.<dir>.
			// They launch servers exactly like the global ones do, and a wrapper
			// that only looks at the top level reports success while guarding
			// nothing.
			ds, err := projectDecls(raw, base, block)
			if err != nil {
				return nil, err
			}
			out = append(out, ds...)
		}
	}
	return out, nil
}

func projectDecls(raw []byte, base int, block json.RawMessage) ([]decl, error) {
	if !isObject(block) {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(block))
	if err := expectOpen(dec); err != nil {
		return nil, err
	}

	var out []decl
	for dec.More() {
		dir, err := readKey(dec)
		if err != nil {
			return nil, err
		}
		project, offset, err := valueAt(dec)
		if err != nil {
			return nil, err
		}
		if !isObject(project) {
			continue
		}

		inner := json.NewDecoder(bytes.NewReader(project))
		if err := expectOpen(inner); err != nil {
			return nil, err
		}
		for inner.More() {
			key, err := readKey(inner)
			if err != nil {
				return nil, err
			}
			servers, at, err := valueAt(inner)
			if err != nil {
				return nil, err
			}
			if key != "mcpServers" {
				continue
			}
			ds, err := declsIn(raw, base+offset+at, servers, "projects/"+dir+"/")
			if err != nil {
				return nil, err
			}
			out = append(out, ds...)
		}
	}
	return out, nil
}

func declsIn(raw []byte, base int, block json.RawMessage, label string) ([]decl, error) {
	// "mcpServers": null is a real thing clients write, and it declares nothing.
	// Treating it as a malformed config would refuse to install over a file that
	// is not broken at all.
	if !isObject(block) {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(block))
	if err := expectOpen(dec); err != nil {
		return nil, err
	}

	var out []decl
	for dec.More() {
		name, err := readKey(dec)
		if err != nil {
			return nil, err
		}
		v, at, err := valueAt(dec)
		if err != nil {
			return nil, err
		}
		start := base + at
		out = append(out, decl{
			start:  start,
			end:    start + len(v),
			prefix: lineIndent(raw, start),
			name:   label + name,
		})
	}
	return out, nil
}

// valueAt reads the next value and reports where it began, relative to the
// start of whatever the decoder was handed.
func valueAt(dec *json.Decoder) (json.RawMessage, int, error) {
	var v json.RawMessage
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	return v, int(dec.InputOffset()) - len(v), nil
}

func isObject(raw json.RawMessage) bool { return len(raw) > 0 && raw[0] == '{' }

func lineIndent(raw []byte, at int) string {
	nl := bytes.LastIndexByte(raw[:at], '\n')
	line := raw[nl+1 : at]
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return string(line[:n])
}

func expectOpen(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("the top level of the config is not an object")
	}
	return nil
}

func readKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("expected an object key, got %v", tok)
	}
	return key, nil
}

// ── the declarations themselves ─────────────────────────────────────────────

// object is a JSON object that remembers the order its keys arrived in, which
// map[string]json.RawMessage does not. Reordering somebody's config to change
// one field in it is the kind of diff that makes a person distrust the tool.
type object struct {
	keys []string
	vals []json.RawMessage
}

func parseObject(raw []byte) (*object, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := expectOpen(dec); err != nil {
		return nil, err
	}
	o := &object{}
	for dec.More() {
		key, err := readKey(dec)
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		o.keys = append(o.keys, key)
		o.vals = append(o.vals, v)
	}
	return o, nil
}

func (o *object) get(key string) (json.RawMessage, bool) {
	for i, k := range o.keys {
		if k == key {
			return o.vals[i], true
		}
	}
	return nil, false
}

func (o *object) set(key string, val json.RawMessage) {
	for i, k := range o.keys {
		if k == key {
			o.vals[i] = val
			return
		}
	}
	o.keys = append(o.keys, key)
	o.vals = append(o.vals, val)
}

func (o *object) remove(key string) {
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			o.vals = append(o.vals[:i], o.vals[i+1:]...)
			return
		}
	}
}

func (o *object) encode() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(k)
		b.Write(key)
		b.WriteByte(':')
		b.Write(o.vals[i])
	}
	b.WriteByte('}')
	return b.Bytes()
}

func wrap(decl []byte, o Options) ([]byte, Kind, string, string, string) {
	fields, err := parseObject(decl)
	if err != nil {
		return decl, Skip, "the declaration is not an object", "", ""
	}

	command, args := commandOf(fields)
	if command == "" {
		// A url with no command is a remote server. It is not that wrapping it
		// fails; it is that a stdio proxy is not in its path at all, and saying
		// so is the honest answer rather than pretending coverage.
		if _, ok := fields.get("url"); ok {
			return decl, Skip, "not a stdio server, nothing to wrap", "", ""
		}
		return decl, Skip, "no command", "", ""
	}
	if isGuard(command) {
		return decl, Skip, "already wrapped", summary(command, args), ""
	}

	newArgs := make([]string, 0, len(o.Args)+1+1+len(args))
	newArgs = append(newArgs, o.Args...)
	newArgs = append(newArgs, "--", command)
	newArgs = append(newArgs, args...)

	before := summary(command, args)
	fields.set("command", mustJSON(o.Guard))
	fields.set("args", mustJSON(newArgs))
	return fields.encode(), Wrap, "", before, summary(o.Guard, newArgs)
}

func unwrap(decl []byte) ([]byte, Kind, string, string, string) {
	fields, err := parseObject(decl)
	if err != nil {
		return decl, Skip, "the declaration is not an object", "", ""
	}

	command, args := commandOf(fields)
	if command == "" || !isGuard(command) {
		return decl, Skip, "not wrapped", "", ""
	}

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	// Without a separator there is no way to tell flags from the command, and
	// guessing here would silently launch the wrong binary. Leaving it alone and
	// saying so lets a person fix by hand what this cannot fix safely.
	if sep < 0 || sep == len(args)-1 {
		return decl, Skip, "wrapped without a -- separator; left alone", summary(command, args), ""
	}

	rest := args[sep+1:]
	before := summary(command, args)
	fields.set("command", mustJSON(rest[0]))
	if len(rest) > 1 {
		fields.set("args", mustJSON(rest[1:]))
	} else {
		fields.remove("args")
	}
	return fields.encode(), Unwrap, "", before, summary(rest[0], rest[1:])
}

func commandOf(fields *object) (string, []string) {
	var command string
	if raw, ok := fields.get("command"); ok {
		_ = json.Unmarshal(raw, &command)
	}
	var args []string
	if raw, ok := fields.get("args"); ok {
		_ = json.Unmarshal(raw, &args)
	}
	return command, args
}

// isGuard reports whether a command is this tool, so a second run is a no-op
// rather than a proxy in front of a proxy.
func isGuard(command string) bool {
	base := filepath.Base(filepath.FromSlash(command))
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if runtime.GOOS == "windows" {
		return strings.EqualFold(base, "effectgate")
	}
	return base == "effectgate"
}

func summary(command string, args []string) string {
	if len(args) == 0 {
		return command
	}
	return command + " " + strings.Join(args, " ")
}

func mustJSON(v any) json.RawMessage {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	// json.Marshal escapes <, > and & so the result can be embedded in HTML,
	// which nothing here does. Left on, it rewrites a real argument like
	// "mcp<2" into "mcp\\u003c2" inside somebody's config: still valid, still
	// launches the same server, and still a diff nobody asked for in a file
	// people read by hand.
	enc.SetEscapeHTML(false)

	// Marshalling a string or a slice of strings cannot fail, and returning an
	// error the caller has no way to act on would only spread that lie.
	if err := enc.Encode(v); err != nil {
		panic("install: " + err.Error())
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
}
