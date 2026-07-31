package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lines builds a fixture without raw newlines in the source, which is a habit
// this repository keeps for reasons recorded elsewhere.
func lines(l ...string) string { return strings.Join(l, "\n") + "\n" }

func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func guard(t *testing.T) Options {
	t.Helper()
	return Options{Guard: filepath.Join(t.TempDir(), "mcp-guard"), Args: []string{"--policy", "default"}}
}

const desktop = `{
  "theme": "dark",
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Users\\me\\dev"],
      "env": {"NODE_ENV": "production"}
    }
  },
  "windowBounds": {"x": 12, "y": 40}
}
`

func TestWrapLeavesEverythingElseAlone(t *testing.T) {
	path := write(t, "claude_desktop_config.json", desktop)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(false); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)

	// The point of splicing rather than re-serialising: keys the tool has no
	// opinion about keep their place and their spelling.
	for _, keep := range []string{`"theme": "dark"`, `"windowBounds": {"x": 12, "y": 40}`} {
		if !strings.Contains(got, keep) {
			t.Errorf("%s was disturbed:\n%s", keep, got)
		}
	}
	// env is a field inside the declaration that this package does not touch,
	// and losing it would silently change what the server can reach.
	if !strings.Contains(got, `"NODE_ENV"`) {
		t.Errorf("env was dropped from the declaration:\n%s", got)
	}
	if !strings.Contains(got, `"--policy"`) || !strings.Contains(got, `"--"`) {
		t.Errorf("the guard flags are missing:\n%s", got)
	}

	var probe struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(got), &probe); err != nil {
		t.Fatalf("the rewritten file does not parse: %v", err)
	}
	fs := probe.MCPServers["filesystem"]
	if fs.Command != o.Guard {
		t.Errorf("command is %q, want the guard", fs.Command)
	}
	want := []string{"--policy", "default", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", `C:\Users\me\dev`}
	if strings.Join(fs.Args, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("args are\n  %q\nwant\n  %q", fs.Args, want)
	}
}

func TestUninstallRestoresTheCommandAndLeavesTheRestAlone(t *testing.T) {
	path := write(t, "claude_desktop_config.json", desktop)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	in, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.Apply(false); err != nil {
		t.Fatal(err)
	}

	out, err := PlanUninstall([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := out.Apply(false); err != nil {
		t.Fatal(err)
	}

	got := read(t, path)

	// The declaration that was wrapped comes back indented rather than in its
	// original shape - the arguments it briefly held did not fit on one line.
	// What must survive exactly is everything the tool had no business touching.
	for _, keep := range []string{`  "theme": "dark",`, `  "windowBounds": {"x": 12, "y": 40}`} {
		if !strings.Contains(got, keep) {
			t.Errorf("%q was disturbed by a round trip:\n%s", keep, got)
		}
	}
	if !same(t, got, desktop) {
		t.Errorf("round trip changed what the file means:\n--- got\n%s\n--- want\n%s", got, desktop)
	}
}

// same compares two configs by content rather than by layout.
func same(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal([]byte(a), &x); err != nil {
		t.Fatalf("left side does not parse: %v", err)
	}
	if err := json.Unmarshal([]byte(b), &y); err != nil {
		t.Fatalf("right side does not parse: %v", err)
	}
	ax, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return string(ax) == string(by)
}

func TestSecondInstallChangesNothing(t *testing.T) {
	path := write(t, "cfg.json", desktop)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	first, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Apply(false); err != nil {
		t.Fatal(err)
	}
	after := read(t, path)

	second, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Files()) != 0 {
		t.Errorf("a second install wants to write %v", second.Files())
	}
	if second.Changes[0].Kind != Skip || second.Changes[0].Note != "already wrapped" {
		t.Errorf("second run reported %+v", second.Changes[0])
	}
	if read(t, path) != after {
		t.Error("the file moved on a run that reported no changes")
	}
}

func TestRemoteServersAreSkippedAndSaidSo(t *testing.T) {
	cfg := lines(
		`{`,
		`  "mcpServers": {`,
		`    "remote": {"url": "https://example.invalid/mcp"}`,
		`  }`,
		`}`,
	)
	path := write(t, "cfg.json", cfg)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Files()) != 0 {
		t.Fatal("a remote server was rewritten")
	}
	// The note matters as much as the skip. A proxy that quietly ignores a
	// server leaves the reader believing it is covered.
	if !strings.Contains(r.Changes[0].Note, "not a stdio server") {
		t.Errorf("note is %q", r.Changes[0].Note)
	}
}

func TestNestedProjectServersAreWrapped(t *testing.T) {
	cfg := lines(
		`{`,
		`  "projects": {`,
		`    "C:\\Users\\me\\dev": {`,
		`      "mcpServers": {`,
		`        "context7": {"command": "npx", "args": ["-y", "@upstash/context7-mcp"]}`,
		`      }`,
		`    }`,
		`  }`,
		`}`,
	)
	path := write(t, "dot-claude.json", cfg)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Changes) != 1 || r.Changes[0].Kind != Wrap {
		t.Fatalf("changes: %+v", r.Changes)
	}
	// Claude Code launches these exactly like the top-level ones. A wrapper
	// that only sees the top level reports success and guards nothing.
	if r.Changes[0].Server != "projects/C:\\Users\\me\\dev/context7" {
		t.Errorf("server is named %q", r.Changes[0].Server)
	}
	if _, err := r.Apply(false); err != nil {
		t.Fatal(err)
	}
	if !json.Valid([]byte(read(t, path))) {
		t.Error("the nested rewrite produced invalid JSON")
	}
}

func TestUnwrapWithoutSeparatorIsLeftAlone(t *testing.T) {
	cfg := lines(
		`{`,
		`  "mcpServers": {`,
		`    "odd": {"command": "/usr/bin/mcp-guard", "args": ["--policy", "default"]}`,
		`  }`,
		`}`,
	)
	path := write(t, "cfg.json", cfg)

	r, err := PlanUninstall([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	// Guessing which argument is the command would silently launch the wrong
	// binary, which is worse than saying it cannot be done.
	if r.Changes[0].Kind != Skip || !strings.Contains(r.Changes[0].Note, "separator") {
		t.Errorf("changes: %+v", r.Changes)
	}
	if len(r.Files()) != 0 {
		t.Error("a declaration with no separator was rewritten anyway")
	}
}

func TestApplyWritesABackup(t *testing.T) {
	path := write(t, "cfg.json", desktop)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	backups, err := r.Apply(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backups: %v", backups)
	}
	if got := read(t, backups[0]); got != desktop {
		t.Errorf("the backup is not the original file:\n%s", got)
	}
}

func TestBrokenConfigIsReportedNotRewritten(t *testing.T) {
	path := write(t, "cfg.json", `{"mcpServers": {`)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := PlanInstall([]string{path}, o); err == nil {
		t.Fatal("a truncated config was accepted")
	}
	if got := read(t, path); got != `{"mcpServers": {` {
		t.Errorf("the file was touched anyway: %q", got)
	}
}

func TestArgumentsAreNotHTMLEscaped(t *testing.T) {
	// Found on a real config: uvx --with "mcp<2" came back as "mcp<2".
	// encoding/json escapes <, > and & by default for embedding in HTML, and
	// the result parses to the same string - but a person opening their config
	// sees a mangled argument and stops trusting the tool that put it there.
	cfg := lines(
		`{`,
		`  "mcpServers": {`,
		`    "fetch": {"command": "uvx", "args": ["--with", "mcp<2", "a&b", "x>y"]}`,
		`  }`,
		`}`,
	)
	path := write(t, "cfg.json", cfg)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(false); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)

	for _, escaped := range []string{"\\u003c", "\\u003e", "\\u0026"} {
		if strings.Contains(got, escaped) {
			t.Errorf("arguments were HTML-escaped (%s):\n%s", escaped, got)
		}
	}
	for _, want := range []string{`"mcp<2"`, `"a&b"`, `"x>y"`} {
		if !strings.Contains(got, want) {
			t.Errorf("%s is missing from:\n%s", want, got)
		}
	}
}

func TestKeyOrderSurvives(t *testing.T) {
	cfg := lines(
		`{`,
		`  "zzz": 1,`,
		`  "mcpServers": {`,
		`    "b": {"command": "b"},`,
		`    "a": {"command": "a"}`,
		`  },`,
		`  "aaa": 2`,
		`}`,
	)
	path := write(t, "cfg.json", cfg)
	o := guard(t)
	if err := os.WriteFile(o.Guard, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, err := PlanInstall([]string{path}, o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(false); err != nil {
		t.Fatal(err)
	}
	got := read(t, path)

	// Go maps would have sorted these. Sorting somebody's config to change one
	// field in it is the kind of diff that makes a person distrust the tool.
	if strings.Index(got, `"zzz"`) > strings.Index(got, `"aaa"`) {
		t.Errorf("top-level keys were reordered:\n%s", got)
	}
	if strings.Index(got, `"b":`) > strings.Index(got, `"a":`) {
		t.Errorf("server keys were reordered:\n%s", got)
	}
}
