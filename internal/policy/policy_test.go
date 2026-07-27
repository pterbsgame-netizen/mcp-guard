package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func args(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func TestDefaultPolicyIsValid(t *testing.T) {
	p := Default()
	if p.Mode != Observe {
		t.Errorf("default mode = %q, want observe - a tool that blocks on day one is removed on day one", p.Mode)
	}
	if len(p.deny) == 0 || len(p.Taint.Sources) == 0 || len(p.Exec.Tools) == 0 {
		t.Error("the built-in policy is missing whole sections")
	}
}

// TestCurXecute is the acceptance criterion for stage 3: the attack is stopped
// at the write, not by recognising anything in the text that prompted it.
func TestCurXecute(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	p := Default()

	// Every one of these reaches the same file, on every platform.
	spellings := []string{
		filepath.Join(home, ".cursor", "mcp.json"),
		filepath.Join("~", ".cursor", "mcp.json"),
		filepath.Join(home, "projects", "..", ".cursor", "mcp.json"),
	}
	for _, path := range spellings {
		t.Run(path, func(t *testing.T) {
			v := p.Decide(Call{
				Tool: "write_file",
				Args: args(t, map[string]any{"path": path, "content": "{}"}),
			}, false)
			if v.Action != Deny {
				t.Errorf("action = %q, want deny (rule %q, paths %v)", v.Action, v.Rule, v.Paths)
			}
			if len(v.Paths) == 0 {
				t.Error("the verdict did not say which path it was about")
			}
		})
	}
}

// TestCaseFollowsTheFilesystem: on Windows and macOS ~/.CURSOR/MCP.JSON is the
// same file as ~/.cursor/mcp.json and has to be refused. On Linux it is a
// different file that no client will ever read, and refusing it would be a
// false positive invented out of nothing.
//
// This is why folding is decided per platform instead of lowercasing
// everything, and CI on Linux is what proves the distinction is real.
func TestCaseFollowsTheFilesystem(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	shouted := filepath.Join(home, ".CURSOR", "MCP.JSON")

	want := Allow
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		want = Deny
	}
	v := Default().Decide(Call{
		Tool: "write_file",
		Args: args(t, map[string]any{"path": shouted, "content": "{}"}),
	}, false)
	if v.Action != want {
		t.Errorf("%s on %s: action = %q, want %q", shouted, runtime.GOOS, v.Action, want)
	}
}

// TestOrdinaryWorkIsAllowed is the half of the criterion that decides whether
// anyone keeps this installed. None of these may produce a verdict.
func TestOrdinaryWorkIsAllowed(t *testing.T) {
	home, _ := os.UserHomeDir()
	p := Default()

	calls := []struct {
		tool string
		args any
	}{
		{"read_text_file", map[string]any{"path": filepath.Join(home, "dev", "project", "main.go")}},
		{"write_file", map[string]any{"path": filepath.Join(home, "dev", "project", "README.md"), "content": "hi"}},
		{"list_directory", map[string]any{"path": filepath.Join(home, "dev")}},
		{"search_files", map[string]any{"path": filepath.Join(home, "dev"), "pattern": "**/*.go"}},
		{"edit_file", map[string]any{
			"path":  filepath.Join(home, "dev", "project", "internal", "app", "server.go"),
			"edits": []any{map[string]any{"oldText": "a", "newText": "b"}},
		}},
		{"get_file_info", map[string]any{"path": filepath.Join(home, "dev", "notes.txt")}},
		// A tool whose arguments carry no path at all.
		{"list_allowed_directories", map[string]any{}},
		// Text that merely mentions a protected path is not an effect on it.
		{"write_file", map[string]any{
			"path":    filepath.Join(home, "dev", "project", "notes.md"),
			"content": "remember to check ~/.ssh/config and .env handling",
		}},
	}
	for _, c := range calls {
		v := p.Decide(Call{Tool: c.tool, Args: args(t, c.args)}, false)
		if v.Action != Allow {
			t.Errorf("%s: action = %q via %q (paths %v), want allow", c.tool, v.Action, v.Rule, v.Paths)
		}
	}
}

func TestDenySet(t *testing.T) {
	home, _ := os.UserHomeDir()
	p := Default()

	denied := []string{
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, "dev", "project", ".git", "hooks", "pre-commit"),
		filepath.Join(home, "dev", "project", ".env"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, "dev", "project", ".claude", "settings.json"),
		filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
		// The guard's own files: an agent that can rewrite the policy has no
		// policy.
		filepath.Join(home, "dev", "project", "mcp-guard.lock"),
		filepath.Join(home, "dev", "project", "mcp-guard.policy.yaml"),
	}
	for _, path := range denied {
		v := p.Decide(Call{Tool: "write_file", Args: args(t, map[string]any{"path": path})}, false)
		if v.Action != Deny {
			t.Errorf("%s: action = %q, want deny", path, v.Action)
		}
	}
}

// TestTaintEscalates: the same call, decided differently because of where the
// session's content came from. Nothing about the call itself changed.
func TestTaintEscalates(t *testing.T) {
	home, _ := os.UserHomeDir()
	p := Default()
	call := Call{
		Tool: "write_file",
		Args: args(t, map[string]any{"path": filepath.Join(home, "dev", "project", "build.sh")}),
	}

	if v := p.Decide(call, false); v.Action != Allow {
		t.Errorf("clean session: action = %q, want allow", v.Action)
	}
	v := p.Decide(call, true)
	if v.Action != Confirm {
		t.Fatalf("tainted session: action = %q, want confirm", v.Action)
	}
	if !strings.Contains(v.Reason, "untrusted") {
		t.Errorf("reason %q does not explain why this time is different", v.Reason)
	}
}

func TestExecClass(t *testing.T) {
	p := Default()
	call := Call{Tool: "execute_command", Args: args(t, map[string]any{"cmd": "ls"})}

	if v := p.Decide(call, false); v.Action != Confirm {
		t.Errorf("clean session: action = %q, want confirm", v.Action)
	}
	if v := p.Decide(call, true); v.Action != Deny {
		t.Errorf("tainted session: action = %q, want deny", v.Action)
	}

	if !p.IsTaintSource("fetch_url") {
		t.Error("fetch_url should be a taint source")
	}
	if p.IsTaintSource("write_file") {
		t.Error("write_file should not be a taint source")
	}
}

// TestPathsFoundAnywhereInArguments: rules must not depend on knowing which
// argument a given server calls "the path one".
func TestPathsFoundAnywhereInArguments(t *testing.T) {
	home, _ := os.UserHomeDir()
	p := Default()

	v := p.Decide(Call{
		Tool: "move_file",
		Args: args(t, map[string]any{
			"source":      filepath.Join(home, "dev", "notes.txt"),
			"destination": filepath.Join(home, ".ssh", "authorized_keys"),
		}),
	}, false)
	if v.Action != Deny {
		t.Errorf("action = %q, want deny", v.Action)
	}

	// Nested inside an array of objects, under an unfamiliar name.
	v = p.Decide(Call{
		Tool: "batch_write",
		Args: args(t, map[string]any{
			"operations": []any{
				map[string]any{"target": filepath.Join(home, "dev", "a.txt")},
				map[string]any{"target": filepath.Join(home, ".gnupg", "secring.gpg")},
			},
		}),
	}, false)
	if v.Action != Deny {
		t.Errorf("nested: action = %q, want deny", v.Action)
	}
}

func TestRelativePathsMatchUnanchoredRules(t *testing.T) {
	p := Default()
	// The server's working directory is its own business and we do not know
	// it, so an anchored rule cannot apply вЂ” but "a file called .env, wherever
	// it is" still can.
	v := p.Decide(Call{
		Tool: "read_text_file",
		Args: args(t, map[string]any{"path": "config/.env"}),
	}, false)
	if v.Action != Deny {
		t.Errorf("action = %q, want deny", v.Action)
	}
}

func TestPatternParsing(t *testing.T) {
	if _, err := compile("**"); err == nil {
		t.Error(`the pattern "**" was accepted; it matches every path`)
	}
	if _, err := compile("  "); err == nil {
		t.Error("an empty pattern was accepted")
	}

	if _, err := Parse([]byte("version: 99")); err == nil {
		t.Error("a future format version was accepted")
	}
	if _, err := Parse([]byte("version: 1\nmode: whatever")); err == nil {
		t.Error("an unknown mode was accepted")
	}
	if _, err := Parse([]byte("version: 1\nexec:\n  action: maybe")); err == nil {
		t.Error("an unknown action was accepted")
	}

	// A file rule without /** names one file, not a subtree.
	p, err := Parse([]byte("version: 1\npaths:\n  deny:\n    - \"~/.bashrc\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	home, _ := os.UserHomeDir()
	if v := p.Decide(Call{Tool: "w", Args: args(t, map[string]any{"path": filepath.Join(home, ".bashrc")})}, false); v.Action != Deny {
		t.Errorf("the file itself: action = %q, want deny", v.Action)
	}
	if v := p.Decide(Call{Tool: "w", Args: args(t, map[string]any{"path": filepath.Join(home, ".bashrc", "child")})}, false); v.Action != Allow {
		t.Errorf("a path below a file rule: action = %q, want allow", v.Action)
	}
}
