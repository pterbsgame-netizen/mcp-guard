package fspath

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func mustResolve(t *testing.T, input, base string) Resolved {
	t.Helper()
	r, err := Resolve(input, base)
	if err != nil {
		t.Fatalf("Resolve(%q): %v", input, err)
	}
	return r
}

// TestSpellingsOfOneFile is the whole point of the package: every one of these
// reaches the same file, so every one of them has to reach the same key. Any
// that does not is a way to walk past the rule protecting it.
func TestSpellingsOfOneFile(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	target := filepath.Join(home, ".ssh", "id_rsa")
	want := mustResolve(t, target, "").Key

	spellings := []struct{ name, input, base string }{
		{"tilde", filepath.Join("~", ".ssh", "id_rsa"), ""},
		{"relative from home", filepath.Join(".ssh", "id_rsa"), home},
		{"dot segments", filepath.Join(home, "x", "..", ".ssh", ".", "id_rsa"), ""},
		{"traversal from a subdirectory", filepath.Join("..", "..", ".ssh", "id_rsa"), filepath.Join(home, "a", "b")},
	}
	if runtime.GOOS == "windows" {
		spellings = append(spellings,
			struct{ name, input, base string }{"environment variable", `%USERPROFILE%\.ssh\id_rsa`, ""},
			struct{ name, input, base string }{"extended prefix", `\\?\` + target, ""},
			struct{ name, input, base string }{"different case", strings.ToUpper(target), ""},
		)
	} else {
		spellings = append(spellings,
			struct{ name, input, base string }{"environment variable", "$HOME/.ssh/id_rsa", ""},
			struct{ name, input, base string }{"braced variable", "${HOME}/.ssh/id_rsa", ""},
		)
	}

	for _, s := range spellings {
		t.Run(s.name, func(t *testing.T) {
			got := mustResolve(t, s.input, s.base)
			if got.Key != want {
				t.Errorf("%q resolved to\n  %s\nwant\n  %s", s.input, got.Key, want)
			}
		})
	}
}

// TestUnsetVariablesAreLeftAlone: blanking an unknown variable invents a path.
// $NOPE/.ssh must not become /.ssh, which is a file nobody asked about.
func TestUnsetVariablesAreLeftAlone(t *testing.T) {
	const unset = "MCPGUARD_DEFINITELY_NOT_SET"
	os.Unsetenv(unset)

	input := "$" + unset + "/x"
	if runtime.GOOS == "windows" {
		input = "%" + unset + `%\x`
	}
	got := mustResolve(t, input, string(filepath.Separator)+"base")
	if !strings.Contains(got.Abs, unset) {
		t.Errorf("an unset variable was expanded away: %q -> %q", input, got.Abs)
	}
}

// TestNonExistentPathsResolve: most interesting decisions are about a file that
// is not there yet, so resolution cannot require the path to exist.
func TestNonExistentPathsResolve(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "does", "not", "exist", "yet.json")

	got := mustResolve(t, filepath.Join(dir, "does", "not", "..", "not", "exist", "yet.json"), "")
	want := mustResolve(t, target, "")
	if got.Key != want.Key {
		t.Errorf("got %s, want %s", got.Key, want.Key)
	}
}

// TestSymlinkIsFollowed: the oldest way to make one name mean another file.
func TestSymlinkIsFollowed(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		// Windows needs developer mode or elevation for this.
		t.Skipf("cannot create symlinks here: %v", err)
	}

	viaLink := mustResolve(t, filepath.Join(link, "secret.txt"), "")
	direct := mustResolve(t, filepath.Join(real, "secret.txt"), "")
	if viaLink.Key != direct.Key {
		t.Errorf("symlink not followed:\n  %s\n  %s", viaLink.Key, direct.Key)
	}
}

// TestUnderIsComponentWise guards the classic prefix bug: /home/user-backup is
// not under /home/user, and a rule that thinks otherwise reaches files it was
// never meant to cover.
func TestUnderIsComponentWise(t *testing.T) {
	base := t.TempDir()
	dir := mustResolve(t, filepath.Join(base, "user"), "")

	inside := mustResolve(t, filepath.Join(base, "user", "notes.txt"), "")
	if !inside.Under(dir) {
		t.Errorf("%s should be under %s", inside.Key, dir.Key)
	}
	if !dir.Under(dir) {
		t.Error("a directory should be under itself")
	}

	sibling := mustResolve(t, filepath.Join(base, "user-backup", "notes.txt"), "")
	if sibling.Under(dir) {
		t.Errorf("%s must not count as under %s", sibling.Key, dir.Key)
	}
}

func TestEmptyInput(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if _, err := Resolve(in, "/base"); err == nil {
			t.Errorf("Resolve(%q) returned no error", in)
		}
	}
}
