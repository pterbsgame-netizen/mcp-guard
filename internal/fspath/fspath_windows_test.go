//go:build windows

package fspath

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAlternateDataStream: "C:\x\.env:secret" writes into a stream hanging off
// .env, not into a file called ".env:secret". A rule protecting the file has to
// protect its streams, or it leaves a place to stash data that does not show up
// in a directory listing.
func TestAlternateDataStream(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, ".env")

	tests := []struct {
		in         string
		wantStream string
	}{
		{base, ""},
		{base + ":secret", "secret"},
		{base + ":secret:$DATA", "secret"},
		{base + "::$DATA", ""},
	}
	for _, tt := range tests {
		got, err := Resolve(tt.in, "")
		if err != nil {
			t.Fatalf("Resolve(%q): %v", tt.in, err)
		}
		if got.Stream != tt.wantStream {
			t.Errorf("Resolve(%q).Stream = %q, want %q", tt.in, got.Stream, tt.wantStream)
		}
		want, err := Resolve(base, "")
		if err != nil {
			t.Fatalf("Resolve(%q): %v", base, err)
		}
		if got.Key != want.Key {
			t.Errorf("Resolve(%q).Key = %s, want it to match the file itself (%s)", tt.in, got.Key, want.Key)
		}
	}
}

// TestDriveColonIsNotAStream: the colon after a drive letter is not a stream
// separator, and treating it as one would reduce every absolute path to "C".
func TestDriveColonIsNotAStream(t *testing.T) {
	got, err := Resolve(`C:\Windows\System32`, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Stream != "" {
		t.Errorf("Stream = %q, want empty", got.Stream)
	}
	if len(got.Abs) < 3 || got.Abs[1] != ':' {
		t.Errorf("Abs = %q, want a drive-qualified path", got.Abs)
	}
}

// TestShortNameIsExpanded covers the 8.3 aliases: C:\PROGRA~1 and
// C:\Program Files are one directory, and only one of them matches a rule
// somebody wrote by hand.
func TestShortNameIsExpanded(t *testing.T) {
	long := filepath.Join(os.Getenv("SystemDrive")+`\`, "Program Files")
	if _, err := os.Stat(long); err != nil {
		t.Skipf("no %s on this machine", long)
	}
	short := filepath.Join(os.Getenv("SystemDrive")+`\`, "PROGRA~1")
	if _, err := os.Stat(short); err != nil {
		t.Skip("8.3 short names are disabled on this volume")
	}

	gotShort, err := Resolve(filepath.Join(short, "x.txt"), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	gotLong, err := Resolve(filepath.Join(long, "x.txt"), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotShort.Key != gotLong.Key {
		t.Errorf("short name not expanded:\n  %s\n  %s", gotShort.Key, gotLong.Key)
	}
}
