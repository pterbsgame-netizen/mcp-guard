package proxy_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
	"github.com/pterbsgame-netizen/mcp-guard/internal/proxy"
)

// helperEnv marks a re-execution of this test binary as "be the MCP server".
const helperEnv = "MCPGUARD_TEST_HELPER"

// TestHelperServer is not a test. When the proxy re-executes this binary with
// helperEnv set, this function plays the role of the MCP server: it echoes
// every line back verbatim, which makes byte-for-byte transparency checkable in
// both directions at once.
//
// It must os.Exit before returning, or the testing framework would print "PASS"
// onto the stream we are pretending is JSON-RPC.
func TestHelperServer(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		t.Skip("not a helper invocation")
	}
	fmt.Fprintln(os.Stderr, "helper: up")

	r := bufio.NewReaderSize(os.Stdin, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			_, _ = os.Stdout.Write(line)
		}
		if err != nil {
			break
		}
	}
	fmt.Fprintln(os.Stderr, "helper: down")
	os.Exit(0)
}

func helperOptions(t *testing.T) proxy.Options {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return proxy.Options{
		Argv:  []string{self, "-test.run=^TestHelperServer$"},
		Env:   append(os.Environ(), helperEnv+"=1"),
		Grace: 5 * time.Second,
	}
}

// TestTransparency is the seed of the conformance test: whatever the client
// sends must reach the server unchanged, and whatever the server answers must
// reach the client unchanged. Every future stage has to keep this passing for
// traffic it does not deliberately block.
func TestTransparency(t *testing.T) {
	// A 2 MiB argument: this is the regression guard for bufio.Scanner's 64 KiB
	// default, which would truncate the message and look like a dead server.
	big := strings.Repeat("x", 2<<20)

	var buf bytes.Buffer
	for _, m := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"` + big + `"}}}`,
	} {
		buf.WriteString(m)
		buf.WriteByte('\n')
	}
	want := buf.Bytes()

	logPath := filepath.Join(t.TempDir(), "session.jsonl")
	log, err := proxy.OpenSessionLog(logPath, 0)
	if err != nil {
		t.Fatalf("OpenSessionLog: %v", err)
	}

	var out, errOut bytes.Buffer
	opts := helperOptions(t)
	opts.Log = log
	opts.Stdin = bytes.NewReader(want)
	opts.Stdout = &out
	opts.Stderr = &errOut

	res, err := proxy.Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v (stderr: %s)", err, errOut.String())
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0 (stderr: %s)", res.ExitCode, errOut.String())
	}
	if got := out.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("stream is not transparent: got %d bytes, want %d", len(got), len(want))
	}
	// stderr must be relayed, not swallowed.
	if s := errOut.String(); !strings.Contains(s, "helper: up") {
		t.Errorf("server stderr was not relayed, got %q", s)
	}

	assertLog(t, logPath, len(want))
}

// assertLog checks that the session file is well-formed JSONL, has both
// directions, and preserved the large message intact.
func assertLog(t *testing.T, path string, streamBytes int) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()

	type rec struct {
		Seq uint64          `json:"seq"`
		Ev  string          `json:"ev"`
		Dir string          `json:"dir"`
		Msg json.RawMessage `json:"msg"`
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20) // the log has 2 MiB lines in it
	var events []string
	counts := map[string]int{}
	var lastSeq uint64
	for sc.Scan() {
		var r rec
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("log line is not valid JSON: %v", err)
		}
		if r.Seq <= lastSeq {
			t.Errorf("seq not monotonic: %d after %d", r.Seq, lastSeq)
		}
		lastSeq = r.Seq
		if r.Ev != "" {
			events = append(events, r.Ev)
			continue
		}
		counts[r.Dir]++
		if len(r.Msg) == 0 {
			t.Errorf("record %d has no msg payload", r.Seq)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan log: %v", err)
	}

	if want := []string{"start", "exit"}; !equalStrings(events, want) {
		t.Errorf("events = %v, want %v", events, want)
	}
	if counts[proxy.DirClientToServer] != 4 {
		t.Errorf("c2s records = %d, want 4", counts[proxy.DirClientToServer])
	}
	if counts[proxy.DirServerToClient] != 4 {
		t.Errorf("s2c records = %d, want 4", counts[proxy.DirServerToClient])
	}
	if fi, err := os.Stat(path); err == nil && fi.Size() < int64(streamBytes) {
		t.Errorf("log is %d bytes, smaller than the %d bytes of traffic it recorded", fi.Size(), streamBytes)
	}
}

// TestNonJSONOutput covers the real-world case of a server writing noise to
// stdout: it must still be relayed, and the log must stay parseable.
func TestNonJSONOutput(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "session.jsonl")
	log, err := proxy.OpenSessionLog(logPath, 0)
	if err != nil {
		t.Fatalf("OpenSessionLog: %v", err)
	}
	log.Record(proxy.DirServerToClient, []byte("npm warn: something\n"))
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var r struct {
		Raw string `json:"raw"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(data), &r); err != nil {
		t.Fatalf("log line is not valid JSON: %v", err)
	}
	if r.Raw != "npm warn: something" {
		t.Errorf("raw = %q, want %q", r.Raw, "npm warn: something")
	}
}

// TestRotation checks that the log is split once it outgrows the limit, that no
// record is lost or torn in half, and that two rotations in the same second do
// not overwrite each other.
func TestRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "session.jsonl")

	// Small enough that a handful of records forces several rotations.
	log, err := proxy.OpenSessionLog(logPath, 300)
	if err != nil {
		t.Fatalf("OpenSessionLog: %v", err)
	}
	const records = 24
	for i := 0; i < records; i++ {
		log.Record(proxy.DirClientToServer, []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`+"\n", i)))
	}
	if err := log.Close(); err != nil {
		t.Fatalf("log.Close: %v", err)
	}

	files, err := filepath.Glob(filepath.Join(dir, "session*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("expected the log to be rotated, got %d file(s): %v", len(files), files)
	}

	// Every record must survive exactly once, and every line must still be
	// complete JSON: rotation may split the file, never a record.
	seen := map[float64]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var r struct {
				Msg struct {
					ID float64 `json:"id"`
				} `json:"msg"`
			}
			if err := json.Unmarshal(line, &r); err != nil {
				t.Fatalf("torn record in %s: %v", filepath.Base(f), err)
			}
			if seen[r.Msg.ID] {
				t.Errorf("record id=%v appears twice across rotated files", r.Msg.ID)
			}
			seen[r.Msg.ID] = true
		}
	}
	if len(seen) != records {
		t.Errorf("recovered %d records across %d files, want %d", len(seen), len(files), records)
	}
}

// TestCorpusParses runs the parser over a real recorded session. It is skipped
// unless MCPGUARD_CORPUS points at one, because the corpus is machine-specific
// and never committed:
//
//	MCPGUARD_CORPUS=~/.mcp-guard/session.jsonl go test ./internal/proxy/
//
// This is the cheap half of the replay harness: every message the parser cannot
// classify is a message stage 3 would have to make a policy decision about
// blind.
func TestCorpusParses(t *testing.T) {
	path := os.Getenv("MCPGUARD_CORPUS")
	if path == "" {
		t.Skip("set MCPGUARD_CORPUS to a session log to run this")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 64<<20)

	var records, parsed int
	kinds := map[string]int{}
	for line := 1; sc.Scan(); line++ {
		var rec struct {
			Ev  string          `json:"ev"`
			Dir string          `json:"dir"`
			Msg json.RawMessage `json:"msg"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("%s:%d is not valid JSONL: %v", path, line, err)
		}
		if rec.Ev != "" || len(rec.Msg) == 0 {
			continue
		}
		records++
		msgs, _, err := mcp.ParseFrame(rec.Msg)
		if err != nil {
			t.Errorf("%s:%d (%s) did not parse: %v\n  %s", path, line, rec.Dir, err, rec.Msg)
			continue
		}
		parsed++
		for _, m := range msgs {
			kinds[rec.Dir+" "+m.Kind.String()]++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	t.Logf("parsed %d/%d recorded messages", parsed, records)
	for k, n := range kinds {
		t.Logf("  %-18s %d", k, n)
	}
}

// TestNilLogIsSafe documents that a nil *SessionLog is a working no-op log.
func TestNilLogIsSafe(t *testing.T) {
	var log *proxy.SessionLog
	log.Record(proxy.DirClientToServer, []byte("{}\n"))
	log.Event("start", map[string]any{"pid": 1})
	if err := log.Close(); err != nil {
		t.Errorf("Close on nil log: %v", err)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
