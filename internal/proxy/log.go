package proxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultMaxLogBytes is the size at which a session log is rotated.
//
// The number is not arbitrary: a single tools/list response from a real server
// is on the order of 15 KB, and a client re-runs the handshake on every restart,
// so the log grows steadily even when no tool is ever called.
const DefaultMaxLogBytes = 64 << 20

// SessionLog appends one JSON object per line to a session file.
//
// Two kinds of records are written:
//
//	{"seq":1,"t":"...","ev":"start","argv":[...],"pid":1234}
//	{"seq":2,"t":"...","dir":"c2s","msg":{...}}
//
// The message payload is embedded verbatim, byte for byte, not re-marshalled.
// That matters later: stage 2 hashes tool schemas, and a round-trip through
// encoding/json would reorder keys and change the hash.
//
// A nil *SessionLog is valid and discards everything, so callers never need a
// nil check.
type SessionLog struct {
	mu  sync.Mutex
	w   io.WriteCloser
	seq uint64

	// sid identifies this proxy run. The log is shared across runs and seq
	// restarts at 1 in every process, so without it a reader has no way to tell
	// two appended sessions apart.
	sid string

	// Rotation state. path is empty for logs not backed by a file, which
	// disables rotation entirely.
	path     string
	maxBytes int64
	size     int64
}

// ErrNotSecured reports that the log was opened but its permissions could not
// be restricted. The log is usable; it is just readable by more accounts than
// intended, which is worth telling the user about rather than dying over.
var ErrNotSecured = errors.New("session log permissions could not be restricted")

// newSessionID returns a short random identifier for one proxy run.
func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Only reachable if the OS entropy source is broken. A timestamp is a
		// poor identifier but better than colliding on the empty string.
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(b[:])
}

// OpenSessionDir opens a log file for this run inside dir, named so that runs
// sort chronologically.
//
// This is the form to prefer. A client runs one proxy per configured server, so
// several are alive at once, and pointing them all at a single file interleaves
// their sessions and makes rotation a race — two processes renaming the same
// file, one clobbering what the other just created. One file per run removes
// both problems, and replay reassembles the corpus from the directory.
func OpenSessionDir(dir string, maxBytes int64) (*SessionLog, error) {
	if dir == "" {
		return nil, nil
	}
	sid := newSessionID()
	name := time.Now().UTC().Format("20060102T150405Z") + "-" + sid + ".jsonl"
	return openSessionLog(filepath.Join(dir, name), maxBytes, sid)
}

// OpenSessionLog opens (creating or appending to) a single log file at path.
// An empty path returns a nil log, which discards all records.
//
// Only one process may write to a given path: see OpenSessionDir.
//
// When the file grows past maxBytes it is renamed aside with a UTC timestamp
// and a fresh one is started; maxBytes <= 0 disables rotation.
//
// The file is opened 0600, but note that on Windows Go's permission bits are
// effectively ignored, so the ACL is set explicitly. See README.
func OpenSessionLog(path string, maxBytes int64) (*SessionLog, error) {
	return openSessionLog(path, maxBytes, newSessionID())
}

func openSessionLog(path string, maxBytes int64, sid string) (*SessionLog, error) {
	if path == "" {
		return nil, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("session log: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("session log: %w", err)
	}
	l := &SessionLog{w: f, path: path, maxBytes: maxBytes, sid: sid}
	if fi, err := f.Stat(); err == nil {
		l.size = fi.Size()
	}
	if secErr := secureFile(path); secErr != nil {
		return l, fmt.Errorf("%w: %v", ErrNotSecured, secErr)
	}
	return l, nil
}

// SessionID identifies this proxy run in the log.
func (l *SessionLog) SessionID() string {
	if l == nil {
		return ""
	}
	return l.sid
}

// NewSessionLog wraps an arbitrary writer. Rotation is disabled. Used by tests.
func NewSessionLog(w io.WriteCloser) *SessionLog { return &SessionLog{w: w} }

// Record appends one relayed message.
func (l *SessionLog) Record(dir string, line []byte) {
	if l == nil {
		return
	}
	msg := bytes.TrimRight(line, "\r\n")
	if len(msg) == 0 {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++

	var b bytes.Buffer
	fmt.Fprintf(&b, `{"seq":%d,"sid":%q,"t":%q,"dir":%q,`, l.seq, l.sid, now(), dir)
	if json.Valid(msg) {
		b.WriteString(`"msg":`)
		b.Write(msg)
	} else {
		// Servers do occasionally write non-JSON to stdout (a stray npm
		// warning, a panic trace). Keep it, but as a string, so the log as a
		// whole stays machine-readable.
		b.WriteString(`"raw":`)
		enc, err := json.Marshal(string(msg))
		if err != nil {
			enc = []byte(`"<unencodable>"`)
		}
		b.Write(enc)
	}
	b.WriteString("}\n")
	l.write(b.Bytes())
}

// Event appends a proxy-level record (start, exit, later: policy verdicts).
func (l *SessionLog) Event(name string, fields map[string]any) {
	if l == nil {
		return
	}
	rec := map[string]any{"ev": name}
	for k, v := range fields {
		rec[k] = v
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	rec["seq"] = l.seq
	rec["sid"] = l.sid
	rec["t"] = now()
	enc, err := json.Marshal(rec)
	if err != nil {
		return
	}
	l.write(append(enc, '\n'))
}

// Close flushes and closes the underlying file.
func (l *SessionLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Close()
}

// write appends one complete line, rotating first if it would push the file
// past maxBytes. Records are never split across files. Caller holds mu.
func (l *SessionLog) write(b []byte) {
	if l.maxBytes > 0 && l.size > 0 && l.size+int64(len(b)) > l.maxBytes {
		l.rotate()
	}
	n, _ := l.w.Write(b)
	l.size += int64(n)
}

// rotate moves the current log aside and starts a fresh one. Caller holds mu.
//
// Every failure path here prefers "keep writing" over "stop writing": the
// corpus is the whole point of stage 0 and cannot be recreated, whereas an
// oversized file is merely annoying.
func (l *SessionLog) rotate() {
	_ = l.w.Close()

	ext := filepath.Ext(l.path)
	base := strings.TrimSuffix(l.path, ext) + "-" + time.Now().UTC().Format("20060102T150405Z")

	// The stamp has one-second resolution, so two rotations can land on the
	// same name. That must not be left to os.Rename: on Windows it fails, and
	// on Unix it silently overwrites the older file, which quietly destroys
	// part of the corpus.
	rotated := base + ext
	for i := 1; i <= 100; i++ {
		if _, err := os.Stat(rotated); os.IsNotExist(err) {
			break
		}
		rotated = fmt.Sprintf("%s.%d%s", base, i, ext)
	}

	if err := os.Rename(l.path, rotated); err != nil {
		// Could not move it aside — most likely another process holds it, or
		// the timestamped name already exists. Give up on rotation for the
		// rest of this run rather than retrying on every single write.
		l.maxBytes = 0
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		// We just closed the only writer we had and cannot get another. Drop
		// records silently rather than take the proxy down with us: the client
		// is mid-session and breaking it is worse than losing the log.
		l.w = discardCloser{}
		l.size = 0
		l.maxBytes = 0
		return
	}
	l.w = f
	l.size = 0
	if fi, err := f.Stat(); err == nil {
		l.size = fi.Size()
	}
	// The fresh file inherits the directory ACL again, so it has to be
	// re-restricted. Nothing to do on failure but keep going: the alternative
	// is dropping the corpus.
	_ = secureFile(l.path)
}

type discardCloser struct{}

func (discardCloser) Write(p []byte) (int, error) { return len(p), nil }
func (discardCloser) Close() error                { return nil }

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
