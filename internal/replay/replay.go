// Package replay turns a recorded session log back into something a human can
// read. It is deliberately offline: no server is started, nothing is contacted,
// and the same .jsonl always produces the same transcript.
package replay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
)

// maxLine is the largest log line we will read. Tool results run to megabytes,
// and a session log line holds one whole message.
const maxLine = 64 << 20

type record struct {
	Seq uint64          `json:"seq"`
	SID string          `json:"sid"`
	T   string          `json:"t"`
	Dir string          `json:"dir"`
	Ev  string          `json:"ev"`
	Msg json.RawMessage `json:"msg"`
	Raw string          `json:"raw"`
}

// section is one proxy run within the log.
type section struct {
	corr   *mcp.Correlator
	sess   *mcp.Session
	sent   map[string]time.Time // correlation key -> when the request went out
	labels map[string]string    // correlation key -> method, for the reply line
}

func newSection() *section {
	return &section{
		// No expiry: a recorded session is finite and we want to see the
		// requests that never got an answer, not quietly forget them.
		corr:   mcp.NewCorrelator(0),
		sess:   mcp.NewSession(),
		sent:   make(map[string]time.Time),
		labels: make(map[string]string),
	}
}

// Path replays a single log file, or every log in a directory in chronological
// order. A directory is the normal case: one file per proxy run.
func Path(w io.Writer, path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return File(w, path)
	}

	logs, err := filepath.Glob(filepath.Join(path, "*.jsonl"))
	if err != nil {
		return err
	}
	if len(logs) == 0 {
		return fmt.Errorf("replay: no .jsonl logs in %s", path)
	}
	// File names start with a UTC stamp, so lexical order is chronological.
	sort.Strings(logs)
	for i, log := range logs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "== %s\n", filepath.Base(log))
		if err := File(w, log); err != nil {
			return err
		}
	}
	return nil
}

// File replays the log at path.
func File(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return Read(w, f)
}

// Read replays a log stream.
func Read(w io.Writer, r io.Reader) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), maxLine)

	var (
		cur    *section
		curSID string
		line   int
		first  = true
	)

	for sc.Scan() {
		line++
		var rec record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			fmt.Fprintf(w, "line %d: not valid JSONL: %v\n", line, err)
			continue
		}

		// A run boundary is either a new session id or a start event, so logs
		// recorded before session ids existed still split correctly.
		if cur == nil || (rec.SID != "" && rec.SID != curSID) || rec.Ev == "start" {
			if !first {
				printSummary(w, cur)
				fmt.Fprintln(w)
			}
			first = false
			cur, curSID = newSection(), rec.SID
			printHeader(w, sc.Bytes(), rec)
			if rec.Ev == "start" {
				continue
			}
		}

		switch {
		case rec.Ev == "exit":
			printEvent(w, sc.Bytes(), rec)
		case rec.Ev != "":
			printEvent(w, sc.Bytes(), rec)
		case rec.Raw != "":
			fmt.Fprintf(w, "  %s  %s\n", arrow(rec.Dir), truncate(rec.Raw, 100))
		case len(rec.Msg) > 0:
			printMessage(w, cur, rec)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("replay: %w", err)
	}
	if cur != nil {
		printSummary(w, cur)
	}
	return nil
}

func printHeader(w io.Writer, raw []byte, rec record) {
	sid := rec.SID
	if sid == "" {
		sid = "(no session id: recorded before they existed)"
	}
	fmt.Fprintf(w, "session %s  %s\n", sid, rec.T)

	var start struct {
		Argv []string `json:"argv"`
		PID  int      `json:"pid"`
	}
	if json.Unmarshal(raw, &start) == nil && len(start.Argv) > 0 {
		fmt.Fprintf(w, "  server: %s  (pid %d)\n", strings.Join(start.Argv, " "), start.PID)
	}
}

func printMessage(w io.Writer, s *section, rec record) {
	msgs, batched, err := mcp.ParseFrame(rec.Msg)
	if err != nil {
		fmt.Fprintf(w, "  %s  <unparseable: %v>\n", arrow(rec.Dir), err)
		return
	}
	dir := mcp.Direction(rec.Dir)
	at := parseTime(rec.T)

	for _, m := range msgs {
		prefix := "  " + arrow(rec.Dir) + "  "
		if batched {
			prefix = "  " + arrow(rec.Dir) + " *"
		}
		switch m.Kind {
		case mcp.KindRequest:
			key := string(dir) + "\x00" + m.ID.Key()
			s.corr.Track(dir, m)
			s.sent[key] = at
			s.labels[key] = m.Method
			fmt.Fprintf(w, "%s%s  id=%s%s\n", prefix, m.Method, m.ID, callDetail(m))
			s.sess.Observe(dir, m, nil)

		case mcp.KindNotification:
			fmt.Fprintf(w, "%s%s\n", prefix, m.Method)
			s.sess.Observe(dir, m, nil)

		case mcp.KindResponse, mcp.KindError:
			p, ok := s.corr.Match(dir, m)
			key := string(dir.Opposite()) + "\x00" + m.ID.Key()
			label := s.labels[key]
			if !ok {
				label = "?"
			}
			var took string
			if sentAt, seen := s.sent[key]; seen && !at.IsZero() && !sentAt.IsZero() {
				took = fmt.Sprintf("  %s", at.Sub(sentAt).Round(time.Millisecond))
			}
			verdict := "result"
			if m.Kind == mcp.KindError {
				verdict = fmt.Sprintf("error %d %q", m.Error.Code, m.Error.Message)
			}
			fmt.Fprintf(w, "%s%s <- %s  id=%s%s\n", prefix, verdict, label, m.ID, took)
			if ok {
				s.sess.Observe(dir, m, &p)
			} else {
				s.sess.Observe(dir, m, nil)
			}
		}
	}
}

// callDetail names the tool a tools/call is aimed at, which is the single most
// useful thing to see when skimming a transcript.
func callDetail(m mcp.Message) string {
	if m.Method != "tools/call" {
		return ""
	}
	var p struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(m.Params, &p) != nil || p.Name == "" {
		return ""
	}
	return "  tool=" + p.Name
}

func printEvent(w io.Writer, raw []byte, rec record) {
	var fields map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Without this every number decodes to float64 and prints in scientific
	// notation: the Windows kill code 1073807364 comes out as 1.073807364e+09.
	dec.UseNumber()
	if dec.Decode(&fields) != nil {
		fmt.Fprintf(w, "  [%s]\n", rec.Ev)
		return
	}
	for _, k := range []string{"seq", "sid", "t", "ev", "argv", "pid"} {
		delete(fields, k)
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%v", k, fields[k])
	}
	fmt.Fprintf(w, "  [%s]%s\n", rec.Ev, b.String())
}

func printSummary(w io.Writer, s *section) {
	if s == nil {
		return
	}
	client, server := s.sess.Peers()
	calls := s.sess.Calls()

	var failed, unfinished int
	byTool := map[string]int{}
	for _, c := range calls {
		byTool[c.Tool]++
		if c.IsError {
			failed++
		}
		if !c.Done {
			unfinished++
		}
	}

	fmt.Fprintf(w, "  --\n")
	if v := s.sess.ProtocolVersion(); v != "" {
		fmt.Fprintf(w, "  protocol %s   client %s   server %s\n", v, name(client), name(server))
	}
	fmt.Fprintf(w, "  %d tools advertised, %d calls", len(s.sess.Tools()), len(calls))
	if failed > 0 {
		fmt.Fprintf(w, ", %d failed", failed)
	}
	if unfinished > 0 {
		fmt.Fprintf(w, ", %d never answered", unfinished)
	}
	if n := s.corr.InFlight(); n > 0 {
		fmt.Fprintf(w, ", %d requests left in flight", n)
	}
	fmt.Fprintln(w)

	if len(byTool) > 0 {
		tools := make([]string, 0, len(byTool))
		for t := range byTool {
			tools = append(tools, t)
		}
		sort.Slice(tools, func(i, j int) bool {
			if byTool[tools[i]] != byTool[tools[j]] {
				return byTool[tools[i]] > byTool[tools[j]]
			}
			return tools[i] < tools[j]
		})
		for _, t := range tools {
			fmt.Fprintf(w, "    %-28s %d\n", t, byTool[t])
		}
	}
}

func name(p mcp.Party) string {
	if p.Name == "" {
		return "?"
	}
	if p.Version == "" {
		return p.Name
	}
	return p.Name + " " + p.Version
}

func arrow(dir string) string {
	switch mcp.Direction(dir) {
	case mcp.ClientToServer:
		return "->"
	case mcp.ServerToClient:
		return "<-"
	default:
		return "??"
	}
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
