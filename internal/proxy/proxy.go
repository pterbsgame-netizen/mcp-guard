// Package proxy implements the MCP stdio proxy: it starts the real MCP server
// as a child process and relays newline-delimited JSON-RPC between the client
// and the server without touching a single byte, recording the session and
// tracking protocol state as it goes.
//
// Through stage 1 it still blocks nothing. Parsing happens beside the traffic,
// never in its way: a frame the parser cannot understand is relayed anyway.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/detect"
	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
	"github.com/pterbsgame-netizen/mcp-guard/internal/pin"
	"github.com/pterbsgame-netizen/mcp-guard/internal/policy"
)

// Direction labels recorded in the session log.
const (
	DirClientToServer = string(mcp.ClientToServer)
	DirServerToClient = string(mcp.ServerToClient)
)

// readBufSize is the initial per-direction read buffer. Messages larger than
// this still work — bufio.Reader.ReadBytes grows as needed — this only avoids
// repeated reallocation on the common case of big tool results.
const readBufSize = 1 << 20

// Options configures a single proxied server session.
type Options struct {
	// Argv is the real MCP server command and its arguments, e.g.
	// {"npx", "-y", "@modelcontextprotocol/server-filesystem", "C:\\tmp"}.
	Argv []string

	// Env is the child's environment. nil means "inherit ours".
	// Stage 3 will filter this (drop AWS_*, GITHUB_TOKEN, *_API_KEY unless the
	// policy allows them); stage 1 just passes it through.
	Env []string

	// Log receives every message in both directions. nil disables logging.
	Log *SessionLog

	// Grace is how long the server gets at each shutdown step before we
	// escalate: wait -> terminate -> kill.
	Grace time.Duration

	// CallTTL is how long an unanswered request is remembered before it is
	// written off. SweepEvery is how often that check runs.
	CallTTL    time.Duration
	SweepEvery time.Duration

	// Lock, when set, is the approved state to check the server against.
	Lock *pin.Lock

	// Policy, when set, decides what tool calls are allowed to do.
	Policy *policy.Policy

	// Detect, when set, scores tool results for instruction-shaped content.
	// It never blocks: a high score only raises the taint level, which makes
	// the policy stricter about effects.
	Detect *detect.Ruleset

	// Enforce turns a mismatch into a refused call. The default is to record
	// it and let it through: a tool that breaks someone's workflow the day it
	// is installed gets uninstalled the day it is installed.
	Enforce bool

	// Stdin/Stdout/Stderr default to the process's own. Overridden in tests.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (o *Options) setDefaults() {
	if o.Grace <= 0 {
		o.Grace = 5 * time.Second
	}
	if o.CallTTL <= 0 {
		o.CallTTL = 5 * time.Minute
	}
	if o.SweepEvery <= 0 {
		o.SweepEvery = 30 * time.Second
	}
	if o.Stdin == nil {
		o.Stdin = os.Stdin
	}
	if o.Stdout == nil {
		o.Stdout = os.Stdout
	}
	if o.Stderr == nil {
		o.Stderr = os.Stderr
	}
}

// Result is what the proxy learned about the connection it just carried.
type Result struct {
	ExitCode int
	Session  *mcp.Session
}

// Run starts the server and relays until either side goes away. The returned
// exit code is the server's, and the caller should exit with it: to the client
// we must be indistinguishable from the server itself.
func Run(ctx context.Context, o Options) (Result, error) {
	if len(o.Argv) == 0 {
		return Result{ExitCode: 2}, errors.New("proxy: empty server command")
	}
	o.setDefaults()

	session := mcp.NewSession()
	corr := mcp.NewCorrelator(o.CallTTL)
	res := Result{ExitCode: 1, Session: session}

	cmd := exec.Command(o.Argv[0], o.Argv[1:]...)
	cmd.Env = o.Env
	// stderr is relayed 1:1 and never captured or parsed. MCP servers log
	// there and clients surface it to the user; swallowing it turns every
	// server-side error into "it just doesn't work".
	cmd.Stderr = o.Stderr

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return res, fmt.Errorf("proxy: stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return res, fmt.Errorf("proxy: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		res.ExitCode = 127
		return res, fmt.Errorf("proxy: cannot start %q: %w", o.Argv[0], err)
	}
	o.Log.Event("start", map[string]any{"argv": o.Argv, "pid": cmd.Process.Pid})

	g := newGuard(&o)
	observe := o.observer(session, corr, g)
	// Everything the client receives goes through one writer, from either
	// goroutine, so messages cannot interleave.
	toClient := &syncWriter{w: o.Stdout}

	// server -> client
	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		o.pump(mcp.ServerToClient, serverOut, toClient, nil, nil, observe)
	}()

	// client -> server.
	//
	// This goroutine is deliberately never joined. A Read blocked on os.Stdin
	// cannot be cancelled or interrupted in Go, so waiting for it would hang
	// shutdown forever whenever the server dies first. We let it outlive Run
	// and die with the process.
	go func() {
		o.pump(mcp.ClientToServer, o.Stdin, serverIn, g.gate, toClient, observe)
		// The client closed its end: propagate the EOF so a well-behaved
		// server can shut itself down instead of being killed.
		_ = serverIn.Close()
	}()

	sweepDone := o.startSweeper(corr)
	defer close(sweepDone)

	waitc := make(chan error, 1)
	go func() { waitc <- cmd.Wait() }()

	select {
	case <-s2cDone:
		// Server closed stdout: it is already on its way out, just reap it.
	case <-ctx.Done():
		// We were interrupted. Ask the server to stop by closing its stdin.
		_ = serverIn.Close()
	}

	code, err := reap(cmd, waitc, o.Grace)
	res.ExitCode = code

	client, server := session.Peers()
	o.Log.Event("exit", map[string]any{
		"code":      code,
		"protocol":  session.ProtocolVersion(),
		"client":    client.Name,
		"server":    server.Name,
		"tools":     len(session.Tools()),
		"calls":     len(session.Calls()),
		"in_flight": corr.InFlight(),
	})
	return res, err
}

// startSweeper expires unanswered requests in the background. Without it the
// correlator grows for the whole session every time a server drops a reply.
func (o *Options) startSweeper(corr *mcp.Correlator) chan struct{} {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(o.SweepEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				for _, p := range corr.Expire() {
					o.Log.Event("unanswered", map[string]any{
						"dir":    string(p.Dir),
						"id":     p.ID.String(),
						"method": p.Method,
						"age_s":  time.Since(p.Sent).Seconds(),
					})
				}
			case <-done:
				return
			}
		}
	}()
	return done
}

// observer returns the callback pump uses to fold each frame into the session.
//
// Everything it notices is recorded as an event, never acted on. Anomalies are
// worth seeing — an orphaned response or a reused id says something is wrong —
// but stage 1 does not get to have an opinion about traffic.
func (o *Options) observer(session *mcp.Session, corr *mcp.Correlator, g *guard) func(mcp.Direction, []byte) {
	return func(dir mcp.Direction, frame []byte) {
		msgs, _, err := mcp.ParseFrame(frame)
		if err != nil {
			o.Log.Event("unparseable", map[string]any{
				"dir": string(dir),
				"err": err.Error(),
			})
			return
		}
		for _, m := range msgs {
			switch m.Kind {
			case mcp.KindRequest:
				if displaced, collision := corr.Track(dir, m); collision {
					o.Log.Event("id-reuse", map[string]any{
						"dir":       string(dir),
						"id":        m.ID.String(),
						"method":    m.Method,
						"displaced": displaced.Method,
					})
				}
				session.Observe(dir, m, nil)

			case mcp.KindResponse, mcp.KindError:
				p, ok := corr.Match(dir, m)
				if !ok {
					o.Log.Event("orphan-response", map[string]any{
						"dir": string(dir),
						"id":  m.ID.String(),
					})
					session.Observe(dir, m, nil)
					continue
				}
				session.Observe(dir, m, &p)
				g.answered(dir, m)
				if p.Method == "tools/list" {
					// The advertised set just changed or was stated for the
					// first time; this is the only moment we can check it.
					g.verifyTools(session)
				}

			default:
				session.Observe(dir, m, nil)
			}
		}
	}
}

// reap waits for the child, escalating politeness in steps of Grace:
// plain wait, then terminate, then kill.
func reap(cmd *exec.Cmd, waitc <-chan error, grace time.Duration) (int, error) {
	steps := []func(){
		func() {},                         // just wait: stdin EOF is usually enough
		func() { terminate(cmd.Process) }, // SIGTERM (see the per-OS files)
		func() { _ = cmd.Process.Kill() },
	}
	for _, step := range steps {
		step()
		select {
		case err := <-waitc:
			return exitCode(err)
		case <-time.After(grace):
		}
	}
	// Killed and still not reaped: the child is stuck in uninterruptible state.
	return 1, errors.New("proxy: server did not exit after kill")
}

// exitCode turns cmd.Wait's error into a status code. A non-zero exit is the
// server's business, not our error, so it is reported with a nil error.
func exitCode(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if c := ee.ExitCode(); c >= 0 {
			return c, nil
		}
		return 1, nil // terminated by a signal; ExitCode reports -1
	}
	return 1, err
}

// pump copies newline-delimited JSON-RPC messages from src to dst, logging each
// one and handing it to observe. The bytes themselves are never modified, and
// observation never gates the copy: relaying comes first.
// deny, when set, inspects each frame before it is forwarded and may return a
// reply to send back to the sender instead; back is where that reply goes.
func (o *Options) pump(dir mcp.Direction, src io.Reader, dst io.Writer, deny func([]byte) []byte, back io.Writer, observe func(mcp.Direction, []byte)) {
	r := bufio.NewReaderSize(src, readBufSize)
	for {
		// NOT bufio.Scanner: its 64 KiB default silently truncates large tool
		// results, and the symptom looks like "the server died for no reason".
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			o.Log.Record(string(dir), line)

			refused := false
			if deny != nil {
				if reply := deny(line); reply != nil {
					// Refused: the server never sees this, and the sender gets
					// an answer rather than silence.
					if _, werr := back.Write(reply); werr != nil {
						return
					}
					refused = true
				}
			}
			if !refused {
				// Observation runs before the message is forwarded, not after.
				// Verification has to finish before the peer can act on what it
				// is about to learn: a client that pipelines a tools/call right
				// behind tools/list would otherwise outrun the check meant to
				// refuse it. Parsing costs microseconds; the race costs the
				// whole guarantee.
				observe(dir, line)

				if _, werr := dst.Write(line); werr != nil {
					return
				}
				// No flush on purpose. dst is an *os.File (or a pipe to one),
				// so every Write is already a syscall. Wrapping it in a
				// bufio.Writer is how you get "the client hangs for 30s".
			}
		}
		if err != nil {
			return
		}
	}
}
