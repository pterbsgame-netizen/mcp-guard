// Package proxy implements the stage-0 transparent MCP stdio proxy.
//
// It starts the real MCP server as a child process and relays newline-delimited
// JSON-RPC between the client and the server without touching a single byte,
// recording the full session to a JSONL log along the way.
//
// Stage 0 contains no security logic on purpose. Nothing is inspected, nothing
// is blocked, nothing is rewritten. The only job here is to be an invisible
// piece of pipe and to start collecting the benign corpus.
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
)

// Direction labels recorded in the session log.
const (
	DirClientToServer = "c2s"
	DirServerToClient = "s2c"
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
	// policy allows them); stage 0 just passes it through.
	Env []string

	// Log receives every message in both directions. nil disables logging.
	Log *SessionLog

	// Grace is how long the server gets at each shutdown step before we
	// escalate: wait -> terminate -> kill.
	Grace time.Duration

	// Stdin/Stdout/Stderr default to the process's own. Overridden in tests.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

func (o *Options) setDefaults() {
	if o.Grace <= 0 {
		o.Grace = 5 * time.Second
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

// Run starts the server and relays until either side goes away. It returns the
// server's exit code, which the caller should exit with: to the client we must
// be indistinguishable from the server itself.
func Run(ctx context.Context, o Options) (int, error) {
	if len(o.Argv) == 0 {
		return 2, errors.New("proxy: empty server command")
	}
	o.setDefaults()

	cmd := exec.Command(o.Argv[0], o.Argv[1:]...)
	cmd.Env = o.Env
	// stderr is relayed 1:1 and never captured or parsed. MCP servers log
	// there and clients surface it to the user; swallowing it turns every
	// server-side error into "it just doesn't work".
	cmd.Stderr = o.Stderr

	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("proxy: stdin pipe: %w", err)
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return 1, fmt.Errorf("proxy: stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return 127, fmt.Errorf("proxy: cannot start %q: %w", o.Argv[0], err)
	}
	o.Log.Event("start", map[string]any{"argv": o.Argv, "pid": cmd.Process.Pid})

	// server -> client
	s2cDone := make(chan struct{})
	go func() {
		defer close(s2cDone)
		pump(DirServerToClient, serverOut, o.Stdout, o.Log)
	}()

	// client -> server.
	//
	// This goroutine is deliberately never joined. A Read blocked on os.Stdin
	// cannot be cancelled or interrupted in Go, so waiting for it would hang
	// shutdown forever whenever the server dies first. We let it outlive Run
	// and die with the process.
	go func() {
		pump(DirClientToServer, o.Stdin, serverIn, o.Log)
		// The client closed its end: propagate the EOF so a well-behaved
		// server can shut itself down instead of being killed.
		_ = serverIn.Close()
	}()

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
	o.Log.Event("exit", map[string]any{"code": code})
	return code, err
}

// reap waits for the child, escalating politeness in steps of Grace:
// plain wait, then terminate, then kill.
func reap(cmd *exec.Cmd, waitc <-chan error, grace time.Duration) (int, error) {
	steps := []func(){
		func() {},                        // just wait: stdin EOF is usually enough
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
// one. Stage 0 neither parses nor modifies anything: bytes go through as-is.
func pump(dir string, src io.Reader, dst io.Writer, log *SessionLog) {
	r := bufio.NewReaderSize(src, readBufSize)
	for {
		// NOT bufio.Scanner: its 64 KiB default silently truncates large tool
		// results, and the symptom looks like "the server died for no reason".
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			log.Record(dir, line)
			if _, werr := dst.Write(line); werr != nil {
				return
			}
			// No flush on purpose. dst is an *os.File (or a pipe to one), so
			// every Write is already a syscall. Wrapping it in a bufio.Writer
			// here is exactly how you get "the client hangs for 30 seconds".
		}
		if err != nil {
			return
		}
	}
}
