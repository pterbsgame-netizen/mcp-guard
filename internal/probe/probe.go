// Package probe performs the smallest possible MCP handshake against a stdio
// server and reports what it advertises.
//
// This is the one place mcp-guard acts as a client rather than a pipe. It
// exists so that approving a server does not require running a real agent
// against it first.
package probe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
)

// protocolVersion is what the probe asks for. A server that does not know it
// answers with one it does, which is recorded in the result.
const protocolVersion = "2025-11-25"

const readBufSize = 1 << 20

// Result is what a server said about itself.
type Result struct {
	Protocol string
	Server   mcp.Party
	Tools    []mcp.Tool

	// Stderr is whatever the server logged. Captured rather than relayed
	// because a probe that fails usually explains itself there.
	Stderr string
}

// Run starts the server, negotiates, asks for its tools, and shuts it down.
func Run(ctx context.Context, argv, env []string, timeout time.Duration) (*Result, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("probe: empty server command")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	// os/exec copies the child's stderr on a goroutine of its own, which runs
	// until the process is reaped. A plain bytes.Buffer read while that is
	// still going is a data race, and every path out of this function reads it.
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("probe: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("probe: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("probe: cannot start %q: %w", argv[0], err)
	}

	s := &session{cmd: cmd, in: stdin, lines: make(chan []byte), fail: make(chan error, 1)}
	go s.read(ctx, stdout)
	defer s.close()

	res := &Result{}
	initResult, err := s.call(ctx, 1, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcp-guard", "version": "0"},
	})
	if err != nil {
		res.Stderr = stderr.String()
		return res, err
	}
	var initBody struct {
		ProtocolVersion string    `json:"protocolVersion"`
		ServerInfo      mcp.Party `json:"serverInfo"`
	}
	if err := json.Unmarshal(initResult, &initBody); err != nil {
		return nil, fmt.Errorf("probe: initialize result: %w", err)
	}
	res.Protocol, res.Server = initBody.ProtocolVersion, initBody.ServerInfo

	if err := s.notify("notifications/initialized", map[string]any{}); err != nil {
		return nil, err
	}

	toolsResult, err := s.call(ctx, 2, "tools/list", map[string]any{})
	if err != nil {
		res.Stderr = stderr.String()
		return res, err
	}
	var toolsBody struct {
		Tools []mcp.Tool `json:"tools"`
	}
	if err := json.Unmarshal(toolsResult, &toolsBody); err != nil {
		return nil, fmt.Errorf("probe: tools/list result: %w", err)
	}
	res.Tools = toolsBody.Tools
	res.Stderr = stderr.String()
	return res, nil
}

type session struct {
	cmd   *exec.Cmd
	in    interface{ Write([]byte) (int, error) }
	lines chan []byte
	fail  chan error
}

func (s *session) read(ctx context.Context, stdout interface{ Read([]byte) (int, error) }) {
	r := bufio.NewReaderSize(stdout, readBufSize)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			select {
			case s.lines <- line:
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			select {
			case s.fail <- err:
			case <-ctx.Done():
			}
			return
		}
	}
}

func (s *session) send(v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("probe: %w", err)
	}
	if _, err := s.in.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("probe: write: %w", err)
	}
	return nil
}

func (s *session) notify(method string, params any) error {
	return s.send(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
}

// call sends a request and waits for the matching response.
//
// Anything else arriving meanwhile is handled rather than ignored: a server may
// send a request of its own, and leaving it unanswered would leave both sides
// waiting for each other until the probe times out.
func (s *session) call(ctx context.Context, id int, method string, params any) (json.RawMessage, error) {
	if err := s.send(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	}); err != nil {
		return nil, err
	}

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("probe: timed out waiting for %s", method)
		case err := <-s.fail:
			return nil, fmt.Errorf("probe: server closed its output during %s: %w", method, err)
		case line := <-s.lines:
			msgs, _, err := mcp.ParseFrame(line)
			if err != nil {
				// Servers do print noise on stdout; it is not our business.
				continue
			}
			for _, m := range msgs {
				switch m.Kind {
				case mcp.KindResponse:
					if m.ID.String() == fmt.Sprint(id) {
						return m.Result, nil
					}
				case mcp.KindError:
					if m.ID.String() == fmt.Sprint(id) {
						return nil, fmt.Errorf("probe: %s failed: %s (code %d)", method, m.Error.Message, m.Error.Code)
					}
				case mcp.KindRequest:
					// We advertise no capabilities, so anything the server asks
					// for is something we cannot provide. Say so, promptly.
					reply, err := mcp.NewError(m.ID, mcp.CodeMethodNotFound,
						"mcp-guard probe supports no client capabilities")
					if err == nil {
						_, _ = s.in.Write(reply)
					}
				}
			}
		}
	}
}

// close shuts the server down: EOF on stdin first, then force.
//
// cmd.Wait, not Process.Wait: the former also waits for os/exec's own copying
// goroutines to finish, and the latter leaves them running against buffers the
// caller is about to read.
func (s *session) close() {
	if c, ok := s.in.(interface{ Close() error }); ok {
		_ = c.Close()
	}
	done := make(chan struct{})
	go func() { _ = s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = s.cmd.Process.Kill()
		<-done
	}
}

// lockedBuffer is a bytes.Buffer that can be read while it is being written.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}
