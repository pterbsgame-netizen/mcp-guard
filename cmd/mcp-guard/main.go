// Command mcp-guard wraps an MCP stdio server: the client launches mcp-guard,
// mcp-guard launches the real server, and everything between them is relayed
// unchanged and recorded.
//
// Through stage 1 it blocks nothing. It is a tap, not a guard, despite the name.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/proxy"
	"github.com/pterbsgame-netizen/mcp-guard/internal/replay"
)

const usage = `mcp-guard - a recording pass-through for MCP stdio servers.

usage:
  mcp-guard [flags] -- <server-command> [server-args...]
  mcp-guard replay [session.jsonl | log-dir]

examples:
  mcp-guard -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\tmp
  mcp-guard replay

flags:
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "replay" {
		os.Exit(runReplay(os.Args[2:]))
	}
	os.Exit(runProxy())
}

func runReplay(args []string) int {
	path := defaultLogDir()
	if len(args) == 1 {
		path = args[0]
	} else if len(args) > 1 {
		fmt.Fprintln(os.Stderr, "usage: mcp-guard replay [session.jsonl | log-dir]")
		return 2
	}
	// Buffered: a replayed session is thousands of small writes, and on a
	// terminal each unbuffered one is a syscall.
	out := bufio.NewWriter(os.Stdout)
	err := replay.Path(out, path)
	if flushErr := out.Flush(); err == nil {
		err = flushErr
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The common first run: nothing has been recorded yet. The raw
		// GetFileAttributesEx error tells the user nothing useful.
		fmt.Fprintf(os.Stderr, "mcp-guard: no sessions recorded at %s yet.\n", path)
		fmt.Fprintln(os.Stderr, "  Wire mcp-guard into your MCP client and use it once, then try again.")
		return 1
	case err != nil:
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}
	return 0
}

func runProxy() int {
	logDir := flag.String("log-dir", defaultLogDir(), `directory for per-run session logs; "" disables logging`)
	logPath := flag.String("log", "", `write to this single file instead of --log-dir; only safe with one proxy process`)
	grace := flag.Duration("grace", 5*time.Second, "per-step grace period when shutting the server down")
	maxLog := flag.Int64("log-max-bytes", proxy.DefaultMaxLogBytes, "rotate the session log past this size; 0 disables rotation")
	callTTL := flag.Duration("call-ttl", 5*time.Minute, "how long an unanswered request is remembered before it is written off")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	argv := flag.Args()
	if len(argv) == 0 {
		flag.Usage()
		return 2
	}

	open := func() (*proxy.SessionLog, error) {
		if *logPath != "" {
			return proxy.OpenSessionLog(*logPath, *maxLog)
		}
		return proxy.OpenSessionDir(*logDir, *maxLog)
	}
	log, err := open()
	switch {
	case errors.Is(err, proxy.ErrNotSecured):
		// Worth saying out loud — the log holds every tool result verbatim —
		// but not worth refusing to start and breaking the client's server.
		fmt.Fprintf(os.Stderr, "mcp-guard: warning: %v\n", err)
	case err != nil:
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}

	// The client owns our lifecycle through stdin; a signal is the fallback.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	res, runErr := proxy.Run(ctx, proxy.Options{
		Argv:    argv,
		Log:     log,
		Grace:   *grace,
		CallTTL: *callTTL,
	})
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", runErr)
	}
	if err := log.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: closing log: %v\n", err)
	}
	// Exit with the server's code: to the client we must look like the server.
	return res.ExitCode
}

func defaultLogDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "mcp-guard-sessions"
	}
	return filepath.Join(home, ".mcp-guard", "sessions")
}
