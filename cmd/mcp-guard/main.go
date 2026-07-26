// Command mcp-guard wraps an MCP stdio server: the client launches mcp-guard,
// mcp-guard launches the real server, and everything between them is relayed
// unchanged and recorded.
//
// Stage 0 blocks nothing. It is a tap, not a guard, despite the name.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/proxy"
)

const usage = `mcp-guard - a recording pass-through for MCP stdio servers.

usage:
  mcp-guard [flags] -- <server-command> [server-args...]

example:
  mcp-guard -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\tmp

flags:
`

func main() {
	logPath := flag.String("log", defaultLogPath(), `session log path (JSONL); "" disables logging`)
	grace := flag.Duration("grace", 5*time.Second, "per-step grace period when shutting the server down")
	maxLog := flag.Int64("log-max-bytes", proxy.DefaultMaxLogBytes, "rotate the session log past this size; 0 disables rotation")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	argv := flag.Args()
	if len(argv) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	log, err := proxy.OpenSessionLog(*logPath, *maxLog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		os.Exit(1)
	}

	// The client owns our lifecycle through stdin; a signal is the fallback.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	code, runErr := proxy.Run(ctx, proxy.Options{
		Argv:  argv,
		Log:   log,
		Grace: *grace,
	})
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", runErr)
	}
	// Not deferred: os.Exit skips defers.
	if err := log.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: closing log: %v\n", err)
	}
	// Exit with the server's code: to the client we must look like the server.
	os.Exit(code)
}

func defaultLogPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "mcp-guard-session.jsonl"
	}
	return filepath.Join(home, ".mcp-guard", "session.jsonl")
}
