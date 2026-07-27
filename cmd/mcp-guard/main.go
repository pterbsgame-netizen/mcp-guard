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
	"strings"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/cfg"
	"github.com/pterbsgame-netizen/mcp-guard/internal/pin"
	"github.com/pterbsgame-netizen/mcp-guard/internal/probe"
	"github.com/pterbsgame-netizen/mcp-guard/internal/proxy"
	"github.com/pterbsgame-netizen/mcp-guard/internal/replay"
)

const usage = `mcp-guard - a recording pass-through for MCP stdio servers.

usage:
  mcp-guard [flags] -- <server-command> [server-args...]
  mcp-guard approve [flags] -- <server-command> [server-args...]
  mcp-guard replay [session.jsonl | log-dir]
  mcp-guard verify [--write] [config-file...]
  mcp-guard watch [config-file...]

examples:
  mcp-guard -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\tmp
  mcp-guard replay

flags:
`

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "replay":
			os.Exit(runReplay(os.Args[2:]))
		case "approve":
			os.Exit(runApprove(os.Args[2:]))
		case "verify":
			os.Exit(runVerify(os.Args[2:]))
		case "watch":
			os.Exit(runWatch(os.Args[2:]))
		}
	}
	os.Exit(runProxy())
}

const configUsage = `mcp-guard %s - guard the client configs that decide which MCP servers run.

usage:
  mcp-guard verify [flags] [config-file...]
  mcp-guard watch  [flags] [config-file...]

With no files given, the known client configs on this machine are used.

Record the current state first, then check against it:

  mcp-guard verify --write
  mcp-guard verify
  mcp-guard watch

Only the MCP server declarations are recorded, never whole files: clients keep
caches and window positions in the same files and rewrite them constantly.
Environment variable and header names are covered, their values never are - the
baseline belongs in a repository.

flags:
`

// configFlags is shared by verify and watch.
func configFlags(name string) (*flag.FlagSet, *string) {
	fset := flag.NewFlagSet(name, flag.ContinueOnError)
	baseline := fset.String("baseline", cfg.DefaultBaselineName,
		"approved config state; keep it in a repository, not beside the configs it guards")
	fset.Usage = func() {
		fmt.Fprintf(os.Stderr, configUsage, name)
		fset.PrintDefaults()
	}
	return fset, baseline
}

func runVerify(args []string) int {
	fset, baselinePath := configFlags("verify")
	write := fset.Bool("write", false, "record the current state as approved instead of checking against it")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	paths := fset.Args()
	if len(paths) == 0 {
		paths = cfg.Discover()
	}
	if len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "mcp-guard: no client configs found; name them explicitly")
		return 1
	}

	current, err := cfg.Snapshot(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}

	if *write {
		if err := current.Save(*baselinePath); err != nil {
			fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
			return 1
		}
		var servers int
		for _, f := range current.Files {
			servers += len(f.Servers)
		}
		fmt.Fprintf(os.Stderr, "recorded %d server(s) across %d config(s) into %s\n",
			servers, len(current.Files), *baselinePath)
		return 0
	}

	approved, err := cfg.LoadBaseline(*baselinePath)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "mcp-guard: no baseline at %s. Record one with:\n  mcp-guard verify --write\n", *baselinePath)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}

	changes := cfg.Diff(approved, current)
	cfg.Report(os.Stdout, changes)
	if len(changes) > 0 {
		return 1
	}
	return 0
}

func runWatch(args []string) int {
	fset, baselinePath := configFlags("watch")
	if err := fset.Parse(args); err != nil {
		return 2
	}

	approved, err := cfg.LoadBaseline(*baselinePath)
	if errors.Is(err, fs.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "mcp-guard: no baseline at %s. Record one with:\n  mcp-guard verify --write\n", *baselinePath)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}

	paths := fset.Args()
	if len(paths) == 0 {
		// Watch what was approved, plus anything that exists now: a config
		// that appeared since approval is itself worth reporting.
		paths = union(approved.Paths(), cfg.Discover())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	fmt.Fprintf(os.Stderr, "watching %d config(s) against %s; Ctrl+C to stop\n", len(paths), *baselinePath)
	err = cfg.Watch(ctx, approved, paths, func(changes []cfg.Change) {
		fmt.Fprintf(os.Stdout, "\n%s\n", time.Now().Format(time.RFC3339))
		cfg.Report(os.Stdout, changes)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}
	return 0
}

func union(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

const approveUsage = `mcp-guard approve - record what a server advertises, so a later change is visible.

usage:
  mcp-guard approve [flags] -- <server-command> [server-args...]

  mcp-guard approve -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev
  mcp-guard approve --diff -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev

The lock file is meant to be committed alongside the project it covers, so that
a tool changing its description or widening its schema shows up in review.

flags:
`

func runApprove(args []string) int {
	fset := flag.NewFlagSet("approve", flag.ContinueOnError)
	lockPath := fset.String("lock", pin.DefaultName, "lock file to write or compare against")
	diffOnly := fset.Bool("diff", false, "report what changed and exit non-zero, without writing")
	timeout := fset.Duration("timeout", 60*time.Second, "how long to wait for the server to answer")
	pinEnv := fset.String("pin-env", "", "comma-separated environment variable names to record (names only, never values)")
	fset.Usage = func() {
		fmt.Fprint(os.Stderr, approveUsage)
		fset.PrintDefaults()
	}
	if err := fset.Parse(args); err != nil {
		return 2
	}
	argv := fset.Args()
	if len(argv) == 0 {
		fset.Usage()
		return 2
	}

	res, err := probe.Run(context.Background(), argv, nil, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		if res != nil && res.Stderr != "" {
			fmt.Fprintf(os.Stderr, "server said:\n%s\n", res.Stderr)
		}
		return 1
	}
	fmt.Fprintf(os.Stderr, "%s %s speaking %s, %d tools\n",
		res.Server.Name, res.Server.Version, res.Protocol, len(res.Tools))

	observed, err := pin.New(pin.Server{
		Command: argv[0],
		Args:    argv[1:],
		EnvKeys: splitList(*pinEnv),
	}, res.Tools)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}

	existing, err := pin.Load(*lockPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if *diffOnly {
			fmt.Fprintf(os.Stderr, "mcp-guard: no lock at %s to compare against\n", *lockPath)
			return 1
		}
	case err != nil:
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	default:
		changes := pin.Diff(existing, observed)
		pin.Report(os.Stdout, changes)
		if *diffOnly {
			if len(changes) > 0 {
				return 1 // so this can gate a build
			}
			return 0
		}
	}

	if *diffOnly {
		return 0
	}
	if err := observed.Save(*lockPath); err != nil {
		fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "approved %d tools into %s\n", len(observed.Tools), *lockPath)
	return 0
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
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
	lockPath := flag.String("lock", "", "check the server against this lock file (see: mcp-guard approve)")
	enforce := flag.Bool("enforce", false, "refuse calls to tools that changed since approval, instead of only recording them")
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

	var lock *pin.Lock
	if *lockPath != "" {
		lock, err = pin.Load(*lockPath)
		if err != nil {
			// A lock that cannot be read is a refusal to start: the user asked
			// for this server to be checked, and starting unchecked would be
			// worse than not starting.
			fmt.Fprintf(os.Stderr, "mcp-guard: %v\n", err)
			return 1
		}
	}

	res, runErr := proxy.Run(ctx, proxy.Options{
		Argv:    argv,
		Log:     log,
		Grace:   *grace,
		CallTTL: *callTTL,
		Lock:    lock,
		Enforce: *enforce,
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
