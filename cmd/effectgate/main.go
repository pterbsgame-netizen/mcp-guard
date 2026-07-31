// Command effectgate wraps an MCP stdio server: the client launches effectgate,
// effectgate launches the real server, and everything between them is relayed
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
	"runtime"
	"strings"
	"time"

	"github.com/pterbsgame-netizen/effectgate/internal/cfg"
	"github.com/pterbsgame-netizen/effectgate/internal/detect"
	"github.com/pterbsgame-netizen/effectgate/internal/eval"
	"github.com/pterbsgame-netizen/effectgate/internal/pin"
	"github.com/pterbsgame-netizen/effectgate/internal/policy"
	"github.com/pterbsgame-netizen/effectgate/internal/probe"
	"github.com/pterbsgame-netizen/effectgate/internal/proxy"
	"github.com/pterbsgame-netizen/effectgate/internal/replay"
)

const usage = `effectgate - a recording pass-through for MCP stdio servers.

usage:
  effectgate [flags] -- <server-command> [server-args...]
  effectgate install [--dry-run] [config-file...]
  effectgate uninstall [config-file...]
  effectgate approve [flags] -- <server-command> [server-args...]
  effectgate replay [session.jsonl | log-dir]
  effectgate verify [--write] [config-file...]
  effectgate watch [config-file...]
  effectgate eval [--attack dir] [--benign log-or-dir]
  effectgate version

examples:
  effectgate install --dry-run
  effectgate -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\tmp
  effectgate replay

flags:
`

// version is stamped at build time:
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/effectgate
//
// A security tool that cannot say which build it is makes every bug report a
// guess, so the default says plainly that it was not stamped rather than
// inventing a number.
var version = "dev (unstamped)"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-version":
			fmt.Printf("effectgate %s %s/%s %s\n",
				version, runtime.GOOS, runtime.GOARCH, runtime.Version())
			return
		case "replay":
			os.Exit(runReplay(os.Args[2:]))
		case "approve":
			os.Exit(runApprove(os.Args[2:]))
		case "verify":
			os.Exit(runVerify(os.Args[2:]))
		case "watch":
			os.Exit(runWatch(os.Args[2:]))
		case "eval":
			os.Exit(runEval(os.Args[2:]))
		case "install":
			os.Exit(runInstall(os.Args[2:], false))
		case "uninstall":
			os.Exit(runInstall(os.Args[2:], true))
		}
	}
	os.Exit(runProxy())
}

const evalUsage = `effectgate eval - measure the rules against corpora.

usage:
  effectgate eval [--attack dir] [--benign log-or-dir] [--policy p] [--rules r]

  effectgate eval --attack corpus/attack --benign ~/.effectgate/sessions

Recall on the attack corpus is easy to move and easy to fool yourself with. The
number that decides whether the tool survives is the false positive rate on real
traffic, and it cannot be invented - it has to come from sessions you actually
had. The benign side reports how much evidence it had, so a rate measured over
four calls is not mistaken for a rate.

flags:
`

func runEval(args []string) int {
	fset := flag.NewFlagSet("eval", flag.ContinueOnError)
	attackDir := fset.String("attack", "", "directory of attack payloads, one per file")
	benignPath := fset.String("benign", "", "recorded session log or directory of them")
	policyPath := fset.String("policy", "default", `policy for the benign side; "default" or a path`)
	rulesPath := fset.String("rules", "default", `signatures; "default" or a path`)
	exclude := fset.String("exclude", "", "comma-separated session ids or file globs to leave out of the benign side")
	excludeFile := fset.String("exclude-file", eval.DefaultExcludeFile,
		"file of exclusion patterns, one per line; missing is fine unless named explicitly")
	fset.Usage = func() { fmt.Fprint(os.Stderr, evalUsage); fset.PrintDefaults() }
	if err := fset.Parse(args); err != nil {
		return 2
	}
	if *attackDir == "" && *benignPath == "" {
		fset.Usage()
		return 2
	}

	rules := detect.Default()
	if *rulesPath != "default" {
		var err error
		if rules, err = detect.Load(*rulesPath); err != nil {
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
	}
	rulesForPolicy := policy.Default()
	if *policyPath != "default" {
		var err error
		if rulesForPolicy, err = policy.Load(*policyPath); err != nil {
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
	}

	var attack *eval.AttackReport
	if *attackDir != "" {
		a, err := eval.Attack(*attackDir, rules)
		if err != nil {
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
		attack = &a
	}
	patterns := splitList(*exclude)
	fromFile, err := eval.LoadExcludes(*excludeFile)
	switch {
	case err == nil:
		patterns = append(patterns, fromFile...)
	case errors.Is(err, fs.ErrNotExist) && *excludeFile == eval.DefaultExcludeFile:
		// The conventional file is optional; a named one that is missing is not.
	default:
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
		return 1
	}

	var benign *eval.BenignReport
	if *benignPath != "" {
		b, err := eval.Benign(*benignPath, rules, rulesForPolicy, patterns)
		if err != nil {
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
		benign = &b
	}

	eval.Report(os.Stdout, attack, benign)
	return 0
}

const configUsage = `effectgate %s - guard the client configs that decide which MCP servers run.

usage:
  effectgate verify [flags] [config-file...]
  effectgate watch  [flags] [config-file...]

With no files given, the known client configs on this machine are used.

Record the current state first, then check against it:

  effectgate verify --write
  effectgate verify
  effectgate watch

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
		fmt.Fprintln(os.Stderr, "effectgate: no client configs found; name them explicitly")
		return 1
	}

	current, err := cfg.Snapshot(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
		return 1
	}

	if *write {
		if err := current.Save(*baselinePath); err != nil {
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "effectgate: no baseline at %s. Record one with:\n  effectgate verify --write\n", *baselinePath)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "effectgate: no baseline at %s. Record one with:\n  effectgate verify --write\n", *baselinePath)
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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

const approveUsage = `effectgate approve - record what a server advertises, so a later change is visible.

usage:
  effectgate approve [flags] -- <server-command> [server-args...]

  effectgate approve -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev
  effectgate approve --diff -- npx -y @modelcontextprotocol/server-filesystem C:\Users\me\dev

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
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
		return 1
	}

	existing, err := pin.Load(*lockPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if *diffOnly {
			fmt.Fprintf(os.Stderr, "effectgate: no lock at %s to compare against\n", *lockPath)
			return 1
		}
	case err != nil:
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
		fmt.Fprintln(os.Stderr, "usage: effectgate replay [session.jsonl | log-dir]")
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
		fmt.Fprintf(os.Stderr, "effectgate: no sessions recorded at %s yet.\n", path)
		fmt.Fprintln(os.Stderr, "  Wire effectgate into your MCP client and use it once, then try again.")
		return 1
	case err != nil:
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
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
	lockPath := flag.String("lock", "", "check the server against this lock file (see: effectgate approve)")
	var enforce enforceFlag
	flag.Var(&enforce, "enforce", "enforcement level: observe, enforce (deny only) or strict (confirm too); bare -enforce means enforce")
	policyPath := flag.String("policy", "", `policy file; "default" uses the built-in one`)
	rulesPath := flag.String("rules", "", "content signature file; defaults to the built-in set when a policy is in use")
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
	if misparsedEnforce(argv) {
		fmt.Fprintf(os.Stderr, "effectgate: -enforce takes its value with an equals sign: -enforce=%s\n", argv[0])
		return 2
	}

	// The kill switch is checked before any configuration file is opened. That
	// is the whole point: a broken policy or lock is otherwise a refusal to
	// start, which is exactly the situation this has to survive.
	disabled := off(os.Getenv)
	if disabled {
		fmt.Fprintln(os.Stderr,
			"effectgate: "+killSwitch+" is set: relaying with no checks at all - no pin check, no policy, no content scan")
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
		// Worth saying out loud - the log holds every tool result verbatim -
		// but not worth refusing to start and breaking the client's server.
		fmt.Fprintf(os.Stderr, "effectgate: warning: %v\n", err)
	case err != nil && disabled:
		// Under the kill switch nothing is allowed to stop the start. The log
		// is still worth keeping when it can be kept, since losing the record
		// of the session the guard misbehaved in is the opposite of useful.
		fmt.Fprintf(os.Stderr, "effectgate: warning: no session log: %v\n", err)
		log = nil
	case err != nil:
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
		return 1
	}

	// The client owns our lifecycle through stdin; a signal is the fallback.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var lock *pin.Lock
	if *lockPath != "" && !disabled {
		lock, err = pin.Load(*lockPath)
		if err != nil {
			// A lock that cannot be read is a refusal to start: the user asked
			// for this server to be checked, and starting unchecked would be
			// worse than not starting. EFFECTGATE_OFF is the way out.
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
	}

	var rules *policy.Policy
	switch {
	case disabled:
	case *policyPath == "default":
		rules = policy.Default()
	case *policyPath != "":
		rules, err = policy.Load(*policyPath)
		if err != nil {
			// Same reasoning as the lock: the user asked for this server to be
			// governed, and running it ungoverned is worse than not running it.
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
	}

	// Signatures are only useful alongside a policy: all they do is raise the
	// taint level, and taint is something only the policy acts on.
	var signatures *detect.Ruleset
	switch {
	case disabled:
	case *rulesPath != "":
		signatures, err = detect.Load(*rulesPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
			return 1
		}
	case rules != nil:
		signatures = detect.Default()
	}

	mode, from := resolveMode(&enforce, rules)
	if disabled {
		mode, from = policy.Observe, "off"
	}

	res, runErr := proxy.Run(ctx, proxy.Options{
		Argv:       argv,
		Log:        log,
		Grace:      *grace,
		CallTTL:    *callTTL,
		Lock:       lock,
		Policy:     rules,
		Detect:     signatures,
		Mode:       mode,
		Provenance: map[string]any{"from": from},
	})
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", runErr)
	}
	if err := log.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "effectgate: closing log: %v\n", err)
	}
	// Exit with the server's code: to the client we must look like the server.
	return res.ExitCode
}

// killSwitch turns the proxy into a pure pass-through.
//
// It exists because every other failure here is a refusal to start, and a
// refusal to start means the MCP server simply does not appear in the client,
// with the reason only on stderr. One environment variable gets the tools back
// without editing a config or rebuilding anything.
const killSwitch = "EFFECTGATE_OFF"

// off reports whether the kill switch is set.
//
// Only affirmative values count. EFFECTGATE_OFF=0 leaving the guard disabled is
// the mistake everyone makes with a variable named like this.
func off(getenv func(string) string) bool {
	switch strings.ToLower(strings.TrimSpace(getenv(killSwitch))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// enforceFlag accepts a bare -enforce as well as -enforce=strict.
//
// The flag package special-cases a Value that reports IsBoolFlag, which is what
// keeps the old spelling working while adding levels.
type enforceFlag struct {
	mode policy.Mode
	set  bool
}

func (e *enforceFlag) String() string {
	if e == nil || !e.set {
		return string(policy.Observe)
	}
	return string(e.mode)
}

func (e *enforceFlag) Set(s string) error {
	mode, err := policy.ParseMode(s)
	if err != nil {
		return err
	}
	e.mode, e.set = mode, true
	return nil
}

// IsBoolFlag is what allows `-enforce` with no value.
func (e *enforceFlag) IsBoolFlag() bool { return true }

// resolveMode decides the level in force and where it came from.
//
// The command line wins over the file. The policy file is meant to be committed
// and may belong to somebody else, while whoever is unbreaking this at nine in
// the morning owns the client config вЂ” so the flag has to be able to turn
// enforcement down, not only up.
func resolveMode(f *enforceFlag, p *policy.Policy) (policy.Mode, string) {
	switch {
	case f != nil && f.set:
		return f.mode, "flag"
	case p != nil && p.Mode != "":
		return p.Mode, "policy"
	}
	return policy.Observe, "default"
}

// misparsedEnforce catches `-enforce strict`, which the flag package reads as a
// bare -enforce followed by a positional argument. Here the positionals are the
// server command, so it would silently launch a server called "strict".
func misparsedEnforce(args []string) bool {
	if len(args) == 0 {
		return false
	}
	_, err := policy.ParseMode(args[0])
	return err == nil
}

func defaultLogDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "effectgate-sessions"
	}
	return filepath.Join(home, ".effectgate", "sessions")
}
