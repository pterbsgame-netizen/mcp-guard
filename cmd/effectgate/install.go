package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pterbsgame-netizen/effectgate/internal/cfg"
	"github.com/pterbsgame-netizen/effectgate/internal/install"
	"github.com/pterbsgame-netizen/effectgate/internal/policy"
)

const installUsage = `effectgate install - put effectgate in front of every stdio server a client launches.

usage:
  effectgate install [flags] [config-file...]
  effectgate uninstall [flags] [config-file...]

  effectgate install --dry-run
  effectgate install
  effectgate uninstall

With no files named, the client configs found on this machine are used. Every
file is copied aside before it is written, and uninstall puts the original
commands back from the wrapped ones, so neither direction needs the backup.

Servers are wrapped at the observing level: nothing is refused until you pass
--enforce here or edit the config later. That is the order the numbers are meant
to be collected in.

flags:
`

func runInstall(args []string, undo bool) int {
	name := "install"
	if undo {
		name = "uninstall"
	}
	fset := flag.NewFlagSet(name, flag.ContinueOnError)
	dryRun := fset.Bool("dry-run", false, "print what would change and write nothing")
	noBackup := fset.Bool("no-backup", false, "do not copy each config aside before writing it")
	guardPath := fset.String("guard", "", "path written into the config; defaults to this binary")
	policyPath := fset.String("policy", "default", `policy the wrapped servers run with; "default" or a path`)
	enforce := fset.String("enforce", "", "enforcement level baked into the wrapped command: observe, enforce or strict")
	fset.Usage = func() { fmt.Fprint(os.Stderr, installUsage); fset.PrintDefaults() }
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

	var result *install.Result
	var err error
	if undo {
		result, err = install.PlanUninstall(paths)
	} else {
		var opts install.Options
		if opts, err = installOptions(*guardPath, *policyPath, *enforce); err == nil {
			result, err = install.PlanInstall(paths, opts)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
		return 1
	}

	report(os.Stdout, result, paths)

	if len(result.Files()) == 0 {
		fmt.Fprintln(os.Stdout, "\nnothing to do.")
		return 0
	}
	if *dryRun {
		fmt.Fprintf(os.Stdout, "\ndry run: %d file(s) left untouched.\n", len(result.Files()))
		return 0
	}

	backups, err := result.Apply(!*noBackup)
	for _, b := range backups {
		fmt.Fprintf(os.Stdout, "\nbacked up  %s", b)
	}
	if len(backups) > 0 {
		fmt.Fprintln(os.Stdout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "effectgate: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stdout, "\nwrote %d file(s). Restart the client for it to take effect.\n", len(result.Files()))
	if !undo {
		fmt.Fprintln(os.Stdout, "If anything breaks, EFFECTGATE_OFF=1 in the client's environment relays with no checks,")
		fmt.Fprintln(os.Stdout, "and `effectgate uninstall` puts the original commands back.")
	}
	return 0
}

func installOptions(guardPath, policyPath, enforce string) (install.Options, error) {
	var o install.Options

	if guardPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return o, fmt.Errorf("cannot find my own path; pass --guard: %w", err)
		}
		// The client launches this path months later, so a relative one, or one
		// that resolves through a symlink that moves, is a server that silently
		// stops appearing. Resolve it once, here, where it can still be seen.
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		guardPath = exe
	}
	abs, err := filepath.Abs(guardPath)
	if err != nil {
		return o, err
	}
	if _, err := os.Stat(abs); err != nil {
		return o, fmt.Errorf("no binary at %s: %w", abs, err)
	}
	o.Guard = abs

	o.Args = []string{"--policy", policyPath}
	if enforce != "" {
		mode, err := policy.ParseMode(enforce)
		if err != nil {
			return o, err
		}
		o.Args = append(o.Args, "-enforce="+string(mode))
	}
	return o, nil
}

// report prints one line per declaration, grouped by the file it came from.
//
// Everything is listed, including what was left alone: a wrapper that prints
// only its successes leaves the reader believing the servers it skipped are
// covered.
func report(w io.Writer, r *install.Result, paths []string) {
	byFile := map[string][]install.Change{}
	for _, c := range r.Changes {
		byFile[c.File] = append(byFile[c.File], c)
	}

	for i, path := range paths {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w, path)
		changes := byFile[path]
		if len(changes) == 0 {
			fmt.Fprintln(w, "  (no server declarations)")
			continue
		}
		width := 0
		for _, c := range changes {
			if n := len(c.Server); n > width {
				width = n
			}
		}
		for _, c := range changes {
			pad := strings.Repeat(" ", width-len(c.Server))
			switch c.Kind {
			case install.Skip:
				fmt.Fprintf(w, "  %s%s  skip    %s\n", c.Server, pad, c.Note)
			default:
				fmt.Fprintf(w, "  %s%s  %-7s %s\n", c.Server, pad, c.Kind, c.Before)
				fmt.Fprintf(w, "  %s  %s  →       %s\n", strings.Repeat(" ", width), "       ", c.After)
			}
		}
	}
}
