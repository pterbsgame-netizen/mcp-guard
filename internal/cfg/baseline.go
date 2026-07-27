package cfg

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pterbsgame-netizen/mcp-guard/internal/canon"
)

// Version is the baseline file format version.
const Version = 1

// DefaultBaselineName is the conventional file name.
//
// It belongs in a project repository, not beside the configs it describes: a
// baseline stored next to what it guards is editable by whoever edits that.
const DefaultBaselineName = "mcp-guard.configs.lock"

// Baseline is the approved state of the client configs.
type Baseline struct {
	Version int    `json:"version"`
	Files   []File `json:"files"`
}

// Snapshot reads the given config files into a baseline. Files that do not
// exist are skipped.
func Snapshot(paths []string) (*Baseline, error) {
	b := &Baseline{Version: Version}
	for _, p := range paths {
		f, err := Load(p)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		b.Files = append(b.Files, *f)
	}
	sort.Slice(b.Files, func(i, j int) bool { return b.Files[i].Path < b.Files[j].Path })
	return b, nil
}

// Save writes the baseline to path.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("cfg: %w", err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("cfg: %w", err)
		}
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadBaseline reads a baseline from path.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(canon.TrimBOM(data), &b); err != nil {
		return nil, fmt.Errorf("cfg: %s: %w", path, err)
	}
	if b.Version != Version {
		return nil, fmt.Errorf("cfg: %s: baseline format version %d, this build understands %d", path, b.Version, Version)
	}
	return &b, nil
}

// Paths lists the config files the baseline covers.
func (b *Baseline) Paths() []string {
	paths := make([]string, 0, len(b.Files))
	for _, f := range b.Files {
		paths = append(paths, f.Path)
	}
	return paths
}

// Kind is what sort of difference was found.
type Kind string

const (
	FileAdded     Kind = "config-added"
	FileRemoved   Kind = "config-removed"
	ServerAdded   Kind = "server-added"
	ServerRemoved Kind = "server-removed"
	ServerChanged Kind = "server-changed"
)

// Change is one difference between an approved config state and the current one.
type Change struct {
	Kind   Kind
	Path   string
	Server string
	Detail string
}

// Diff reports how the current state differs from the approved one.
func Diff(approved, current *Baseline) []Change {
	byPath := make(map[string]File, len(approved.Files))
	for _, f := range approved.Files {
		byPath[f.Path] = f
	}
	seen := make(map[string]bool, len(current.Files))

	var changes []Change
	for _, now := range current.Files {
		seen[now.Path] = true
		before, known := byPath[now.Path]
		if !known {
			changes = append(changes, Change{Kind: FileAdded, Path: now.Path,
				Detail: fmt.Sprintf("%d server(s) declared", len(now.Servers))})
			continue
		}
		changes = append(changes, diffServers(now.Path, before.Servers, now.Servers)...)
	}
	for _, before := range approved.Files {
		if !seen[before.Path] {
			changes = append(changes, Change{Kind: FileRemoved, Path: before.Path})
		}
	}
	return changes
}

func diffServers(path string, approved, current []Server) []Change {
	byName := make(map[string]Server, len(approved))
	for _, s := range approved {
		byName[s.Name] = s
	}
	seen := make(map[string]bool, len(current))

	var changes []Change
	for _, now := range current {
		seen[now.Name] = true
		before, known := byName[now.Name]
		if !known {
			changes = append(changes, Change{
				Kind: ServerAdded, Path: path, Server: now.Name, Detail: describe(now),
			})
			continue
		}
		if before.Hash == now.Hash {
			continue
		}
		changes = append(changes, Change{
			Kind: ServerChanged, Path: path, Server: now.Name,
			Detail: fmt.Sprintf("was: %s\n            now: %s", describe(before), describe(now)),
		})
	}
	for _, before := range approved {
		if !seen[before.Name] {
			changes = append(changes, Change{Kind: ServerRemoved, Path: path, Server: before.Name})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Server < changes[j].Server })
	return changes
}

func describe(s Server) string {
	var parts []string
	if s.Command != "" {
		parts = append(parts, strings.TrimSpace(s.Command+" "+strings.Join(s.Args, " ")))
	}
	if s.URL != "" {
		parts = append(parts, s.URL)
	}
	if len(s.EnvKeys) > 0 {
		parts = append(parts, "env: "+strings.Join(s.EnvKeys, ", "))
	}
	if len(parts) == 0 {
		return "(empty declaration)"
	}
	return strings.Join(parts, "   ")
}

// Report writes changes in a form meant to be read at a glance.
func Report(w io.Writer, changes []Change) {
	if len(changes) == 0 {
		fmt.Fprintln(w, "configs unchanged")
		return
	}
	byPath := map[string][]Change{}
	var order []string
	for _, c := range changes {
		if _, ok := byPath[c.Path]; !ok {
			order = append(order, c.Path)
		}
		byPath[c.Path] = append(byPath[c.Path], c)
	}
	for _, path := range order {
		fmt.Fprintln(w, path)
		for _, c := range byPath[path] {
			switch c.Kind {
			case FileAdded:
				fmt.Fprintf(w, "  + config appeared  %s\n", c.Detail)
			case FileRemoved:
				fmt.Fprintln(w, "  - config gone")
			case ServerAdded:
				fmt.Fprintf(w, "  + server  %s\n            %s\n", c.Server, c.Detail)
			case ServerRemoved:
				fmt.Fprintf(w, "  - server  %s\n", c.Server)
			case ServerChanged:
				fmt.Fprintf(w, "  ~ server  %s\n            %s\n", c.Server, c.Detail)
			}
		}
	}
}
