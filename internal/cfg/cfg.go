// Package cfg watches the client configuration files that decide which MCP
// servers run.
//
// This deliberately sits outside the traffic path. The proxy is itself a line
// in the config it would be guarding, so anyone who can rewrite that file
// removes the proxy from the chain first and everything downstream becomes
// theatre. Config integrity has to be checked by something the config does not
// control.
//
// Only the MCP server declarations are recorded, never the whole file. Client
// configs are also where the applications keep caches, feature flags and window
// positions, all rewritten constantly; a whole-file hash would report a change
// every few minutes and be ignored within a day.
package cfg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/pterbsgame-netizen/effectgate/internal/canon"
)

// Server is one MCP server declaration found in a client config.
type Server struct {
	// Name is the key it was declared under, prefixed by its project when the
	// declaration is nested under one.
	Name string `json:"name"`

	Command string   `json:"command,omitempty"`
	Args    []string `json:"args,omitempty"`
	URL     string   `json:"url,omitempty"`
	EnvKeys []string `json:"envKeys,omitempty"`

	// Hash covers the whole declaration with secrets redacted.
	Hash string `json:"hash"`
}

// File is the MCP-relevant content of one client config.
type File struct {
	Path    string   `json:"path"`
	Servers []Server `json:"servers"`
}

// Load extracts the MCP server declarations from a client config file.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(canon.TrimBOM(raw), &root); err != nil {
		return nil, fmt.Errorf("cfg: %s: %w", path, err)
	}

	f := &File{Path: path}
	if err := f.collect("", root["mcpServers"]); err != nil {
		return nil, fmt.Errorf("cfg: %s: %w", path, err)
	}

	// Claude Code keeps per-project declarations under projects.<dir>. They
	// are as dangerous as the global ones and are missed by anything that
	// only looks at the top level.
	if projects, ok := root["projects"]; ok {
		var byDir map[string]json.RawMessage
		if json.Unmarshal(projects, &byDir) == nil {
			dirs := make([]string, 0, len(byDir))
			for dir := range byDir {
				dirs = append(dirs, dir)
			}
			sort.Strings(dirs)
			for _, dir := range dirs {
				var project map[string]json.RawMessage
				if json.Unmarshal(byDir[dir], &project) != nil {
					continue
				}
				if err := f.collect("projects/"+dir+"/", project["mcpServers"]); err != nil {
					return nil, fmt.Errorf("cfg: %s: %w", path, err)
				}
			}
		}
	}

	sort.Slice(f.Servers, func(i, j int) bool { return f.Servers[i].Name < f.Servers[j].Name })
	return f, nil
}

func (f *File) collect(prefix string, block json.RawMessage) error {
	if len(block) == 0 {
		return nil
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(block, &servers); err != nil {
		return fmt.Errorf("mcpServers: %w", err)
	}
	for name, decl := range servers {
		s, err := newServer(prefix+name, decl)
		if err != nil {
			return err
		}
		f.Servers = append(f.Servers, s)
	}
	return nil
}

func newServer(name string, decl json.RawMessage) (Server, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(decl, &fields); err != nil {
		return Server{}, fmt.Errorf("server %q: %w", name, err)
	}

	s := Server{Name: name}
	_ = json.Unmarshal(fields["command"], &s.Command)
	_ = json.Unmarshal(fields["args"], &s.Args)
	_ = json.Unmarshal(fields["url"], &s.URL)
	s.EnvKeys = keysOf(fields["env"])

	redacted, err := redact(fields)
	if err != nil {
		return Server{}, fmt.Errorf("server %q: %w", name, err)
	}
	s.Hash, err = canon.Hash(redacted)
	if err != nil {
		return Server{}, fmt.Errorf("server %q: %w", name, err)
	}
	return s, nil
}

// redact replaces the values of the fields that carry secrets with their sorted
// key names.
//
// A change in which credentials a server receives is exactly what this is
// meant to catch, so the names have to be covered by the hash. The values must
// not be: the baseline is meant to be committed to a repository.
func redact(fields map[string]json.RawMessage) ([]byte, error) {
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		switch k {
		case "env", "headers":
			out[k+"Keys"] = keysOf(v)
		default:
			out[k] = v
		}
	}
	return json.Marshal(out)
}

func keysOf(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Discover returns the client config files that exist on this machine.
//
// Missing files are not an error and not reported: most people run one client.
// A file that appears later shows up as an added file in the next check, which
// is itself worth seeing.
func Discover() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	var candidates []string
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("APPDATA"); appData != "" {
			candidates = append(candidates, filepath.Join(appData, "Claude", "claude_desktop_config.json"))
		}
	case "darwin":
		candidates = append(candidates,
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"))
	default:
		candidates = append(candidates,
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"))
	}
	candidates = append(candidates,
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".cursor", "mcp.json"),
	)

	var found []string
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			found = append(found, c)
		}
	}
	return found
}
