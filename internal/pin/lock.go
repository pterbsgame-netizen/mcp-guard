// Package pin records what a server looked like when it was approved, and
// reports how it differs later.
//
// The threat is a server that behaves during review and changes afterwards:
// same tool name, a description rewritten to instruct the agent, or a schema
// widened to accept a path it had no business accepting. Nothing about the
// traffic looks wrong at the moment it happens, so the only way to see it is to
// have written down what was agreed to.
//
// The lock file is meant to live in the repository it guards, so that a change
// to a tool shows up in a diff during code review like any other change.
package pin

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pterbsgame-netizen/effectgate/internal/canon"
	"github.com/pterbsgame-netizen/effectgate/internal/mcp"
)

// Version is the lock file format version.
const Version = 1

// DefaultName is the conventional file name, alongside the project it covers.
const DefaultName = "effectgate.lock"

// Lock is the approved state of one MCP server.
type Lock struct {
	Version int    `json:"version"`
	Server  Server `json:"server"`
	Tools   []Tool `json:"tools"`
}

// Server is how the server is launched.
type Server struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`

	// EnvKeys are the names of the environment variables the server was
	// approved with. Names only — a lock file is committed to a repository,
	// and values are exactly what must never end up there.
	EnvKeys []string `json:"envKeys,omitempty"`
}

// Tool is one approved tool.
//
// The schema is stored indented rather than in canonical form: this file is
// read by humans in a diff. Hash is always computed from the canonical form, so
// formatting here cannot affect verification.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Hash        string          `json:"hash"`
}

// New builds a lock from a server description and the tools it advertised.
func New(server Server, tools []mcp.Tool) (*Lock, error) {
	l := &Lock{Version: Version, Server: server, Tools: make([]Tool, 0, len(tools))}
	sort.Strings(l.Server.EnvKeys)

	for _, t := range tools {
		pinned, err := newTool(t)
		if err != nil {
			return nil, err
		}
		l.Tools = append(l.Tools, pinned)
	}
	// Sorted by name so the file is stable: a server that lists its tools in a
	// different order must not produce a diff.
	sort.Slice(l.Tools, func(i, j int) bool { return l.Tools[i].Name < l.Tools[j].Name })
	return l, nil
}

func newTool(t mcp.Tool) (Tool, error) {
	schema := t.InputSchema
	if len(schema) == 0 {
		schema = json.RawMessage("null")
	}
	canonical, err := canon.JSON(schema)
	if err != nil {
		return Tool{}, fmt.Errorf("pin: tool %q schema: %w", t.Name, err)
	}
	hash, err := hashTool(t.Name, t.Description, canonical)
	if err != nil {
		return Tool{}, err
	}
	return Tool{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: indent(canonical),
		Hash:        hash,
	}, nil
}

// hashTool covers the three fields an attacker has to change to be useful: the
// name the agent calls, the description that tells the agent when to call it,
// and the schema that bounds what it may pass.
func hashTool(name, description string, canonicalSchema []byte) (string, error) {
	return canon.HashOf(struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		InputSchema json.RawMessage `json:"inputSchema"`
	}{name, description, canonicalSchema})
}

// rehash recomputes a stored tool's hash from its stored fields, so a hand-
// edited lock file cannot quietly approve something by adjusting the hash.
func (t Tool) rehash() (string, error) {
	schema := t.InputSchema
	if len(schema) == 0 {
		schema = json.RawMessage("null")
	}
	canonical, err := canon.JSON(schema)
	if err != nil {
		return "", fmt.Errorf("pin: tool %q schema: %w", t.Name, err)
	}
	return hashTool(t.Name, t.Description, canonical)
}

func indent(canonical []byte) json.RawMessage {
	var buf strings.Builder
	if err := indentInto(&buf, canonical); err != nil {
		return canonical
	}
	return json.RawMessage(buf.String())
}

// Save writes the lock to path.
func (l *Lock) Save(path string) error {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("pin: %w", err)
		}
	}
	// The lock is not a secret — it is meant to be committed — so the usual
	// 0644 is right here, unlike the session log.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("pin: %w", err)
	}
	return nil
}

// Load reads a lock from path and checks that every stored hash matches the
// fields stored beside it.
func Load(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l Lock
	if err := json.Unmarshal(canon.TrimBOM(data), &l); err != nil {
		return nil, fmt.Errorf("pin: %s: %w", path, err)
	}
	if l.Version != Version {
		return nil, fmt.Errorf("pin: %s: lock format version %d, this build understands %d", path, l.Version, Version)
	}
	for _, t := range l.Tools {
		want, err := t.rehash()
		if err != nil {
			return nil, err
		}
		if want != t.Hash {
			return nil, fmt.Errorf("pin: %s: tool %q has hash %s but its fields hash to %s — the file was edited", path, t.Name, short(t.Hash), short(want))
		}
	}
	return &l, nil
}

// Verify reports how the tools a server is advertising now differ from the
// approved set.
func (l *Lock) Verify(tools []mcp.Tool) ([]Change, error) {
	observed, err := New(l.Server, tools)
	if err != nil {
		return nil, err
	}
	return diffTools(l.Tools, observed.Tools), nil
}

func short(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
