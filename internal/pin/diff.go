package pin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/pterbsgame-netizen/effectgate/internal/canon"
)

// Kind is what sort of difference was found.
type Kind string

const (
	ToolAdded     Kind = "tool-added"
	ToolRemoved   Kind = "tool-removed"
	ToolChanged   Kind = "tool-changed"
	ServerChanged Kind = "server-changed"
)

// Change is one difference between an approved state and an observed one.
type Change struct {
	Kind Kind

	// Tool is the tool involved, empty for ServerChanged.
	Tool string

	// Fields names what changed within the tool: "description", "inputSchema".
	Fields []string

	// Detail describes a server-level change in words.
	Detail string

	Old *Tool
	New *Tool
}

// Diff reports every way observed differs from approved, server included.
func Diff(approved, observed *Lock) []Change {
	var changes []Change

	if approved.Server.Command != observed.Server.Command {
		changes = append(changes, Change{
			Kind:   ServerChanged,
			Detail: fmt.Sprintf("command: %q -> %q", approved.Server.Command, observed.Server.Command),
		})
	}
	if !equalStrings(approved.Server.Args, observed.Server.Args) {
		changes = append(changes, Change{
			Kind:   ServerChanged,
			Detail: fmt.Sprintf("args: %q -> %q", strings.Join(approved.Server.Args, " "), strings.Join(observed.Server.Args, " ")),
		})
	}
	// Environment variable names, never values. A name that was not there at
	// approval is how a credential reaches a server it was never meant to.
	if added, removed := diffSets(approved.Server.EnvKeys, observed.Server.EnvKeys); len(added)+len(removed) > 0 {
		var parts []string
		if len(added) > 0 {
			parts = append(parts, "added "+strings.Join(added, ", "))
		}
		if len(removed) > 0 {
			parts = append(parts, "removed "+strings.Join(removed, ", "))
		}
		changes = append(changes, Change{
			Kind:   ServerChanged,
			Detail: "env keys: " + strings.Join(parts, "; "),
		})
	}

	return append(changes, diffTools(approved.Tools, observed.Tools)...)
}

// diffTools compares two tool sets by name. Both are sorted by New.
func diffTools(approved, observed []Tool) []Change {
	byName := make(map[string]Tool, len(approved))
	for _, t := range approved {
		byName[t.Name] = t
	}

	var changes []Change
	seen := make(map[string]bool, len(observed))
	for _, now := range observed {
		seen[now.Name] = true
		before, known := byName[now.Name]
		if !known {
			added := now
			changes = append(changes, Change{Kind: ToolAdded, Tool: now.Name, New: &added})
			continue
		}
		if before.Hash == now.Hash {
			continue
		}
		old, cur := before, now
		changes = append(changes, Change{
			Kind:   ToolChanged,
			Tool:   now.Name,
			Fields: changedFields(before, now),
			Old:    &old,
			New:    &cur,
		})
	}
	for _, before := range approved {
		if !seen[before.Name] {
			old := before
			changes = append(changes, Change{Kind: ToolRemoved, Tool: before.Name, Old: &old})
		}
	}

	sort.Slice(changes, func(i, j int) bool { return changes[i].Tool < changes[j].Tool })
	return changes
}

func changedFields(before, now Tool) []string {
	var fields []string
	if before.Description != now.Description {
		fields = append(fields, "description")
	}
	if !sameSchema(before.InputSchema, now.InputSchema) {
		fields = append(fields, "inputSchema")
	}
	if len(fields) == 0 {
		// The hashes differ but neither field does, which should be
		// impossible. Say so rather than reporting a change with no content.
		fields = append(fields, "unknown")
	}
	return fields
}

func sameSchema(a, b json.RawMessage) bool {
	ca, err := canon.JSON(a)
	if err != nil {
		return false
	}
	cb, err := canon.JSON(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ca, cb)
}

// Report writes changes in a form meant to be read before deciding whether to
// re-approve. Description changes are shown in full: tool poisoning lives
// there, and a truncated one is a poisoning you did not read.
func Report(w io.Writer, changes []Change) {
	if len(changes) == 0 {
		fmt.Fprintln(w, "no changes since approval")
		return
	}
	for _, c := range changes {
		switch c.Kind {
		case ServerChanged:
			fmt.Fprintf(w, "~ server  %s\n", c.Detail)

		case ToolAdded:
			fmt.Fprintf(w, "+ tool    %s\n", c.Tool)
			fmt.Fprintf(w, "          description: %s\n", oneLine(c.New.Description))

		case ToolRemoved:
			fmt.Fprintf(w, "- tool    %s\n", c.Tool)

		case ToolChanged:
			fmt.Fprintf(w, "~ tool    %s  (%s)\n", c.Tool, strings.Join(c.Fields, ", "))
			for _, f := range c.Fields {
				switch f {
				case "description":
					fmt.Fprintf(w, "          description was: %s\n", oneLine(c.Old.Description))
					fmt.Fprintf(w, "          description now: %s\n", oneLine(c.New.Description))
				case "inputSchema":
					fmt.Fprintf(w, "          schema was: %s\n", compact(c.Old.InputSchema))
					fmt.Fprintf(w, "          schema now: %s\n", compact(c.New.InputSchema))
				}
			}
		}
	}
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	return strings.TrimSpace(s)
}

func compact(raw json.RawMessage) string {
	c, err := canon.JSON(raw)
	if err != nil {
		return string(raw)
	}
	return string(c)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// diffSets returns what is in b but not a, and what is in a but not b.
func diffSets(a, b []string) (added, removed []string) {
	in := func(set []string, s string) bool {
		for _, e := range set {
			if e == s {
				return true
			}
		}
		return false
	}
	for _, s := range b {
		if !in(a, s) {
			added = append(added, s)
		}
	}
	for _, s := range a {
		if !in(b, s) {
			removed = append(removed, s)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func indentInto(w *strings.Builder, canonical []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, canonical, "", "  "); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}
