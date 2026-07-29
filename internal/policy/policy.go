// Package policy decides what a tool call is allowed to do.
//
// It decides on effects, not on wording. Whether a message contains something
// that reads like an instruction is not knowable — in MCP the instruction and
// the data are the same bytes — but whether a call is about to write to
// ~/.ssh/authorized_keys is a fact. The set of dangerous effects is small and
// finite; the set of ways to phrase an instruction is neither.
//
// Content inspection has no vote here. Its only job, later, is to raise the
// taint level, which tightens what the effects rules already say.
package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/pterbsgame-netizen/mcp-guard/internal/fspath"
	"gopkg.in/yaml.v3"
)

// Version is the policy file format version.
const Version = 1

// DefaultName is the conventional file name.
const DefaultName = "mcp-guard.policy.yaml"

//go:embed default.yaml
var defaultYAML []byte

// Action is what to do about a call.
type Action string

const (
	Allow   Action = "allow"
	Confirm Action = "confirm"
	Deny    Action = "deny"
)

// severity orders actions so the strictest match wins.
func (a Action) severity() int {
	switch a {
	case Deny:
		return 3
	case Confirm:
		return 2
	case Allow:
		return 1
	}
	return 0
}

// Mode decides which verdicts are acted on and which are only recorded.
type Mode string

const (
	// Observe records what would have happened and changes nothing. This is
	// the default, and it is the only reason a tool like this survives its
	// first week on someone's machine.
	Observe Mode = "observe"

	// Enforce blocks deny and relays confirm. The two lists are not the same
	// kind of thing: deny covers credentials, agent configuration and shell
	// startup files, which ordinary work never writes, while confirm covers
	// package.json, Makefiles and shell scripts, which it writes constantly.
	// Refusing the second kind breaks the workflow on day one, and a tool that
	// does that is uninstalled on day one.
	Enforce Mode = "enforce"

	// Strict blocks confirm as well. Worth having, worth not defaulting to.
	Strict Mode = "strict"
)

// ParseMode reads a level from a flag or a config file.
//
// The spellings are generous in one direction only: "off" and "deny" and "all"
// say what they do at a glance, but nothing here quietly maps an unknown word
// onto a working default. A typo in an enforcement level must be an error.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "observe", "off", "false", "0", "no":
		return Observe, nil
	case "enforce", "deny", "true", "1", "yes", "on":
		return Enforce, nil
	case "strict", "all":
		return Strict, nil
	}
	return "", fmt.Errorf("policy: unknown enforcement level %q (want observe, enforce or strict)", s)
}

// Blocks reports whether an action is refused at this level.
//
// This is the only place the graduation lives. Anything that re-derives it from
// a boolean is how "enforce" quietly starts meaning "strict" again.
func (m Mode) Blocks(a Action) bool {
	switch m {
	case Enforce:
		return a == Deny
	case Strict:
		return a == Deny || a == Confirm
	}
	return false
}

// Enforcing reports whether this level acts on anything at all.
func (m Mode) Enforcing() bool { return m != "" && m != Observe }

// Policy is the parsed rule set.
type Policy struct {
	Version int   `yaml:"version"`
	Mode    Mode  `yaml:"mode"`
	Paths   Paths `yaml:"paths"`
	Exec    Exec  `yaml:"exec"`
	Taint   Taint `yaml:"taint"`

	deny             []pattern
	confirm          []pattern
	confirmIfTainted []pattern
}

// Paths lists the path patterns that carry an action.
type Paths struct {
	Deny    []string `yaml:"deny"`
	Confirm []string `yaml:"confirm"`

	// ConfirmIfTainted is where taint earns its keep: paths that are ordinary
	// to touch during honest work, and worth a second look once the session
	// has swallowed content from somewhere untrusted.
	ConfirmIfTainted []string `yaml:"confirm_if_tainted"`
}

// Exec covers tools that run commands, which are a class of their own: their
// arguments are a language, not a path, and nothing useful can be said about
// where one will end up writing.
type Exec struct {
	Tools           []string `yaml:"tools"`
	Action          Action   `yaml:"action"`
	ActionIfTainted Action   `yaml:"action_if_tainted"`
}

// Taint marks the tools whose results are content from somewhere nobody
// vouches for: fetched pages, mail, issue trackers, other people's branches.
type Taint struct {
	Sources []string `yaml:"sources"`

	// Exclude names tools the source patterns catch by accident. An exclusion
	// wins over a match, so a broad pattern can stay broad without dragging in
	// local tools that share a word with a remote one.
	Exclude []string `yaml:"exclude"`
}

// Default returns the built-in policy.
func Default() *Policy {
	p, err := Parse(defaultYAML)
	if err != nil {
		// The default is compiled in and covered by a test; reaching here
		// means the binary is broken, not the user's setup.
		panic("policy: built-in default is invalid: " + err.Error())
	}
	return p
}

// Load reads a policy from path.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse reads a policy from YAML.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if p.Version != Version {
		return nil, fmt.Errorf("policy: format version %d, this build understands %d", p.Version, Version)
	}
	if p.Mode == "" {
		p.Mode = Observe
	} else {
		mode, err := ParseMode(string(p.Mode))
		if err != nil {
			return nil, err
		}
		p.Mode = mode
	}
	for _, a := range []Action{p.Exec.Action, p.Exec.ActionIfTainted} {
		switch a {
		case "", Allow, Confirm, Deny:
		default:
			return nil, fmt.Errorf("policy: unknown action %q", a)
		}
	}

	var err error
	if p.deny, err = compileAll(p.Paths.Deny); err != nil {
		return nil, err
	}
	if p.confirm, err = compileAll(p.Paths.Confirm); err != nil {
		return nil, err
	}
	if p.confirmIfTainted, err = compileAll(p.Paths.ConfirmIfTainted); err != nil {
		return nil, err
	}
	return &p, nil
}

func compileAll(raws []string) ([]pattern, error) {
	out := make([]pattern, 0, len(raws))
	for _, raw := range raws {
		p, err := compile(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func errPattern(raw, why string) error {
	return fmt.Errorf("policy: pattern %q: %s", raw, why)
}

// Call is one tools/call to decide about.
type Call struct {
	Tool string
	Args json.RawMessage
}

// Verdict is the decision and why.
type Verdict struct {
	Action Action

	// Rule is the pattern or tool glob that decided it.
	Rule string

	// Reason is written for whoever has to read the refusal in their client.
	Reason string

	// Paths are the resolved paths the call would have touched.
	Paths []string
}

// IsTaintSource reports whether a tool's results should be treated as content
// from an untrusted source.
func (p *Policy) IsTaintSource(tool string) bool {
	// Exclusions are checked first: a tool named here is local whatever the
	// source patterns think of its name.
	for _, pat := range p.Taint.Exclude {
		if matchName(pat, tool) {
			return false
		}
	}
	for _, pat := range p.Taint.Sources {
		if matchName(pat, tool) {
			return true
		}
	}
	return false
}

// Decide evaluates a call. tainted says whether the session has already taken
// in content from an untrusted source.
//
// The strictest match wins, and every matching path is reported, because a call
// that touches one protected file and four ordinary ones is still a call about
// the protected one.
func (p *Policy) Decide(call Call, tainted bool) Verdict {
	v := Verdict{Action: Allow}

	// fromExec tracks who owns the current verdict, so a path of equal severity
	// can take the attribution away from the exec class. "exec:run_*" is the
	// least actionable thing to tell someone whose write to package.json was
	// held; the path is what they need to see. It never changes the decision.
	fromExec := false
	if action, rule := p.execAction(call.Tool, tainted); action != "" {
		v = Verdict{
			Action: action,
			Rule:   rule,
			Reason: fmt.Sprintf("%q runs commands", call.Tool),
		}
		fromExec = true
		if tainted && p.Exec.ActionIfTainted != "" {
			v.Reason += ", and this session has taken in untrusted content"
		}
	}

	for _, candidate := range extractPaths(call.Args) {
		segs, resolved, ok := resolveCandidate(candidate)
		if !ok {
			continue
		}
		hit := p.pathAction(segs, tainted)
		if hit.action == "" {
			continue
		}
		v.Paths = append(v.Paths, resolved)

		stricter := hit.action.severity() > v.Action.severity()
		// Equal severity displaces the exec class, but never another path: two
		// path rules of the same weight keep the first, as they always have.
		takeover := fromExec && hit.action.severity() == v.Action.severity()
		if !stricter && !takeover {
			continue
		}

		v.Action = hit.action
		v.Rule = hit.rule
		if takeover {
			v.Reason = fmt.Sprintf("%q runs commands, and would touch %s", call.Tool, resolved)
		} else {
			v.Reason = fmt.Sprintf("%q would touch %s", call.Tool, resolved)
		}
		fromExec = false
		if hit.tainted {
			v.Reason += ", and this session has taken in untrusted content"
		}
	}

	sort.Strings(v.Paths)
	v.Paths = dedup(v.Paths)
	return v
}

type pathHit struct {
	action  Action
	rule    string
	tainted bool
}

func (p *Policy) pathAction(segs []string, tainted bool) pathHit {
	for _, pat := range p.deny {
		if pat.match(segs) {
			return pathHit{Deny, pat.raw, false}
		}
	}
	for _, pat := range p.confirm {
		if pat.match(segs) {
			return pathHit{Confirm, pat.raw, false}
		}
	}
	if tainted {
		for _, pat := range p.confirmIfTainted {
			if pat.match(segs) {
				return pathHit{Confirm, pat.raw, true}
			}
		}
	}
	return pathHit{}
}

func (p *Policy) execAction(tool string, tainted bool) (Action, string) {
	for _, pat := range p.Exec.Tools {
		if !matchName(pat, tool) {
			continue
		}
		if tainted && p.Exec.ActionIfTainted != "" {
			return p.Exec.ActionIfTainted, "exec:" + pat
		}
		if p.Exec.Action != "" {
			return p.Exec.Action, "exec:" + pat
		}
		return Allow, "exec:" + pat
	}
	return "", ""
}

// resolveCandidate turns an argument value into comparable segments.
//
// An absolute path is resolved properly. A relative one cannot be: the server's
// working directory is its own business and we do not know it. Rather than
// guess — and invent a path nobody asked about — relative values are matched on
// their literal segments, which is exactly what the unanchored **/ rules need.
func resolveCandidate(s string) (segs []string, display string, ok bool) {
	r, err := fspath.Resolve(s, "")
	if err != nil {
		return nil, "", false
	}
	if isAbsolutish(s) {
		return segments(r.Abs), r.String(), true
	}
	return foldAll(splitAny(s)), s, true
}

func isAbsolutish(s string) bool {
	switch {
	case strings.HasPrefix(s, "~"):
		return true
	case strings.HasPrefix(s, "/"), strings.HasPrefix(s, `\`):
		return true
	case len(s) >= 2 && s[1] == ':':
		return true
	case strings.HasPrefix(s, "%") || strings.HasPrefix(s, "$"):
		// An environment variable at the front usually expands to an absolute
		// path; resolution has already done the expanding.
		return true
	}
	return false
}

func dedup(sorted []string) []string {
	if len(sorted) < 2 {
		return sorted
	}
	out := sorted[:1]
	for _, s := range sorted[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
