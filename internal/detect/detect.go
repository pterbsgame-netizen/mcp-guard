// Package detect scores text for instruction-shaped content.
//
// It never blocks anything, and nothing in this package is allowed to. Its
// output raises the taint level, which tightens what the effect rules already
// say; that is the entire contract.
//
// The reason is not modesty about regular expressions. The rules live in a
// public repository, so getting around them takes an attacker about thirty
// seconds, while the false positives land on the user every day — a blog post
// about prompt injection, a code review of a file containing the phrase, a test
// fixture like the ones in this package. As a defence the value is close to
// zero. As telemetry, and as a reason to be stricter about what a session is
// then allowed to do, it is real. Keeping it in exactly that role is the whole
// discipline here.
package detect

import (
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/pterbsgame-netizen/effectgate/internal/normalize"
	"gopkg.in/yaml.v3"
)

// Version is the ruleset format version.
const Version = 1

//go:embed default.yaml
var defaultYAML []byte

// Rule is one signature.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Weight      int    `yaml:"weight"`
	Pattern     string `yaml:"pattern"`

	re *regexp.Regexp
}

// Ruleset is the parsed signature set.
type Ruleset struct {
	Version int `yaml:"version"`

	// Threshold is the score at or above which content is treated as untrusted
	// enough to taint the session. It still blocks nothing.
	Threshold int `yaml:"threshold"`

	// HiddenBonus is added to a rule's weight when it matches inside a layer
	// that was not visible in the original — a base64 blob, an HTML comment, a
	// span with display:none. That an instruction was hidden says more than the
	// instruction does.
	HiddenBonus int `yaml:"hidden_bonus"`

	Rules []Rule `yaml:"rules"`
}

// Hit is one rule matching in one layer.
type Hit struct {
	Rule   string `json:"rule"`
	Layer  string `json:"layer"`
	Hidden bool   `json:"hidden,omitempty"`
	Weight int    `json:"weight"`

	// Sample is a short excerpt, for the log. Never the whole text: the log
	// already holds that, and a verdict record is meant to be skimmable.
	Sample string `json:"sample"`
}

// Result is the outcome of scanning one piece of text.
type Result struct {
	Score int   `json:"score"`
	Hits  []Hit `json:"hits,omitempty"`
}

const maxSample = 120

// Default returns the built-in ruleset.
func Default() *Ruleset {
	rs, err := Parse(defaultYAML)
	if err != nil {
		panic("detect: built-in ruleset is invalid: " + err.Error())
	}
	return rs
}

// Load reads a ruleset from path.
func Load(path string) (*Ruleset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

// Parse reads a ruleset from YAML.
func Parse(data []byte) (*Ruleset, error) {
	var rs Ruleset
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("detect: %w", err)
	}
	if rs.Version != Version {
		return nil, fmt.Errorf("detect: format version %d, this build understands %d", rs.Version, Version)
	}
	seen := make(map[string]bool, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if r.ID == "" {
			return nil, fmt.Errorf("detect: rule %d has no id", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("detect: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Weight <= 0 {
			return nil, fmt.Errorf("detect: rule %q has weight %d", r.ID, r.Weight)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("detect: rule %q: %w", r.ID, err)
		}
		r.re = re
	}
	return &rs, nil
}

// Scan unfolds the text and matches every rule against every layer.
//
// A rule that fires in several layers counts once, at its best weight: the same
// sentence written twice is one sentence, and letting repetition run the score
// up would make padding an attack rather than a nuisance.
func (rs *Ruleset) Scan(text string) Result {
	best := make(map[string]Hit, len(rs.Rules))

	for _, layer := range normalize.Reveal(text) {
		for i := range rs.Rules {
			r := &rs.Rules[i]
			loc := r.re.FindStringIndex(layer.Text)
			if loc == nil {
				continue
			}
			weight := r.Weight
			if layer.Hidden {
				weight += rs.HiddenBonus
			}
			if prev, ok := best[r.ID]; ok && prev.Weight >= weight {
				continue
			}
			best[r.ID] = Hit{
				Rule:   r.ID,
				Layer:  layer.Name,
				Hidden: layer.Hidden,
				Weight: weight,
				Sample: sample(layer.Text, loc),
			}
		}
	}

	res := Result{Hits: make([]Hit, 0, len(best))}
	for i := range rs.Rules {
		if h, ok := best[rs.Rules[i].ID]; ok {
			res.Score += h.Weight
			res.Hits = append(res.Hits, h)
		}
	}
	if len(res.Hits) == 0 {
		res.Hits = nil
	}
	return res
}

// Tainting reports whether a result is strong enough to mark the session.
func (rs *Ruleset) Tainting(res Result) bool {
	return rs.Threshold > 0 && res.Score >= rs.Threshold
}

func sample(text string, loc []int) string {
	start := loc[0] - 20
	if start < 0 {
		start = 0
	}
	end := start + maxSample
	if end > len(text) {
		end = len(text)
	}
	return strings.TrimSpace(text[start:end])
}
