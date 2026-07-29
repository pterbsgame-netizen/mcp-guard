// Package eval measures the rules against two corpora and prints numbers.
//
// The numbers that matter are not symmetrical. Recall on an attack corpus is
// easy to move and easy to fool yourself with: the samples are ones somebody
// already thought of, and every rule was written after reading them. The false
// positive rate on real traffic is the one that decides whether the tool is
// still installed in a month, and it cannot be invented — it has to be measured
// on sessions somebody actually had.
//
// So both are reported, and the benign side reports how much evidence it
// actually had. A false positive rate measured over four tool calls is not a
// rate.
package eval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pterbsgame-netizen/mcp-guard/internal/detect"
	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
	"github.com/pterbsgame-netizen/mcp-guard/internal/policy"
)

const maxLogLine = 64 << 20

// AttackReport is how the signatures did against known payloads.
type AttackReport struct {
	Samples  int
	Tainting int
	PerRule  map[string]int
	Missed   []string
}

// BenignReport is how everything did against real recorded traffic.
type BenignReport struct {
	Sessions int

	// Excluded is how many session logs were skipped by name. Reported, never
	// silent: a measurement that quietly dropped part of its input is not a
	// measurement.
	Excluded int

	Results   int
	Tainting  int
	RuleHits  map[string]int
	Calls     int
	Verdicts  map[policy.Action]int
	PolicyHit map[string]int
	Flagged   []string

	First, Last time.Time
}

// Span is how much wall-clock time the benign corpus covers.
func (b BenignReport) Span() time.Duration {
	if b.First.IsZero() || b.Last.IsZero() {
		return 0
	}
	return b.Last.Sub(b.First)
}

// BlocksPerWeekAt is the number that predicts whether a tool survives, at one
// enforcement level.
//
// It has to be per level, because the levels differ by an order of magnitude:
// enforce refuses only deny, which honest work never triggers, while strict
// also refuses confirm, which it triggers all day. The difference between the
// two lines is the whole argument for having levels at all.
//
// Meaningless without a span, and says so by returning false rather than a
// confident zero.
func (b BenignReport) BlocksPerWeekAt(m policy.Mode) (float64, bool) {
	span := b.Span()
	if span < time.Hour {
		return 0, false
	}
	var blocked int
	for action, n := range b.Verdicts {
		if m.Blocks(action) {
			blocked += n
		}
	}
	return float64(blocked) * float64(7*24*time.Hour) / float64(span), true
}

// Attack scans every file in dir as one payload.
func Attack(dir string, rs *detect.Ruleset) (AttackReport, error) {
	rep := AttackReport{PerRule: map[string]int{}}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return rep, err
	}
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		// README.md documents the corpus; it is not a payload.
		if strings.EqualFold(e.Name(), "README.md") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return rep, err
		}
		rep.Samples++
		res := rs.Scan(string(data))
		for _, h := range res.Hits {
			rep.PerRule[h.Rule]++
		}
		if rs.Tainting(res) {
			rep.Tainting++
		} else {
			rep.Missed = append(rep.Missed, fmt.Sprintf("%s (score %d)", e.Name(), res.Score))
		}
	}
	return rep, nil
}

// Benign replays recorded sessions: every tool result goes past the signatures,
// every tool call past the policy.
//
// exclude drops sessions from the measurement. It exists because probing the
// guard on purpose writes into the same directory as ordinary work, and a
// deliberate attempt to read ~/.ssh sitting in the benign corpus turns the one
// number this project waits on into a lie in both directions: the block counts
// as a false positive it is not, and the rate it inflates has no meaning.
// Nothing in a log distinguishes the two — only a human knows which run was
// which — so it has to be said rather than detected.
func Benign(path string, rs *detect.Ruleset, p *policy.Policy, exclude []string) (BenignReport, error) {
	rep := BenignReport{
		RuleHits:  map[string]int{},
		Verdicts:  map[policy.Action]int{},
		PolicyHit: map[string]int{},
	}

	logs, err := logFiles(path)
	if err != nil {
		return rep, err
	}
	for _, log := range logs {
		if excluded(log, exclude) {
			rep.Excluded++
			continue
		}
		rep.Sessions++
		if err := replayLog(log, rs, p, &rep); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// excluded matches a pattern against the log's file name, as a glob or as a
// plain substring — so a session id copied out of a report works as-is.
func excluded(path string, patterns []string) bool {
	base := filepath.Base(path)
	for _, pat := range patterns {
		if pat == "" {
			continue
		}
		if strings.Contains(base, pat) {
			return true
		}
		if ok, err := filepath.Match(pat, base); err == nil && ok {
			return true
		}
	}
	return false
}

func logFiles(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{path}, nil
	}
	logs, err := filepath.Glob(filepath.Join(path, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(logs)
	if len(logs) == 0 {
		return nil, fmt.Errorf("eval: no .jsonl logs in %s", path)
	}
	return logs, nil
}

func replayLog(path string, rs *detect.Ruleset, p *policy.Policy, rep *BenignReport) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLogLine)

	// Tool names by correlation key, so a result can be attributed to the call
	// that asked for it.
	pending := map[string]string{}

	for sc.Scan() {
		var rec struct {
			T   string          `json:"t"`
			Dir string          `json:"dir"`
			Msg json.RawMessage `json:"msg"`
		}
		if json.Unmarshal(sc.Bytes(), &rec) != nil || len(rec.Msg) == 0 {
			continue
		}
		if at, err := time.Parse(time.RFC3339Nano, rec.T); err == nil {
			if rep.First.IsZero() || at.Before(rep.First) {
				rep.First = at
			}
			if at.After(rep.Last) {
				rep.Last = at
			}
		}

		msgs, _, err := mcp.ParseFrame(rec.Msg)
		if err != nil {
			continue
		}
		dir := mcp.Direction(rec.Dir)
		for _, m := range msgs {
			switch {
			case m.Kind == mcp.KindRequest && m.Method == "tools/call":
				var params struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				}
				if json.Unmarshal(m.Params, &params) != nil {
					continue
				}
				pending[string(dir)+"\x00"+m.ID.Key()] = params.Name
				rep.Calls++
				if p == nil {
					continue
				}
				// Judged on a clean session: taint escalation is expected
				// behaviour, not a false positive.
				v := p.Decide(policy.Call{Tool: params.Name, Args: params.Arguments}, false)
				rep.Verdicts[v.Action]++
				if v.Action != policy.Allow {
					rep.PolicyHit[v.Rule]++
					rep.Flagged = append(rep.Flagged,
						fmt.Sprintf("%s: %s -> %s via %q %v",
							filepath.Base(path), params.Name, v.Action, v.Rule, v.Paths))
				}

			case m.Kind == mcp.KindResponse || m.Kind == mcp.KindError:
				key := string(dir.Opposite()) + "\x00" + m.ID.Key()
				if _, ok := pending[key]; !ok {
					continue
				}
				delete(pending, key)
				if rs == nil {
					continue
				}
				text := resultText(m.Result)
				if text == "" {
					continue
				}
				rep.Results++
				res := rs.Scan(text)
				for _, h := range res.Hits {
					rep.RuleHits[h.Rule]++
				}
				if rs.Tainting(res) {
					rep.Tainting++
				}
			}
		}
	}
	return sc.Err()
}

func resultText(result json.RawMessage) string {
	if len(result) == 0 || len(result) > 4<<20 {
		return ""
	}
	var v any
	if json.Unmarshal(result, &v) != nil {
		return ""
	}
	var b strings.Builder
	collect(v, 0, &b)
	return b.String()
}

func collect(v any, depth int, b *strings.Builder) {
	if depth > 8 || b.Len() > 256<<10 {
		return
	}
	switch t := v.(type) {
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	case []any:
		for _, e := range t {
			collect(e, depth+1, b)
		}
	case map[string]any:
		for _, e := range t {
			collect(e, depth+1, b)
		}
	}
}

// Report prints both sides, and is deliberately blunt about how much evidence
// each number rests on.
func Report(w io.Writer, attack *AttackReport, benign *BenignReport) {
	if attack != nil {
		fmt.Fprintln(w, "attack corpus")
		if attack.Samples == 0 {
			fmt.Fprintln(w, "  empty")
		} else {
			fmt.Fprintf(w, "  %d/%d samples reached the threshold (recall %.0f%%)\n",
				attack.Tainting, attack.Samples,
				100*float64(attack.Tainting)/float64(attack.Samples))
			for _, m := range attack.Missed {
				fmt.Fprintf(w, "    missed: %s\n", m)
			}
			printCounts(w, "  rule", attack.PerRule)
		}
		fmt.Fprintln(w)
	}
	if benign == nil {
		return
	}

	fmt.Fprintln(w, "benign corpus")
	fmt.Fprintf(w, "  %d session(s), %d tool call(s), %d result(s) scanned\n",
		benign.Sessions, benign.Calls, benign.Results)
	if benign.Excluded > 0 {
		fmt.Fprintf(w, "  %d session(s) excluded by name\n", benign.Excluded)
	}
	if span := benign.Span(); span > 0 {
		fmt.Fprintf(w, "  covering %s\n", span.Round(time.Minute))
	}

	if benign.Calls == 0 {
		fmt.Fprintln(w, "  no tool calls: this measures nothing about false positives")
		return
	}

	fmt.Fprintf(w, "  policy: %d allow, %d confirm, %d deny\n",
		benign.Verdicts[policy.Allow], benign.Verdicts[policy.Confirm], benign.Verdicts[policy.Deny])
	printCounts(w, "  rule", benign.PolicyHit)
	for _, f := range benign.Flagged {
		fmt.Fprintf(w, "    %s\n", f)
	}

	fmt.Fprintf(w, "  content: %d/%d results reached the threshold\n", benign.Tainting, benign.Results)
	printCounts(w, "  signature", benign.RuleHits)

	enforce, ok := benign.BlocksPerWeekAt(policy.Enforce)
	strict, _ := benign.BlocksPerWeekAt(policy.Strict)
	if ok {
		fmt.Fprintf(w, "  blocks per week of this traffic:  %.1f at enforce, %.1f at strict\n", enforce, strict)
	} else {
		fmt.Fprintln(w, "  blocks per week: not enough elapsed time to say")
	}
}

func printCounts(w io.Writer, label string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		name := k
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Fprintf(w, "%s %-28s %d\n", label, name, counts[k])
	}
}
