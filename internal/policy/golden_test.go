package policy

import (
	"bufio"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update rewrites the expected file instead of comparing against it:
//
//	go test ./internal/policy/ -update-golden
//
// Regenerating is not the same as being right. Read the diff before committing
// it: this file is the only thing that notices a rule change quietly moving a
// decision somewhere else.
var update = flag.Bool("update-golden", false, "rewrite corpus/golden/expected-verdicts.json")

const (
	goldenInput    = "../../corpus/golden/input.jsonl"
	goldenExpected = "../../corpus/golden/expected-verdicts.json"
)

type goldenCase struct {
	Case    string          `json:"case"`
	Tool    string          `json:"tool"`
	Args    json.RawMessage `json:"args"`
	Tainted bool            `json:"tainted,omitempty"`
}

type goldenVerdict struct {
	Case   string `json:"case"`
	Action string `json:"action"`
	Rule   string `json:"rule"`
}

// TestGoldenVerdicts pins every decision the default policy makes over a fixed
// set of calls.
//
// The cases are written with ~ rather than absolute paths, and none of them
// turn on letter case, so the answers are the same on Windows and on Linux —
// which is what makes this runnable in CI rather than a machine-specific
// snapshot.
func TestGoldenVerdicts(t *testing.T) {
	cases := readGoldenInput(t)
	p := Default()

	got := make([]goldenVerdict, 0, len(cases))
	for _, c := range cases {
		v := p.Decide(Call{Tool: c.Tool, Args: c.Args}, c.Tainted)
		got = append(got, goldenVerdict{Case: c.Case, Action: string(v.Action), Rule: v.Rule})
	}

	if *update {
		out, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(goldenExpected, append(out, '\n'), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("rewrote %s with %d verdicts - read the diff before committing", goldenExpected, len(got))
		return
	}

	want := readGoldenExpected(t)
	if len(got) != len(want) {
		t.Fatalf("%d verdicts against %d expected; rerun with -update-golden after reviewing", len(got), len(want))
	}
	for i := range got {
		if got[i].Case != want[i].Case {
			t.Fatalf("case %d is %q, expected file has %q; the two files are out of step", i, got[i].Case, want[i].Case)
		}
		if got[i].Action != want[i].Action || got[i].Rule != want[i].Rule {
			t.Errorf("%s:\n  got  %s via %q\n  want %s via %q",
				got[i].Case, got[i].Action, got[i].Rule, want[i].Action, want[i].Rule)
		}
	}
}

func readGoldenInput(t *testing.T) []goldenCase {
	t.Helper()
	f, err := os.Open(filepath.FromSlash(goldenInput))
	if err != nil {
		t.Skipf("no golden input: %v", err)
	}
	defer f.Close()

	var cases []goldenCase
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var c goldenCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatalf("%s:%d: %v", goldenInput, line, err)
		}
		if c.Case == "" {
			t.Fatalf("%s:%d: every case needs a name, or a diff says nothing about what moved", goldenInput, line)
		}
		cases = append(cases, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("the golden input is empty")
	}
	return cases
}

func readGoldenExpected(t *testing.T) []goldenVerdict {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(goldenExpected))
	if err != nil {
		t.Fatalf("no expected verdicts (%v); generate them with -update-golden and review the result", err)
	}
	var want []goldenVerdict
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatalf("%s: %v", goldenExpected, err)
	}
	return want
}
