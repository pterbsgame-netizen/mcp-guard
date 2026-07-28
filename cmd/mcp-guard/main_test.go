package main

import (
	"flag"
	"io"
	"testing"

	"github.com/pterbsgame-netizen/mcp-guard/internal/policy"
)

// TestKillSwitchIsAffirmativeOnly: a variable named like this invites
// MCPGUARD_OFF=0, and a guard that disarms itself on being told "off is false"
// is worse than one with no switch at all.
func TestKillSwitchIsAffirmativeOnly(t *testing.T) {
	on := []string{"1", "true", "TRUE", "yes", "on", " on "}
	for _, v := range on {
		if !off(func(string) string { return v }) {
			t.Errorf("%s=%q did not disable the guard", killSwitch, v)
		}
	}
	for _, v := range []string{"", "0", "false", "no", "off", "maybe", "OFF=1"} {
		if off(func(string) string { return v }) {
			t.Errorf("%s=%q disabled the guard", killSwitch, v)
		}
	}
}

func TestResolveMode(t *testing.T) {
	strictPolicy := &policy.Policy{Mode: policy.Strict}
	observePolicy := &policy.Policy{Mode: policy.Observe}

	tests := []struct {
		name   string
		flag   *enforceFlag
		policy *policy.Policy
		want   policy.Mode
		from   string
	}{
		{"nothing set", &enforceFlag{}, nil, policy.Observe, "default"},
		{"policy only", &enforceFlag{}, strictPolicy, policy.Strict, "policy"},
		{"flag only", &enforceFlag{mode: policy.Enforce, set: true}, nil, policy.Enforce, "flag"},
		{"flag raises over policy", &enforceFlag{mode: policy.Strict, set: true}, observePolicy, policy.Strict, "flag"},
		// The flag must be able to turn enforcement DOWN. The policy file is
		// meant to be committed and may belong to somebody else; whoever is
		// unbreaking this owns the client config, not that file.
		{"flag lowers under policy", &enforceFlag{mode: policy.Observe, set: true}, strictPolicy, policy.Observe, "flag"},
		{"flag lowers to deny-only", &enforceFlag{mode: policy.Enforce, set: true}, strictPolicy, policy.Enforce, "flag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, from := resolveMode(tt.flag, tt.policy)
			if mode != tt.want || from != tt.from {
				t.Errorf("got (%q, %q), want (%q, %q)", mode, from, tt.want, tt.from)
			}
		})
	}
}

// TestEnforceFlagParsing: a bare -enforce has to keep working, or every
// existing config that has one breaks on upgrade.
func TestEnforceFlagParsing(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want policy.Mode
		rest []string
	}{
		{"bare", []string{"-enforce", "--", "npx", "server"}, policy.Enforce, []string{"npx", "server"}},
		{"strict", []string{"-enforce=strict", "--", "npx"}, policy.Strict, []string{"npx"}},
		{"off", []string{"-enforce=off", "--", "npx"}, policy.Observe, []string{"npx"}},
		{"deny alias", []string{"-enforce=deny", "--", "npx"}, policy.Enforce, []string{"npx"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var e enforceFlag
			fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			fs.Var(&e, "enforce", "")
			if err := fs.Parse(tt.args); err != nil {
				t.Fatalf("Parse(%v): %v", tt.args, err)
			}
			if !e.set || e.mode != tt.want {
				t.Errorf("mode = %q (set=%v), want %q", e.mode, e.set, tt.want)
			}
			if got := fs.Args(); !equal(got, tt.rest) {
				t.Errorf("remaining args = %v, want %v", got, tt.rest)
			}
		})
	}

	var e enforceFlag
	fs := flag.NewFlagSet("proxy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&e, "enforce", "")
	if err := fs.Parse([]string{"-enforce=nonsense", "--", "npx"}); err == nil {
		t.Error("an unknown level was accepted; a typo in an enforcement level must be an error")
	}
}

// TestSpaceSeparatedEnforceIsCaught: because the flag reports IsBoolFlag,
// "-enforce strict" parses as a bare -enforce plus a positional argument. Here
// the positionals are the server command, so it would launch a server called
// "strict" and silently enforce at the wrong level.
func TestSpaceSeparatedEnforceIsCaught(t *testing.T) {
	if !misparsedEnforce([]string{"strict", "--", "npx"}) {
		t.Error("-enforce strict was not caught")
	}
	if !misparsedEnforce([]string{"off"}) {
		t.Error("-enforce off was not caught")
	}
	// An ordinary server command must not trip it.
	for _, argv := range [][]string{{"npx", "-y", "server"}, {"node", "server.js"}, {}} {
		if misparsedEnforce(argv) {
			t.Errorf("%v was mistaken for a misplaced enforcement level", argv)
		}
	}
}

func equal(a, b []string) bool {
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
