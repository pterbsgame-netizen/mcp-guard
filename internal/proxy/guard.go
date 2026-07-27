package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
	"github.com/pterbsgame-netizen/mcp-guard/internal/normalize"
	"github.com/pterbsgame-netizen/mcp-guard/internal/pin"
	"github.com/pterbsgame-netizen/mcp-guard/internal/policy"
)

// syncWriter serialises writes to the client.
//
// Two goroutines write there: the one relaying the server's answers, and the
// one that refuses a call and answers it itself. Without this they can
// interleave mid-message, and a torn line is not JSON any more.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// guard holds everything the proxy knows that bears on a decision: which tools
// stopped matching their approval, whether the session has taken in untrusted
// content, and which call is waiting on which answer.
type guard struct {
	o *Options

	mu sync.Mutex
	// mismatched maps a tool name to why it no longer matches the lock.
	mismatched map[string]string
	// pendingTools maps a correlation key to the tool a call is waiting on, so
	// the answer can be attributed when it arrives.
	pendingTools map[string]string
	tainted      bool
}

func newGuard(o *Options) *guard {
	return &guard{o: o, pendingTools: make(map[string]string)}
}

// enforcing reports whether verdicts are acted on rather than only recorded.
//
// Either switch turns it on: --enforce on the command line, or mode: enforce in
// the policy file. Observe is the default in both, deliberately.
func (g *guard) enforcing() bool {
	if g.o.Enforce {
		return true
	}
	return g.o.Policy != nil && g.o.Policy.Mode == policy.Enforce
}

func (g *guard) isTainted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tainted
}

// setPinMismatches records the result of checking a tools/list answer.
func (g *guard) setPinMismatches(changes []pin.Change) {
	m := make(map[string]string, len(changes))
	for _, c := range changes {
		switch c.Kind {
		case pin.ToolChanged:
			m[c.Tool] = fmt.Sprintf("tool %q changed since it was approved (%s)",
				c.Tool, strings.Join(c.Fields, ", "))
		case pin.ToolAdded:
			m[c.Tool] = fmt.Sprintf("tool %q was not present when this server was approved", c.Tool)
		}
		// A removed tool needs no entry: it cannot be called.
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mismatched = m
}

// verifyTools checks the server's currently advertised tools against the lock.
func (g *guard) verifyTools(session *mcp.Session) {
	if g.o.Lock == nil {
		return
	}
	changes, err := g.o.Lock.Verify(session.Tools())
	if err != nil {
		g.o.Log.Event("pin-error", map[string]any{"err": err.Error()})
		return
	}
	g.setPinMismatches(changes)
	for _, c := range changes {
		g.o.Log.Event("pin-mismatch", map[string]any{
			"kind":   string(c.Kind),
			"tool":   c.Tool,
			"fields": c.Fields,
		})
	}
}

// answered is called when a reply arrives, so a result from a tool that carries
// content from somewhere untrusted can taint the session.
//
// Taint is decided by where the content came from, not by what it says. An
// attacker has to reach an effect, and the set of effects is small; the set of
// ways to phrase an instruction is not.
func (g *guard) answered(dir mcp.Direction, m mcp.Message) {
	if g.o.Policy == nil {
		return
	}
	key := string(dir.Opposite()) + "\x00" + m.ID.Key()

	g.mu.Lock()
	tool, ok := g.pendingTools[key]
	delete(g.pendingTools, key)
	alreadyTainted := g.tainted
	bySource := ok && g.o.Policy.IsTaintSource(tool)
	if bySource {
		g.tainted = true
	}
	g.mu.Unlock()

	if !ok {
		return
	}
	if bySource && !alreadyTainted {
		g.o.Log.Event("tainted", map[string]any{
			"by":     tool,
			"reason": "source",
			"why": "a result from this tool is content from a source nobody vouches for; " +
				"sensitive effects are tightened from here on",
		})
	}

	// The content signal is the weaker one and comes second on purpose. It
	// never blocks and never can: all it may do is reach the same conclusion
	// the source rule would have reached, for a tool nobody thought to list.
	if g.o.Detect == nil {
		return
	}
	text := resultText(m.Result)
	if text == "" {
		return
	}
	res := g.o.Detect.Scan(text)
	if len(res.Hits) == 0 {
		return
	}
	tainting := g.o.Detect.Tainting(res)
	g.o.Log.Event("content-score", map[string]any{
		"tool":     tool,
		"score":    res.Score,
		"hits":     res.Hits,
		"tainting": tainting,
	})
	if !tainting || alreadyTainted || bySource {
		return
	}
	g.mu.Lock()
	g.tainted = true
	g.mu.Unlock()
	g.o.Log.Event("tainted", map[string]any{
		"by":     tool,
		"reason": "content",
		"score":  res.Score,
		"why": "this result reads like instructions aimed at the agent; " +
			"nothing is blocked for that, but sensitive effects are tightened from here on",
	})
}

// resultText pulls the human-readable strings out of a tool result.
//
// Bounded twice over: the walk stops early, and the detector truncates again.
// A result can be megabytes, and an instruction meant for a model has to be
// short enough for the model to act on.
func resultText(result json.RawMessage) string {
	if len(result) == 0 || len(result) > 4<<20 {
		return ""
	}
	var v any
	if json.Unmarshal(result, &v) != nil {
		return ""
	}
	var b strings.Builder
	collectText(v, 0, &b)
	return b.String()
}

func collectText(v any, depth int, b *strings.Builder) {
	if depth > 8 || b.Len() > normalizeBudget {
		return
	}
	switch t := v.(type) {
	case string:
		b.WriteString(t)
		b.WriteByte('\n')
	case []any:
		for _, e := range t {
			collectText(e, depth+1, b)
		}
	case map[string]any:
		for _, e := range t {
			collectText(e, depth+1, b)
		}
	}
}

// normalizeBudget matches what the normaliser will look at anyway.
const normalizeBudget = normalize.MaxInput

// gate decides whether a client-to-server frame should be refused, returning
// the reply to send back instead, or nil to let it through.
//
// Only tools/call is gated. Letting tools/list through is a deliberate trade:
// refusing it leaves the client with no tools and a visibly broken server,
// while the thing that does damage is the call.
func (g *guard) gate(frame []byte) []byte {
	if g.o.Lock == nil && g.o.Policy == nil {
		return nil
	}
	msgs, batched, err := mcp.ParseFrame(frame)
	if err != nil || len(msgs) != 1 {
		if batched {
			// A batch needs a batched reply to stay well-formed. Rather than
			// answer badly, let it through and say so.
			g.o.Log.Event("gate-skipped-batch", nil)
		}
		return nil
	}
	m := msgs[0]
	if m.Kind != mcp.KindRequest || m.Method != "tools/call" {
		return nil
	}
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(m.Params, &params) != nil || params.Name == "" {
		return nil
	}

	g.mu.Lock()
	g.pendingTools[string(mcp.ClientToServer)+"\x00"+m.ID.Key()] = params.Name
	reason, mismatched := g.mismatched[params.Name]
	tainted := g.tainted
	g.mu.Unlock()

	if mismatched {
		g.o.Log.Event("pin-violation", map[string]any{
			"tool":    params.Name,
			"id":      m.ID.String(),
			"reason":  reason,
			"blocked": g.enforcing(),
		})
		if g.enforcing() {
			return g.refuse(m.ID, reason+". Review it with: mcp-guard approve --diff -- <server command>")
		}
	}

	if g.o.Policy == nil {
		return nil
	}
	v := g.o.Policy.Decide(policy.Call{Tool: params.Name, Args: params.Arguments}, tainted)
	if v.Action == policy.Allow {
		return nil
	}

	g.o.Log.Event("policy-verdict", map[string]any{
		"tool":    params.Name,
		"id":      m.ID.String(),
		"action":  string(v.Action),
		"rule":    v.Rule,
		"paths":   v.Paths,
		"tainted": tainted,
		"blocked": g.enforcing(),
	})
	if !g.enforcing() {
		return nil
	}

	switch v.Action {
	case policy.Deny:
		return g.refuse(m.ID, fmt.Sprintf(
			"blocked by mcp-guard: %s (rule %q)", v.Reason, v.Rule))
	case policy.Confirm:
		// There is no way to ask from here. The protocol has elicitation/create
		// for exactly this, but it needs client support that cannot be assumed,
		// so a confirm becomes a refusal with instructions rather than a
		// silent allow. Saying so plainly beats pretending to have asked.
		return g.refuse(m.ID, fmt.Sprintf(
			"held by mcp-guard for confirmation: %s (rule %q). "+
				"There is no way to ask you from here yet, so it was refused. "+
				"Allow it by adding a rule to the policy file, or rerun without --enforce.",
			v.Reason, v.Rule))
	}
	return nil
}

// refuse builds the reply that goes back instead of the result.
//
// A blocked call must still be answered, with the same id. Dropping it leaves
// the client waiting until it times out, with nothing to show for it and no
// idea why.
func (g *guard) refuse(id mcp.ID, message string) []byte {
	reply, err := mcp.NewError(id, mcp.CodeBlocked, message)
	if err != nil {
		return nil
	}
	return reply
}
