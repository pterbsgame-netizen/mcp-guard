package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/pterbsgame-netizen/effectgate/internal/mcp"
	"github.com/pterbsgame-netizen/effectgate/internal/normalize"
	"github.com/pterbsgame-netizen/effectgate/internal/pin"
	"github.com/pterbsgame-netizen/effectgate/internal/policy"
)

// syncWriter serialises writes to a stream with more than one writer.
//
// The client receives messages from two goroutines: the one relaying the
// server's answers, and the one that refuses a call and answers it itself.
// Without this they can interleave mid-message, and a torn line is not JSON.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// maxStderrRecorded caps how much of a server's stderr goes into the session
// log. A traceback is a few kilobytes; a server stuck in a logging loop is not
// worth a gigabyte of disk.
const maxStderrRecorded = 64 << 10

// stderrTee relays the server's stderr and records a copy.
//
// "Never swallow stderr" still holds: every byte reaches the client exactly as
// before, and the relay happens first so a slow log cannot delay it. The copy
// exists because a session log saying "exited code=1" without saying why sends
// whoever is debugging out of the tool and into reproducing by hand - which is
// exactly what happened the first time a real server died in production.
type stderrTee struct {
	w   io.Writer
	log *SessionLog

	mu        sync.Mutex
	partial   []byte
	recorded  int
	truncated bool
}

func (t *stderrTee) Write(p []byte) (int, error) {
	n, err := t.w.Write(p)
	t.record(p[:n])
	return n, err
}

// record accumulates whole lines and logs them one at a time, so a traceback
// stays greppable instead of arriving as one blob.
func (t *stderrTee) record(p []byte) {
	if t.log == nil || len(p) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.truncated {
		return
	}

	t.partial = append(t.partial, p...)
	for {
		i := bytes.IndexByte(t.partial, '\n')
		if i < 0 {
			break
		}
		line := bytes.TrimRight(t.partial[:i], "\r")
		t.partial = t.partial[i+1:]
		if len(line) == 0 {
			continue
		}
		if t.recorded+len(line) > maxStderrRecorded {
			t.truncated = true
			t.log.Event("stderr-truncated", map[string]any{"after_bytes": t.recorded})
			return
		}
		t.recorded += len(line)
		t.log.Event("stderr", map[string]any{"line": string(line)})
	}
	// An unterminated tail is kept, but not without limit: a server writing a
	// megabyte with no newline must not grow this buffer forever.
	if len(t.partial) > maxStderrRecorded {
		t.partial = t.partial[:0]
	}
}

// flush records whatever the server wrote without a trailing newline, which is
// often the most interesting line: the one it died in the middle of.
func (t *stderrTee) flush() {
	if t.log == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	line := bytes.TrimRight(t.partial, "\r\n")
	t.partial = nil
	if len(line) > 0 && !t.truncated {
		t.log.Event("stderr", map[string]any{"line": string(line)})
	}
}

// pendingCall is a tools/call waiting for its answer, remembered so the answer
// can be attributed back to the tool that produced it.
type pendingCall struct {
	tool string
	at   time.Time
}

// guard holds everything the proxy knows that bears on a decision: which tools
// stopped matching their approval, whether the session has taken in untrusted
// content, and which call is waiting on which answer.
type guard struct {
	o       *Options
	session *mcp.Session
	notice  func(string, ...any)
	now     func() time.Time

	mu           sync.Mutex
	mismatched   map[string]string
	verifyErr    string
	pendingTools map[string]pendingCall
	tainted      bool
	announced    map[string]bool
	blocked      int
	relayed      int
}

func newGuard(o *Options, session *mcp.Session, notice func(string, ...any)) *guard {
	return &guard{
		o:            o,
		session:      session,
		notice:       notice,
		now:          time.Now,
		pendingTools: make(map[string]pendingCall),
		announced:    make(map[string]bool),
	}
}

// blocks reports whether an action is refused at the level in force.
func (g *guard) blocks(a policy.Action) bool { return g.o.Mode.Blocks(a) }

func (g *guard) enforcing() bool { return g.o.Mode.Enforcing() }

func (g *guard) isTainted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tainted
}

// counts returns how many calls were refused and how many verdicts fired
// without refusing, for the exit record.
func (g *guard) counts() (blocked, relayed int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.blocked, g.relayed
}

// expire drops call attributions older than ttl.
//
// Without it the map grows for the whole session on every reply a server never
// sends - the same leak the correlator has a sweeper for, one map to the side.
func (g *guard) expire(ttl time.Duration) int {
	if ttl <= 0 {
		return 0
	}
	cutoff := g.now().Add(-ttl)

	g.mu.Lock()
	defer g.mu.Unlock()
	var dropped int
	for key, p := range g.pendingTools {
		if p.at.Before(cutoff) {
			delete(g.pendingTools, key)
			dropped++
		}
	}
	return dropped
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
	g.mismatched, g.verifyErr = m, ""
}

// verifyTools checks the server's currently advertised tools against the lock.
func (g *guard) verifyTools(session *mcp.Session) {
	if g.o.Lock == nil {
		return
	}
	changes, err := g.o.Lock.Verify(session.Tools())
	if err != nil {
		// Leaving the old map in place makes the reasons stale in one
		// direction and clearing it silently makes them stale in the other.
		// "This could not be checked" is the only honest third answer, and it
		// carries a weaker action than "this changed".
		g.mu.Lock()
		g.mismatched, g.verifyErr = nil, err.Error()
		g.mu.Unlock()
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

// pinStatus reports why a call should not be trusted against the lock, and how
// strong the signal is.
//
// A tool that changed since approval is a deny: it fires only when something
// actually moved, it is precise, and the refusal names the cure. A tool that
// could not be checked at all is a confirm: "we do not know" is a much weaker
// claim than "it changed", and under enforcement its blast radius would be the
// whole server dying over one malformed schema.
func (g *guard) pinStatus(tool string) (reason string, action policy.Action, bad bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r, ok := g.mismatched[tool]; ok {
		return r, policy.Deny, true
	}
	if g.verifyErr != "" {
		return "the approved tool list could not be checked: " + g.verifyErr, policy.Confirm, true
	}
	return "", "", false
}

// handshakeDone records what each side said it could do.
//
// Nothing acts on this yet. It is the evidence needed to revisit protocol-native
// confirmation: elicitation/create can only be used if the client declared it,
// and today's logs are how that question gets answered with data.
func (g *guard) handshakeDone() {
	client, server := g.session.Capabilities()
	clientName, serverName := g.session.Peers()
	g.o.Log.Event("handshake", map[string]any{
		"protocol":            g.session.ProtocolVersion(),
		"client":              clientName.Name,
		"server":              serverName.Name,
		"client_capabilities": client.Names,
		"server_capabilities": server.Names,
		"elicitation":         g.session.ClientSupports("elicitation"),
	})
}

// answered is called when a reply arrives, so a result from a tool carrying
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
	pending, ok := g.pendingTools[key]
	delete(g.pendingTools, key)
	alreadyTainted := g.tainted
	bySource := ok && g.o.Policy.IsTaintSource(pending.tool)
	if bySource {
		g.tainted = true
	}
	g.mu.Unlock()

	if !ok {
		return
	}
	tool := pending.tool
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

// gateResult is what the gate concluded about one message.
type gateResult struct {
	refuse bool
	reason string
	// tool is set for a tools/call that is being let through, so the caller can
	// remember it once the whole frame has been judged.
	tool string
}

// gate decides whether a client-to-server frame should be refused, returning
// the reply to send back instead, or nil to let it through.
//
// Only tools/call is judged. Letting tools/list through is a deliberate trade:
// refusing it leaves the client with no tools and a visibly broken server,
// while the thing that does damage is the call.
func (g *guard) gate(frame []byte) []byte {
	if g.o.Lock == nil && g.o.Policy == nil {
		return nil
	}
	msgs, batched, err := mcp.ParseFrame(frame)
	if err != nil || len(msgs) == 0 {
		// Transparency wins over judgement here; the observer already records
		// the frame as unparseable.
		return nil
	}

	if !batched {
		res := g.inspect(msgs[0])
		if res.refuse {
			return g.refuse(msgs[0], res.reason)
		}
		if res.tool != "" {
			g.remember(msgs[0].ID, res.tool)
		}
		return nil
	}

	// A batch is judged whole, and nothing is recorded until every member has
	// been. Removing one member would leave a hole in the server's reply array
	// where the client is still waiting on an id, and stitching a synthetic
	// error into that reply is a whole rewriting machine for a protocol feature
	// dropped in revision 2025-06-18. Refusing the batch is well-formed.
	var refusal string
	results := make([]gateResult, 0, len(msgs))
	for _, m := range msgs {
		res := g.inspect(m)
		results = append(results, res)
		if res.refuse && refusal == "" {
			refusal = res.reason
		}
	}
	g.o.Log.Event("gate-batch", map[string]any{
		"messages": len(msgs),
		"refused":  refusal != "",
	})
	if refusal != "" {
		return g.refuseBatch(msgs, refusal)
	}
	for i, m := range msgs {
		if results[i].tool != "" {
			g.remember(m.ID, results[i].tool)
		}
	}
	return nil
}

// inspect judges one message. It records the verdict but never touches
// pendingTools: in a batch nothing may be remembered until the whole frame has
// been decided.
func (g *guard) inspect(m mcp.Message) gateResult {
	if m.Kind != mcp.KindRequest || m.Method != "tools/call" {
		return gateResult{}
	}
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(m.Params, &params) != nil || params.Name == "" {
		return gateResult{}
	}

	if reason, action, bad := g.pinStatus(params.Name); bad {
		blocked := g.blocks(action)
		g.o.Log.Event("pin-violation", map[string]any{
			"tool":    params.Name,
			"id":      m.ID.String(),
			"action":  string(action),
			"reason":  reason,
			"mode":    string(g.o.Mode),
			"blocked": blocked,
		})
		if blocked {
			g.countBlocked()
			return gateResult{refuse: true,
				reason: reason + ". Review it with: effectgate approve --diff -- <server command>"}
		}
		g.announce(params.Name, "pin", reason)
	}

	if g.o.Policy == nil {
		return gateResult{tool: params.Name}
	}
	v := g.o.Policy.Decide(policy.Call{Tool: params.Name, Args: params.Arguments}, g.isTainted())
	if v.Action == policy.Allow {
		return gateResult{tool: params.Name}
	}

	blocked := g.blocks(v.Action)
	g.o.Log.Event("policy-verdict", map[string]any{
		"tool":    params.Name,
		"id":      m.ID.String(),
		"action":  string(v.Action),
		"rule":    v.Rule,
		"paths":   v.Paths,
		"tainted": g.isTainted(),
		"mode":    string(g.o.Mode),
		"blocked": blocked,
	})
	if !blocked {
		g.announce(params.Name, v.Rule, v.Reason)
		return gateResult{tool: params.Name}
	}
	g.countBlocked()

	switch v.Action {
	case policy.Deny:
		return gateResult{refuse: true,
			reason: fmt.Sprintf("blocked by effectgate: %s (rule %q)", v.Reason, v.Rule)}
	default:
		return gateResult{refuse: true, reason: fmt.Sprintf(
			"held by effectgate for confirmation: %s (rule %q). "+
				"There is no way to ask you from here, so it was refused. "+
				"Allow it with a policy rule, or drop back to -enforce (deny only).",
			v.Reason, v.Rule)}
	}
}

// announce says on stderr that a verdict fired without stopping anything.
//
// Once per (tool, rule) per session. A log file read later is honest but not
// loud, and unbounded stderr is how a tool gets uninstalled; one line the first
// time a rule fires is the balance. Silent in observe mode, where everything is
// relayed and the notice would fire from the first minute.
func (g *guard) announce(tool, rule, reason string) {
	if !g.enforcing() || g.notice == nil {
		return
	}
	key := tool + "\x00" + rule
	g.mu.Lock()
	g.relayed++
	first := !g.announced[key]
	g.announced[key] = true
	g.mu.Unlock()
	if first {
		g.notice("allowed but noted: %s (rule %q)", reason, rule)
	}
}

func (g *guard) countBlocked() {
	g.mu.Lock()
	g.blocked++
	g.mu.Unlock()
}

func (g *guard) remember(id mcp.ID, tool string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pendingTools[string(mcp.ClientToServer)+"\x00"+id.Key()] = pendingCall{tool: tool, at: g.now()}
}

// refuse builds the reply that goes back instead of the result, and records it.
//
// A blocked call must still be answered, with the same id. Dropping it leaves
// the client waiting until it times out, with nothing to show for it and no
// idea why. The log entry is written before the reply goes out, so if the write
// then fails the record says "refused, and the client never got it".
func (g *guard) refuse(m mcp.Message, reason string) []byte {
	reply := mcp.NewError(m.ID, mcp.CodeBlocked, reason)
	g.o.Log.Record(string(mcp.ServerToClient), reply)
	g.session.ObserveRefusal(mcp.ClientToServer, m, reason)
	return reply
}

func (g *guard) refuseBatch(msgs []mcp.Message, reason string) []byte {
	ids := make([]mcp.ID, 0, len(msgs))
	for _, m := range msgs {
		if m.Kind == mcp.KindRequest {
			ids = append(ids, m.ID)
			g.session.ObserveRefusal(mcp.ClientToServer, m, reason)
		}
	}
	reply := mcp.NewErrorBatch(ids, mcp.CodeBlocked, reason)
	if reply != nil {
		g.o.Log.Record(string(mcp.ServerToClient), reply)
	}
	return reply
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
