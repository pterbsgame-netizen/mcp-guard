package proxy

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pterbsgame-netizen/effectgate/internal/mcp"
	"github.com/pterbsgame-netizen/effectgate/internal/pin"
	"github.com/pterbsgame-netizen/effectgate/internal/policy"
)

func testGuard(t *testing.T, o Options) *guard {
	t.Helper()
	o.setDefaults()
	return newGuard(&o, mcp.NewSession(), func(string, ...any) {})
}

func callFrame(id int, tool, path string) []byte {
	args, _ := json.Marshal(map[string]any{"path": path})
	body, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": json.RawMessage(args)},
	})
	return append(body, '\n')
}

// TestRefusedCallLeavesNoAttribution: the attribution exists so a reply can be
// credited to the tool that asked for it. A refused call has no reply coming,
// so recording one is a leak that grows for the whole session.
func TestRefusedCallLeavesNoAttribution(t *testing.T) {
	g := testGuard(t, Options{Policy: policy.Default(), Mode: policy.Enforce})

	if reply := g.gate(callFrame(1, "write_file", "~/.ssh/authorized_keys")); reply == nil {
		t.Fatal("a write to ~/.ssh was not refused")
	}
	if n := len(g.pendingTools); n != 0 {
		t.Errorf("a refused call left %d attribution(s) behind: %+v", n, g.pendingTools)
	}

	// A call that goes through is remembered, because its answer is coming.
	if reply := g.gate(callFrame(2, "read_text_file", "~/dev/notes.txt")); reply != nil {
		t.Fatalf("an ordinary read was refused: %s", reply)
	}
	if n := len(g.pendingTools); n != 1 {
		t.Errorf("a relayed call left %d attribution(s), want 1", n)
	}
}

// TestAttributionsExpire covers the other half of the same leak: a reply the
// server never sends. The correlator has a sweeper for exactly this; the
// guard's map needs one too, or it grows until the session ends.
func TestAttributionsExpire(t *testing.T) {
	clock := time.Unix(1000, 0)
	g := testGuard(t, Options{Policy: policy.Default(), Mode: policy.Enforce})
	g.now = func() time.Time { return clock }

	g.gate(callFrame(1, "read_text_file", "~/dev/a.txt"))
	clock = clock.Add(20 * time.Second)
	g.gate(callFrame(2, "read_text_file", "~/dev/b.txt"))

	if dropped := g.expire(30 * time.Second); dropped != 0 {
		t.Fatalf("expired %d attributions too early", dropped)
	}
	clock = clock.Add(15 * time.Second) // the first is now 35s old, the second 15s
	if dropped := g.expire(30 * time.Second); dropped != 1 {
		t.Errorf("expired %d, want 1", dropped)
	}
	if n := len(g.pendingTools); n != 1 {
		t.Errorf("%d attributions left, want 1", n)
	}
	if g.expire(0) != 0 {
		t.Error("a ttl of zero must expire nothing")
	}
}

// TestVerifyErrorClearsStaleMismatches: "we could not check" must not be
// reported using yesterday's answers, and it is a weaker claim than "it
// changed" — so it holds only at strict.
func TestVerifyErrorClearsStaleMismatches(t *testing.T) {
	// A lock whose stored schema is fine, against a server advertising one
	// canon rejects: duplicate keys, which no parser agrees how to resolve.
	lock, err := pin.New(pin.Server{Command: "x"}, []mcp.Tool{{
		Name:        "read_text_file",
		Description: "Read a file.",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}})
	if err != nil {
		t.Fatalf("pin.New: %v", err)
	}

	session := mcp.NewSession()
	g := newGuard(&Options{Lock: lock, Mode: policy.Enforce}, session, func(string, ...any) {})
	g.o.setDefaults()

	// Seed a real mismatch, the way a first tools/list would.
	g.setPinMismatches([]pin.Change{{Kind: pin.ToolChanged, Tool: "read_text_file", Fields: []string{"description"}}})
	if _, _, bad := g.pinStatus("read_text_file"); !bad {
		t.Fatal("the seeded mismatch was not recorded")
	}

	// Now a tools/list the checker cannot make sense of at all.
	broken := &brokenLock{}
	g.o.Lock = broken.lock(t)
	g.verifyTools(sessionAdvertising(t, `{"type":"object","a":1,"a":2}`))

	if len(g.mismatched) != 0 {
		t.Errorf("stale mismatches survived a failed check: %+v", g.mismatched)
	}
	reason, action, bad := g.pinStatus("read_text_file")
	if !bad {
		t.Fatal("a failed check reported nothing at all")
	}
	if action != policy.Confirm {
		t.Errorf("action = %q, want confirm: not knowing is weaker than knowing it changed", action)
	}
	if reason == "" {
		t.Error("the reason was empty")
	}

	// Confirm-class, so it is relayed at enforce and held at strict.
	if g.blocks(action) {
		t.Error("an unverifiable tool list blocked at the ordinary level")
	}
	g.o.Mode = policy.Strict
	if !g.blocks(action) {
		t.Error("an unverifiable tool list was not held at strict")
	}
}

// brokenLock builds a lock that verifies against nothing usable.
type brokenLock struct{}

func (brokenLock) lock(t *testing.T) *pin.Lock {
	t.Helper()
	l, err := pin.New(pin.Server{Command: "x"}, nil)
	if err != nil {
		t.Fatalf("pin.New: %v", err)
	}
	return l
}

func sessionAdvertising(t *testing.T, schema string) *mcp.Session {
	t.Helper()
	s := mcp.NewSession()
	frame := []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_text_file",` +
		`"description":"Read a file.","inputSchema":` + schema + `}]}}`)
	msgs, _, err := mcp.ParseFrame(frame)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	s.Observe(mcp.ServerToClient, msgs[0], &mcp.Pending{Method: "tools/list"})
	return s
}

// TestBatchIsGated closes a bypass: a batched frame used to skip the gate
// entirely. Batching left the protocol in revision 2025-06-18, but a hole is a
// hole.
func TestBatchIsGated(t *testing.T) {
	g := testGuard(t, Options{Policy: policy.Default(), Mode: policy.Enforce})

	batch := []byte(`[` +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"~/dev/a.txt"}}},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.ssh/authorized_keys"}}}` +
		`]` + "\n")

	reply := g.gate(batch)
	if reply == nil {
		t.Fatal("a batch containing a denied call was relayed")
	}
	msgs, batched, err := mcp.ParseFrame(reply)
	if err != nil {
		t.Fatalf("the refusal is not a parseable frame %s: %v", reply, err)
	}
	if !batched {
		t.Error("a batch must be answered with a batch, or the client cannot match the reply")
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d replies, want one per request", len(msgs))
	}
	for i, m := range msgs {
		if m.Kind != mcp.KindError || m.Error.Code != mcp.CodeBlocked {
			t.Errorf("reply %d = %v, want a blocked error", i, m.Kind)
		}
	}
	if n := len(g.pendingTools); n != 0 {
		t.Errorf("a refused batch remembered %d call(s)", n)
	}
}

// TestBatchWithNothingToRefuseIsRelayed is the transparency half: an innocent
// batch must pass untouched, and both its calls must still be attributed so
// their results can taint the session.
func TestBatchWithNothingToRefuseIsRelayed(t *testing.T) {
	g := testGuard(t, Options{Policy: policy.Default(), Mode: policy.Enforce})

	batch := []byte(`[` +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"~/dev/a.txt"}}},` +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com"}}}` +
		`]` + "\n")

	if reply := g.gate(batch); reply != nil {
		t.Fatalf("an innocent batch was refused: %s", reply)
	}
	if n := len(g.pendingTools); n != 2 {
		t.Errorf("remembered %d of 2 batched calls; the rest can never taint the session", n)
	}
}

// TestObserveGateIsInert: at the default level the gate judges and records but
// never returns a reply.
func TestObserveGateIsInert(t *testing.T) {
	g := testGuard(t, Options{Policy: policy.Default()})
	if reply := g.gate(callFrame(1, "write_file", "~/.ssh/authorized_keys")); reply != nil {
		t.Errorf("observe mode refused a call: %s", reply)
	}
	if blocked, _ := g.counts(); blocked != 0 {
		t.Errorf("observe mode counted %d blocks", blocked)
	}
}
