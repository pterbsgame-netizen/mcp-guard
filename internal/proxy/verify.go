package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/pterbsgame-netizen/mcp-guard/internal/mcp"
	"github.com/pterbsgame-netizen/mcp-guard/internal/pin"
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

// pinState remembers which tools stopped matching what was approved.
//
// It is written when a tools/list answer comes back and read when a call goes
// out, from two different goroutines.
type pinState struct {
	mu      sync.Mutex
	reasons map[string]string
}

func (p *pinState) set(changes []pin.Change) {
	reasons := make(map[string]string, len(changes))
	for _, c := range changes {
		switch c.Kind {
		case pin.ToolChanged:
			reasons[c.Tool] = fmt.Sprintf("tool %q changed since it was approved (%s)",
				c.Tool, strings.Join(c.Fields, ", "))
		case pin.ToolAdded:
			reasons[c.Tool] = fmt.Sprintf("tool %q was not present when this server was approved", c.Tool)
		}
		// A removed tool needs no entry: it cannot be called.
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reasons = reasons
}

func (p *pinState) reason(tool string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.reasons[tool]
	return r, ok
}

// verify checks the server's currently advertised tools against the lock.
func (o *Options) verify(session *mcp.Session, pins *pinState) {
	if o.Lock == nil {
		return
	}
	changes, err := o.Lock.Verify(session.Tools())
	if err != nil {
		o.Log.Event("pin-error", map[string]any{"err": err.Error()})
		return
	}
	pins.set(changes)
	for _, c := range changes {
		o.Log.Event("pin-mismatch", map[string]any{
			"kind":   string(c.Kind),
			"tool":   c.Tool,
			"fields": c.Fields,
		})
	}
}

// deny decides whether a client-to-server frame should be refused, returning
// the reply to send back to the client instead, or nil to let it through.
//
// Only tools/call is gated. Letting tools/list itself through is a deliberate
// trade: refusing it leaves the client with no tools at all and a broken
// server, while the thing that actually does damage is the call. It does mean a
// poisoned description reaches the model before the call is refused, which is
// the honest limit of pinning as a control.
func (o *Options) deny(pins *pinState) func([]byte) []byte {
	if o.Lock == nil {
		return nil
	}
	return func(frame []byte) []byte {
		msgs, batched, err := mcp.ParseFrame(frame)
		if err != nil || batched || len(msgs) != 1 {
			// A batch would need a batched reply to stay well-formed. Rather
			// than answer badly, let it through and record it.
			if batched {
				o.Log.Event("pin-skipped-batch", nil)
			}
			return nil
		}
		m := msgs[0]
		if m.Kind != mcp.KindRequest || m.Method != "tools/call" {
			return nil
		}
		var params struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(m.Params, &params) != nil || params.Name == "" {
			return nil
		}
		reason, mismatched := pins.reason(params.Name)
		if !mismatched {
			return nil
		}

		o.Log.Event("pin-violation", map[string]any{
			"tool":    params.Name,
			"id":      m.ID.String(),
			"reason":  reason,
			"blocked": o.Enforce,
		})
		if !o.Enforce {
			return nil
		}

		// A blocked call must still be answered, with the same id. Dropping it
		// leaves the client waiting until it times out, with nothing to show
		// for it and no idea why.
		reply, err := mcp.NewError(m.ID, mcp.CodeBlocked,
			reason+". Review it with: mcp-guard approve --diff -- <server command>")
		if err != nil {
			return nil
		}
		return reply
	}
}
