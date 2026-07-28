package mcp

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// Party identifies one end of the connection.
type Party struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool is one entry from a tools/list result.
//
// Name, Description and InputSchema are exactly the three things stage 2 pins:
// a server that swaps a tool's description or widens its schema after approval
// is the MCPoison pattern, and it is invisible unless these are recorded.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// Call is one tools/call, from request to reply.
type Call struct {
	Tool      string
	ID        string
	Started   time.Time
	Finished  time.Time
	Done      bool
	IsError   bool
	Arguments json.RawMessage

	// Blocked marks a call the proxy answered itself. The server never saw it.
	Blocked     bool
	BlockReason string
}

// Capabilities is what a peer declared it can do during the handshake.
//
// The raw object is kept so a protocol revision that adds something is recorded
// rather than dropped; Names is the sorted top-level keys, which is all any
// caller has wanted so far.
type Capabilities struct {
	Raw   json.RawMessage `json:"-"`
	Names []string        `json:"names"`
}

func newCapabilities(raw json.RawMessage) Capabilities {
	c := Capabilities{Raw: raw}
	var fields map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &fields) != nil {
		return c
	}
	c.Names = make([]string, 0, len(fields))
	for k := range fields {
		c.Names = append(c.Names, k)
	}
	sort.Strings(c.Names)
	return c
}

// Session accumulates what the proxy has learned about one connection by
// watching it go past. It never asks the server anything of its own.
type Session struct {
	mu sync.Mutex

	protocolVersion string
	client          Party
	server          Party
	clientCaps      Capabilities
	serverCaps      Capabilities
	tools           []Tool
	calls           []Call
	callIndex       map[string]int // correlation key -> index into calls
}

// NewSession returns an empty session.
func NewSession() *Session {
	return &Session{callIndex: make(map[string]int)}
}

// Observe folds one message into the session. matched is the request a response
// answers, as resolved by a Correlator, and is nil for anything else.
//
// Parse failures are ignored rather than reported: this is bookkeeping, and a
// server that sends something unexpected must not affect whether traffic flows.
func (s *Session) Observe(dir Direction, m Message, matched *Pending) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case m.Kind == KindRequest && m.Method == "initialize":
		var p struct {
			ProtocolVersion string          `json:"protocolVersion"`
			ClientInfo      Party           `json:"clientInfo"`
			Capabilities    json.RawMessage `json:"capabilities"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.protocolVersion = p.ProtocolVersion
			s.client = p.ClientInfo
			s.clientCaps = newCapabilities(p.Capabilities)
		}

	case m.Kind == KindRequest && m.Method == "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(m.Params, &p) != nil {
			return
		}
		s.callIndex[pendingKey(dir, m.ID)] = len(s.calls)
		s.calls = append(s.calls, Call{
			Tool:      p.Name,
			ID:        m.ID.String(),
			Started:   time.Now(),
			Arguments: p.Arguments,
		})

	case (m.Kind == KindResponse || m.Kind == KindError) && matched != nil:
		switch matched.Method {
		case "initialize":
			var r struct {
				ProtocolVersion string          `json:"protocolVersion"`
				ServerInfo      Party           `json:"serverInfo"`
				Capabilities    json.RawMessage `json:"capabilities"`
			}
			if json.Unmarshal(m.Result, &r) == nil {
				s.serverCaps = newCapabilities(r.Capabilities)
				// The server's answer is authoritative: it may downgrade to a
				// revision the client did not ask for.
				if r.ProtocolVersion != "" {
					s.protocolVersion = r.ProtocolVersion
				}
				s.server = r.ServerInfo
			}
		case "tools/list":
			var r struct {
				Tools []Tool `json:"tools"`
			}
			if json.Unmarshal(m.Result, &r) == nil && r.Tools != nil {
				s.tools = r.Tools
			}
		case "tools/call":
			key := pendingKey(dir.Opposite(), m.ID)
			i, ok := s.callIndex[key]
			if !ok {
				return
			}
			delete(s.callIndex, key)
			s.calls[i].Done = true
			s.calls[i].Finished = time.Now()
			// A failed tool call is reported two ways: as a JSON-RPC error, or
			// as a normal result carrying isError. Both count as failure.
			s.calls[i].IsError = m.Kind == KindError
			var r struct {
				IsError bool `json:"isError"`
			}
			if json.Unmarshal(m.Result, &r) == nil && r.IsError {
				s.calls[i].IsError = true
			}
		}
	}
}

// ProtocolVersion is the negotiated revision, empty until initialize completes.
func (s *Session) ProtocolVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.protocolVersion
}

// Peers returns the client and server identities from the handshake.
func (s *Session) Peers() (client, server Party) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client, s.server
}

// Capabilities returns what each side declared during the handshake.
func (s *Session) Capabilities() (client, server Capabilities) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientCaps, s.serverCaps
}

// ClientSupports reports whether the client declared a capability.
//
// This is the question protocol-native confirmation has to ask before it can
// exist: elicitation/create is the right way to hold a call until the user
// answers, and it is only available if the client says so here.
func (s *Session) ClientSupports(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.clientCaps.Names {
		if n == name {
			return true
		}
	}
	return false
}

// ObserveRefusal folds in a call the proxy answered itself: the request that
// was made, and why a result never came from the server.
//
// The correlator is deliberately not involved. No answer is coming, so an entry
// there could only ever expire into a false "unanswered" - and the transcript
// would otherwise omit the call entirely, which is the one moment it most needs
// to be in there.
func (s *Session) ObserveRefusal(dir Direction, request Message, reason string) {
	if request.Kind != KindRequest || request.Method != "tools/call" {
		return
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(request.Params, &p) != nil {
		return
	}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, Call{
		Tool:        p.Name,
		ID:          request.ID.String(),
		Started:     now,
		Finished:    now,
		Done:        true,
		IsError:     true,
		Blocked:     true,
		BlockReason: reason,
		Arguments:   p.Arguments,
	})
}

// Tools returns the tools most recently advertised by the server.
func (s *Session) Tools() []Tool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Tool(nil), s.tools...)
}

// Calls returns the tools/call history in the order the calls were made.
func (s *Session) Calls() []Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Call(nil), s.calls...)
}
