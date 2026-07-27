package mcp

import (
	"encoding/json"
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
}

// Session accumulates what the proxy has learned about one connection by
// watching it go past. It never asks the server anything of its own.
type Session struct {
	mu sync.Mutex

	protocolVersion string
	client          Party
	server          Party
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
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      Party  `json:"clientInfo"`
		}
		if json.Unmarshal(m.Params, &p) == nil {
			s.protocolVersion = p.ProtocolVersion
			s.client = p.ClientInfo
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
				ProtocolVersion string `json:"protocolVersion"`
				ServerInfo      Party  `json:"serverInfo"`
			}
			if json.Unmarshal(m.Result, &r) == nil {
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
