// Package mcp parses the JSON-RPC 2.0 messages that MCP is built on.
//
// It deliberately does not model MCP semantics — no tool registry, no
// capability negotiation, no schema validation. Its job is to tell requests,
// responses and notifications apart, in both directions, while keeping the
// original bytes intact for everything downstream.
package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Kind classifies a JSON-RPC message.
type Kind uint8

const (
	KindInvalid Kind = iota
	KindRequest
	KindNotification
	KindResponse
	KindError
)

func (k Kind) String() string {
	switch k {
	case KindRequest:
		return "request"
	case KindNotification:
		return "notification"
	case KindResponse:
		return "response"
	case KindError:
		return "error"
	default:
		return "invalid"
	}
}

// ID is a JSON-RPC request id: a string or a number, per the spec, and absent
// on notifications.
//
// The original bytes are kept so a synthesised reply can echo the id exactly as
// it arrived. A client that sent "id":"7" must not get back "id":7 — some
// clients match strictly, and a mismatch means the caller hangs until timeout.
type ID struct {
	raw json.RawMessage
	key string
}

// Set reports whether an id was present. Notifications have none.
func (i ID) Set() bool { return len(i.raw) > 0 }

// Raw returns the id exactly as it appeared on the wire.
func (i ID) Raw() json.RawMessage { return i.raw }

// Key is the canonical correlation key. It is type-tagged, so the string id
// "1" and the number 1 never collide.
func (i ID) Key() string { return i.key }

func (i ID) String() string {
	if !i.Set() {
		return "-"
	}
	return string(i.raw)
}

func parseID(raw json.RawMessage) (ID, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return ID{}, nil
	}
	var s string
	if err := json.Unmarshal(trimmed, &s); err == nil {
		return ID{raw: trimmed, key: "s:" + s}, nil
	}
	var n json.Number
	if err := json.Unmarshal(trimmed, &n); err == nil {
		// json.Number keeps the literal text, so 1 and 1.0 stay distinct. That
		// is the honest behaviour: they are different bytes on the wire and we
		// cannot know which form the peer will echo back.
		return ID{raw: trimmed, key: "n:" + n.String()}, nil
	}
	return ID{}, fmt.Errorf("id must be a string or a number, got %s", trimmed)
}

// Error is the error object of a JSON-RPC error response.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Message is one parsed JSON-RPC message.
type Message struct {
	// Raw is the message exactly as it arrived, and is what gets relayed and
	// hashed. Nothing downstream should re-marshal a Message to reproduce it.
	Raw json.RawMessage

	Kind   Kind
	ID     ID
	Method string
	Params json.RawMessage
	Result json.RawMessage
	Error  *Error
}

// ErrBatchEmpty is returned for a top-level array with no messages in it, which
// the JSON-RPC spec calls an invalid request.
var ErrBatchEmpty = errors.New("mcp: empty batch")

// ParseFrame parses one newline-delimited frame.
//
// A frame is normally a single message, but protocol revision 2025-03-26 also
// allowed a batch: a top-level array. Revision 2025-06-18 removed it. Both are
// accepted here because old servers are still in circulation, and batched is
// reported so a caller can reply in the shape it was asked.
func ParseFrame(frame []byte) (msgs []Message, batched bool, err error) {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 {
		return nil, false, errors.New("mcp: empty frame")
	}

	if trimmed[0] != '[' {
		m, err := parseOne(trimmed)
		if err != nil {
			return nil, false, err
		}
		return []Message{m}, false, nil
	}

	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return nil, true, fmt.Errorf("mcp: batch: %w", err)
	}
	if len(items) == 0 {
		return nil, true, ErrBatchEmpty
	}
	msgs = make([]Message, 0, len(items))
	for i, item := range items {
		m, err := parseOne(bytes.TrimSpace(item))
		if err != nil {
			return nil, true, fmt.Errorf("mcp: batch item %d: %w", i, err)
		}
		msgs = append(msgs, m)
	}
	return msgs, true, nil
}

// parseOne decodes into a field map rather than a struct, because what
// classifies a JSON-RPC message is which fields are *present*, and a struct
// cannot express that.
//
// A pointer field does not work either: encoding/json unmarshals the literal
// null by setting the pointer to nil, so `{"result":null}` — a perfectly valid
// response to a call that returns nothing — becomes indistinguishable from a
// message with no result at all. Classified as malformed, its caller waits for
// an answer that already arrived.
func parseOne(raw json.RawMessage) (Message, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return Message{}, fmt.Errorf("mcp: %w", err)
	}
	if fields == nil {
		return Message{}, errors.New("mcp: message is not a JSON object")
	}

	m := Message{Raw: raw, Params: fields["params"], Result: fields["result"]}

	if idRaw, ok := fields["id"]; ok {
		id, err := parseID(idRaw)
		if err != nil {
			return Message{}, fmt.Errorf("mcp: %w", err)
		}
		m.ID = id
	}

	methodRaw, hasMethod := fields["method"]
	if hasMethod {
		if err := json.Unmarshal(methodRaw, &m.Method); err != nil {
			return Message{}, fmt.Errorf("mcp: method must be a string: %w", err)
		}
	}

	if errRaw, ok := fields["error"]; ok && !isJSONNull(errRaw) {
		var e Error
		if err := json.Unmarshal(errRaw, &e); err != nil {
			return Message{}, fmt.Errorf("mcp: error object: %w", err)
		}
		m.Error = &e
	}
	_, hasResult := fields["result"]

	switch {
	case hasMethod && m.ID.Set():
		m.Kind = KindRequest
	case hasMethod:
		// No id, or an explicit null id, which the spec treats the same way.
		m.Kind = KindNotification
	case m.Error != nil:
		m.Kind = KindError
	case hasResult:
		m.Kind = KindResponse
	default:
		m.Kind = KindInvalid
		return m, errors.New("mcp: message has neither method, result nor error")
	}
	return m, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// NewError builds an error response for id, ready to be written to the wire.
//
// This is what makes blocking safe: a dropped message leaves the peer waiting
// until it times out, with nothing to show the user. A blocked message must
// always be answered, with the same id and a reason a human can read.
//
// It cannot fail. Marshalling a Go string is infallible, and the caller of a
// refusal has no useful way to handle an error anyway — the one thing it must
// never do is fall back to letting the message through.
func NewError(id ID, code int, message string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"jsonrpc":"2.0","id":`)
	b.Write(idOrNull(id))
	fmt.Fprintf(&b, `,"error":{"code":%d,"message":`, code)
	b.Write(quote(message))
	b.WriteString("}}\n")
	return b.Bytes()
}

// NewErrorBatch answers a batched frame with a batched reply: one error per
// request id, in the order they arrived.
//
// A batch has to be answered with an array. A client that sent one and got back
// a bare object has no way to match the reply to anything, which is the same
// hang as sending nothing at all. Returns nil for an empty list, since a batch
// of pure notifications is owed no reply.
func NewErrorBatch(ids []ID, code int, message string) []byte {
	if len(ids) == 0 {
		return nil
	}
	var b bytes.Buffer
	b.WriteByte('[')
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"jsonrpc":"2.0","id":`)
		b.Write(idOrNull(id))
		fmt.Fprintf(&b, `,"error":{"code":%d,"message":`, code)
		b.Write(quote(message))
		b.WriteString("}}")
	}
	b.WriteString("]\n")
	return b.Bytes()
}

func idOrNull(id ID) json.RawMessage {
	if !id.Set() {
		return json.RawMessage("null")
	}
	return id.Raw()
}

// quote renders a string as a JSON string, substituting a fixed message in the
// case json.Marshal is documented not to reach.
func quote(s string) []byte {
	enc, err := json.Marshal(s)
	if err != nil {
		return []byte(`"blocked by effectgate"`)
	}
	return enc
}

// JSON-RPC reserved error codes, plus the range MCP leaves to applications.
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// CodeBlocked is ours, inside the implementation-defined range. It marks a
	// call refused by policy rather than one that failed.
	CodeBlocked = -32000
)
