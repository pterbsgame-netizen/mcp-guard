package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseFrameClassification(t *testing.T) {
	tests := []struct {
		name    string
		frame   string
		want    Kind
		id      string
		method  string
		wantErr bool
	}{
		{
			name:   "request",
			frame:  `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			want:   KindRequest,
			id:     "1",
			method: "tools/list",
		},
		{
			name:   "request with string id",
			frame:  `{"jsonrpc":"2.0","id":"abc","method":"tools/call"}`,
			want:   KindRequest,
			id:     `"abc"`,
			method: "tools/call",
		},
		{
			name:   "notification has no id",
			frame:  `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			want:   KindNotification,
			id:     "-",
			method: "notifications/initialized",
		},
		{
			name:   "explicit null id is still a notification",
			frame:  `{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled"}`,
			want:   KindNotification,
			id:     "-",
			method: "notifications/cancelled",
		},
		{
			name:  "response",
			frame: `{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`,
			want:  KindResponse,
			id:    "2",
		},
		{
			// Present-but-null must not be read as absent, or a valid response
			// gets classified as a malformed message and the caller hangs.
			name:  "response with null result",
			frame: `{"jsonrpc":"2.0","id":3,"result":null}`,
			want:  KindResponse,
			id:    "3",
		},
		{
			name:  "error response",
			frame: `{"jsonrpc":"2.0","id":4,"error":{"code":-32601,"message":"no such method"}}`,
			want:  KindError,
			id:    "4",
		},
		{
			name:    "neither method nor result nor error",
			frame:   `{"jsonrpc":"2.0","id":5}`,
			wantErr: true,
		},
		{
			name:    "id of the wrong type",
			frame:   `{"jsonrpc":"2.0","id":{"nested":true},"method":"x"}`,
			wantErr: true,
		},
		{
			name:    "not json at all",
			frame:   `npm warn: something`,
			wantErr: true,
		},
		{
			name:    "empty frame",
			frame:   `   `,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs, batched, err := ParseFrame([]byte(tt.frame))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseFrame(%s) = no error, want one", tt.frame)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFrame(%s): %v", tt.frame, err)
			}
			if batched {
				t.Errorf("batched = true, want false")
			}
			if len(msgs) != 1 {
				t.Fatalf("got %d messages, want 1", len(msgs))
			}
			m := msgs[0]
			if m.Kind != tt.want {
				t.Errorf("Kind = %v, want %v", m.Kind, tt.want)
			}
			if got := m.ID.String(); got != tt.id {
				t.Errorf("ID = %s, want %s", got, tt.id)
			}
			if m.Method != tt.method {
				t.Errorf("Method = %q, want %q", m.Method, tt.method)
			}
			if string(m.Raw) != strings.TrimSpace(tt.frame) {
				t.Errorf("Raw was not preserved verbatim:\n got %s\nwant %s", m.Raw, tt.frame)
			}
		})
	}
}

func TestParseFrameBatch(t *testing.T) {
	frame := `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","method":"notifications/initialized"}]`
	msgs, batched, err := ParseFrame([]byte(frame))
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if !batched {
		t.Error("batched = false, want true")
	}
	if len(msgs) != 2 {
		t.Fatalf("got %d messages, want 2", len(msgs))
	}
	if msgs[0].Kind != KindRequest || msgs[1].Kind != KindNotification {
		t.Errorf("kinds = %v, %v; want request, notification", msgs[0].Kind, msgs[1].Kind)
	}

	if _, _, err := ParseFrame([]byte(`[]`)); err != ErrBatchEmpty {
		t.Errorf("empty batch error = %v, want ErrBatchEmpty", err)
	}
}

// TestIDKeysAreTypeTagged guards the one way ids can quietly collide: a string
// id and a numeric id that print the same.
func TestIDKeysAreTypeTagged(t *testing.T) {
	num, _ := parseID(json.RawMessage(`1`))
	str, _ := parseID(json.RawMessage(`"1"`))
	if num.Key() == str.Key() {
		t.Errorf("id 1 and id \"1\" share key %q", num.Key())
	}
	if !num.Set() || !str.Set() {
		t.Error("both ids should report Set")
	}
}

// TestNewErrorEchoesID matters because a client that sent a string id and gets
// a number back may not match the reply at all, and then hangs until timeout —
// exactly the failure blocking is supposed to avoid.
func TestNewErrorEchoesID(t *testing.T) {
	for _, raw := range []string{`7`, `"7"`, `"a-b-c"`} {
		id, err := parseID(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("parseID(%s): %v", raw, err)
		}
		out := NewError(id, CodeBlocked, `blocked by policy: write to "~/.ssh"`)
		msgs, _, err := ParseFrame(out)
		if err != nil {
			t.Fatalf("NewError produced an unparseable frame %s: %v", out, err)
		}
		m := msgs[0]
		if m.Kind != KindError {
			t.Errorf("Kind = %v, want error", m.Kind)
		}
		if string(m.ID.Raw()) != raw {
			t.Errorf("id echoed as %s, want %s", m.ID.Raw(), raw)
		}
		if m.Error == nil || m.Error.Code != CodeBlocked {
			t.Errorf("error object = %+v, want code %d", m.Error, CodeBlocked)
		}
	}

	// A message we could not parse has no id to echo; null is the spec's answer.
	out := NewError(ID{}, CodeParseError, "unparseable")
	if !strings.Contains(string(out), `"id":null`) {
		t.Errorf("absent id should serialise as null, got %s", out)
	}
}

// TestNewErrorBatch: a client that sent an array and gets back a bare object
// cannot match the reply to anything, which hangs it exactly as dropping the
// message would.
func TestNewErrorBatch(t *testing.T) {
	ids := make([]ID, 0, 3)
	for _, raw := range []string{`1`, `"two"`, `3`} {
		id, err := parseID(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("parseID(%s): %v", raw, err)
		}
		ids = append(ids, id)
	}

	out := NewErrorBatch(ids, CodeBlocked, "refused")
	msgs, batched, err := ParseFrame(out)
	if err != nil {
		t.Fatalf("NewErrorBatch produced an unparseable frame %s: %v", out, err)
	}
	if !batched {
		t.Error("the reply to a batch must itself be a batch")
	}
	if len(msgs) != len(ids) {
		t.Fatalf("got %d replies, want %d", len(msgs), len(ids))
	}
	for i, m := range msgs {
		if m.Kind != KindError {
			t.Errorf("reply %d is %v, want an error", i, m.Kind)
		}
		if string(m.ID.Raw()) != string(ids[i].Raw()) {
			t.Errorf("reply %d has id %s, want %s (order must be preserved)", i, m.ID.Raw(), ids[i].Raw())
		}
	}

	// A batch of pure notifications is owed no reply at all.
	if out := NewErrorBatch(nil, CodeBlocked, "refused"); out != nil {
		t.Errorf("an empty id list produced %q, want nothing", out)
	}
}
