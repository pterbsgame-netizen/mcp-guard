package mcp

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, frame string) Message {
	t.Helper()
	msgs, _, err := ParseFrame([]byte(frame))
	if err != nil {
		t.Fatalf("ParseFrame(%s): %v", frame, err)
	}
	return msgs[0]
}

// TestLiveTrace replays a session captured from a real Claude Desktop run. It
// is the reason the correlation key is (direction, id): the client's initialize
// and the server's roots/list both used id 0, and the server interleaved its
// own request inside the client's outstanding tools/list.
func TestLiveTrace(t *testing.T) {
	c := NewCorrelator(time.Minute)

	// seq=2  c2s  id=0  initialize
	initialize := mustParse(t, `{"jsonrpc":"2.0","id":0,"method":"initialize"}`)
	if _, collision := c.Track(ClientToServer, initialize); collision {
		t.Fatal("unexpected collision tracking initialize")
	}

	// seq=3  s2c  id=0  result
	p, ok := c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":0,"result":{}}`))
	if !ok {
		t.Fatal("initialize response did not match its request")
	}
	if p.Method != "initialize" {
		t.Errorf("matched %q, want initialize", p.Method)
	}

	// seq=5  c2s  id=1  tools/list — stays outstanding for the rest of the test
	c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))

	// seq=6  s2c  id=0  roots/list — the server asks the client something, and
	// reuses id 0, which the client already used for initialize.
	rootsList := mustParse(t, `{"jsonrpc":"2.0","id":0,"method":"roots/list"}`)
	if _, collision := c.Track(ServerToClient, rootsList); collision {
		t.Error("roots/list id 0 collided with the client's id 0: the two directions share a key")
	}
	if n := c.InFlight(); n != 2 {
		t.Fatalf("in flight = %d, want 2 (tools/list and roots/list)", n)
	}

	// seq=7  c2s  id=0  result — the client answers roots/list. This must match
	// the server's request, not the client's own long-finished initialize.
	p, ok = c.Match(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":0,"result":{"roots":[]}}`))
	if !ok {
		t.Fatal("roots/list response did not match its request")
	}
	if p.Method != "roots/list" {
		t.Errorf("matched %q, want roots/list", p.Method)
	}
	if p.Dir != ServerToClient {
		t.Errorf("matched a request that travelled %s, want %s", p.Dir, ServerToClient)
	}

	// seq=8  s2c  id=1  result — and only now the answer to tools/list.
	p, ok = c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	if !ok {
		t.Fatal("tools/list response did not match its request")
	}
	if p.Method != "tools/list" {
		t.Errorf("matched %q, want tools/list", p.Method)
	}
	if n := c.InFlight(); n != 0 {
		t.Errorf("in flight = %d, want 0", n)
	}
}

// TestOutOfOrderResponses: a server answered id 3 before id 2 on real traffic,
// so nothing may depend on replies arriving in the order requests were sent.
func TestOutOfOrderResponses(t *testing.T) {
	c := NewCorrelator(time.Minute)
	c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":2,"method":"read_a"}`))
	c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":3,"method":"read_b"}`))

	if p, ok := c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":3,"result":{}}`)); !ok || p.Method != "read_b" {
		t.Errorf("id 3 matched %q (ok=%v), want read_b", p.Method, ok)
	}
	if p, ok := c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":2,"result":{}}`)); !ok || p.Method != "read_a" {
		t.Errorf("id 2 matched %q (ok=%v), want read_a", p.Method, ok)
	}
}

func TestMatchIgnoresUnrelated(t *testing.T) {
	c := NewCorrelator(time.Minute)

	// A response nobody asked for.
	if _, ok := c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":99,"result":{}}`)); ok {
		t.Error("matched a response with no outstanding request")
	}
	// Notifications are neither tracked nor matched.
	notif := mustParse(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	c.Track(ClientToServer, notif)
	if n := c.InFlight(); n != 0 {
		t.Errorf("in flight = %d after tracking a notification, want 0", n)
	}
	// An error with a null id: the peer could not tell what it was answering.
	if _, ok := c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}`)); ok {
		t.Error("matched an error with a null id")
	}
}

func TestTrackReportsIDReuse(t *testing.T) {
	c := NewCorrelator(time.Minute)
	c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"first"}`))
	displaced, collision := c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"second"}`))
	if !collision {
		t.Fatal("reusing an in-flight id was not reported")
	}
	if displaced.Method != "first" {
		t.Errorf("displaced %q, want first", displaced.Method)
	}
	// The newer request wins: that is the one the peer will answer.
	if p, ok := c.Match(ServerToClient, mustParse(t, `{"jsonrpc":"2.0","id":1,"result":{}}`)); !ok || p.Method != "second" {
		t.Errorf("matched %q (ok=%v), want second", p.Method, ok)
	}
}

// TestExpire covers the leak: without it, every reply a server never sends
// leaves an entry in the map for the lifetime of the session.
func TestExpire(t *testing.T) {
	clock := time.Unix(1000, 0)
	c := NewCorrelator(30 * time.Second)
	c.now = func() time.Time { return clock }

	c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"old"}`))
	clock = clock.Add(20 * time.Second)
	c.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":2,"method":"newer"}`))

	if stale := c.Expire(); len(stale) != 0 {
		t.Fatalf("expired %d requests too early: %+v", len(stale), stale)
	}

	clock = clock.Add(15 * time.Second) // "old" is now 35s, "newer" is 15s
	stale := c.Expire()
	if len(stale) != 1 {
		t.Fatalf("expired %d requests, want 1", len(stale))
	}
	if stale[0].Method != "old" {
		t.Errorf("expired %q, want old", stale[0].Method)
	}
	if n := c.InFlight(); n != 1 {
		t.Errorf("in flight = %d, want 1", n)
	}

	// A ttl of zero means never expire.
	never := NewCorrelator(0)
	never.Track(ClientToServer, mustParse(t, `{"jsonrpc":"2.0","id":1,"method":"forever"}`))
	if stale := never.Expire(); stale != nil {
		t.Errorf("ttl=0 expired %+v, want nothing", stale)
	}
}
