package mcp

import (
	"sync"
	"time"
)

// Direction is which way a message travelled.
type Direction string

const (
	ClientToServer Direction = "c2s"
	ServerToClient Direction = "s2c"
)

// Opposite returns the direction a reply travels in.
func (d Direction) Opposite() Direction {
	if d == ClientToServer {
		return ServerToClient
	}
	return ClientToServer
}

// Pending is a request that has been sent and not yet answered.
type Pending struct {
	Dir    Direction // direction the request itself travelled
	ID     ID
	Method string
	Sent   time.Time
}

// Correlator matches responses back to the requests that caused them.
//
// Keys are (direction, id), never id alone. Request id spaces belong to the
// peer that allocates them, so both sides can and do use the same numbers at
// the same time — observed on real traffic, where a client's initialize and a
// server's roots/list were both id 0 within one session. Keying on id alone
// silently mismatches the two, which at stage 3 means applying a policy verdict
// to the wrong call.
type Correlator struct {
	mu      sync.Mutex
	pending map[string]Pending
	ttl     time.Duration

	// now is injectable so expiry can be tested without sleeping.
	now func() time.Time
}

// NewCorrelator returns a Correlator that forgets unanswered requests after
// ttl. A ttl of zero disables expiry.
func NewCorrelator(ttl time.Duration) *Correlator {
	return &Correlator{
		pending: make(map[string]Pending),
		ttl:     ttl,
		now:     time.Now,
	}
}

func pendingKey(dir Direction, id ID) string {
	return string(dir) + "\x00" + id.Key()
}

// Track records an outgoing request. Notifications, responses and errors are
// ignored, so it is safe to call for every message.
//
// If the peer reused an id that is still in flight — a protocol violation, but
// one that happens — the displaced request is returned with true. The new
// request wins, because the peer will answer the newer one.
func (c *Correlator) Track(dir Direction, m Message) (displaced Pending, collision bool) {
	if m.Kind != KindRequest || !m.ID.Set() {
		return Pending{}, false
	}
	key := pendingKey(dir, m.ID)

	c.mu.Lock()
	defer c.mu.Unlock()
	prev, existed := c.pending[key]
	c.pending[key] = Pending{Dir: dir, ID: m.ID, Method: m.Method, Sent: c.now()}
	return prev, existed
}

// Match consumes the request a response answers, reporting false when there is
// no matching request in flight.
//
// dir is the direction the response arrived in; the request it answers
// travelled the other way.
func (c *Correlator) Match(dir Direction, m Message) (Pending, bool) {
	if m.Kind != KindResponse && m.Kind != KindError {
		return Pending{}, false
	}
	if !m.ID.Set() {
		// An error with a null id: the peer could not parse our frame well
		// enough to know what it was answering. Nothing to correlate.
		return Pending{}, false
	}
	key := pendingKey(dir.Opposite(), m.ID)

	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.pending[key]
	if ok {
		delete(c.pending, key)
	}
	return p, ok
}

// Expire drops requests older than the ttl and returns them, oldest first, so
// the caller can account for calls that never got an answer. Without this the
// map grows for the lifetime of the session every time a server drops a reply.
func (c *Correlator) Expire() []Pending {
	if c.ttl <= 0 {
		return nil
	}
	cutoff := c.now().Add(-c.ttl)

	c.mu.Lock()
	defer c.mu.Unlock()
	var stale []Pending
	for key, p := range c.pending {
		if p.Sent.Before(cutoff) {
			stale = append(stale, p)
			delete(c.pending, key)
		}
	}
	sortBySent(stale)
	return stale
}

// InFlight is the number of unanswered requests.
func (c *Correlator) InFlight() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

func sortBySent(p []Pending) {
	// Insertion sort: this list is the number of simultaneously dropped
	// replies, which is a handful at worst.
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && p[j].Sent.Before(p[j-1].Sent); j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}
