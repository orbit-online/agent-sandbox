package control

import (
	"sync"
	"sync/atomic"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
)

// Conn is a client connection's side of the live sets (judge.Judge)
type Conn interface {
	// AddSet notes a set added to the rules in force
	AddSet(*rules.Set)
	// RemoveSet notes a set removed from them, after the removal, and says whether the connection used it
	RemoveSet(*rules.Set) bool
}

// Registry is the rules in force, the static ones and the live sets, and the connections they apply to
type Registry struct {
	cur atomic.Pointer[rules.Rules]
	// Orders the changes to the rules
	setsMu sync.Mutex

	mu    sync.Mutex
	conns map[Conn]func() // Each connection, with what ends it
}

// NewRegistry starts with the static rules
func NewRegistry(static *rules.Rules) *Registry {
	r := &Registry{conns: map[Conn]func(){}}
	r.cur.Store(static)
	return r
}

// Current is the rules messages are judged by now
func (r *Registry) Current() *rules.Rules { return r.cur.Load() }

// Register adds a connection, which kill ends; the function returned takes it out again
func (r *Registry) Register(c Conn, kill func()) func() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns[c] = kill
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(r.conns, c)
	}
}

// The connections now, with what ends each
func (r *Registry) connected() map[Conn]func() {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[Conn]func(), len(r.conns))
	for c, kill := range r.conns {
		out[c] = kill
	}
	return out
}

// KillAll ends every connection registered
func (r *Registry) KillAll() {
	for _, kill := range r.connected() {
		kill()
	}
}

// Add adds a live set: every message judged from here on sees it. Each connection looks up its names before its
// client's next message
func (r *Registry) Add(rs *rules.Set) {
	r.setsMu.Lock()
	defer r.setsMu.Unlock()
	r.cur.Store(r.Current().With(rs))
	for c := range r.connected() {
		c.AddSet(rs)
	}
}

// Remove removes a live set and ends every connection that sent or got a message under it, which drops the names,
// match rules and objects it set up on the bus. Returns how many it ended. Each connection hears of it after the
// swap, under the lock its messages are judged under: a message judged under the set before finishes first, and one
// judged after sees the rules without it (models/proxy.als, D1inflight)
func (r *Registry) Remove(rs *rules.Set) int {
	r.setsMu.Lock()
	defer r.setsMu.Unlock()
	r.cur.Store(r.Current().Without(rs))
	ended := 0
	for c, kill := range r.connected() {
		if c.RemoveSet(rs) {
			kill()
			ended++
		}
	}
	return ended
}
