package main

import "github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"

// The live rule sets the control socket adds and removes (control.go), applied to the clients connected

// The clients connected now
func (p *Proxy) register(c *client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns == nil {
		p.conns = map[*client]bool{}
	}
	p.conns[c] = true
}

func (p *Proxy) unregister(c *client) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
}

func (p *Proxy) connected() []*client {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*client, 0, len(p.conns))
	for c := range p.conns {
		out = append(out, c)
	}
	return out
}

// The rules messages are judged by now
func (p *Proxy) current() *rules.Rules {
	if r := p.cur.Load(); r != nil {
		return r
	}
	return p.rules
}

// Adds a live set: every message judged from here on sees it. Each client looks up its names before its next message
func (p *Proxy) addSet(rs *rules.Set) {
	p.setsMu.Lock()
	defer p.setsMu.Unlock()
	p.cur.Store(p.current().With(rs))
	for _, c := range p.connected() {
		c.j.AddSet(rs)
	}
}

// Removes a live set and ends every connection that sent or got a message under it, which drops the names, match
// rules and objects it set up on the bus. Returns how many it ended. Taken under each client's mu after the swap: a
// message judged under the set before it finishes there, and one judged after sees the rules without it
func (p *Proxy) removeSet(rs *rules.Set) int {
	p.setsMu.Lock()
	defer p.setsMu.Unlock()
	p.cur.Store(p.current().Without(rs))
	ended := 0
	for _, c := range p.connected() {
		if c.j.RemoveSet(rs) {
			c.kill()
			ended++
		}
	}
	return ended
}
