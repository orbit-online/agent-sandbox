package main

import "errors"

// A client's side of the live rule sets (control.go): which sets it used, and their names looked up when one is added

var errRevoked = errors.New("A live rule set the connection used was removed")

// The policy and filters for a name by the rules the message is judged by; called with mu held. A live set with a
// filter for the name counts as used, whatever the verdict: its removal ends the connection
func (c *client) lookup(name string) (policy, []*filter) {
	if c.cur == nil {
		c.cur = c.p.current()
	}
	p, fs := c.names.lookup(c.cur, name)
	for _, f := range fs {
		if f.set != nil && f.set.live() {
			if c.used == nil {
				c.used = map[*RuleSet]bool{}
			}
			c.used[f.set] = true
		}
	}
	return p, fs
}

// Holds the client's next message until n more of the proxy's own calls are answered; called with mu held
func (c *client) holdFor(n int) {
	c.syncing += n
	if c.synced == nil {
		c.synced = make(chan struct{})
	}
}

// Watches names and asks who owns them, holding the client until the owners are known: a call by an owner's unique
// name right after Hello or after a set is added passes too. Returns the match rules. Called with mu held
func (c *client) lookupNames(names []string, fakes *[][]byte) ([]string, error) {
	var matches []string
	for _, name := range names {
		match := ownerMatch(name)
		if err := c.fakeCall(fakes, busCall("AddMatch", match), expect{kind: expectFakeMatch}); err != nil {
			return nil, err
		}
		matches = append(matches, match)
		if err := c.fakeCall(fakes, busCall("GetNameOwner", name), expect{kind: expectFakeOwner, name: name, sync: true}); err != nil {
			return nil, err
		}
		c.holdFor(1)
	}
	return matches, nil
}

// lookupNames for a live set's names, whose match rules go when the set does
func (c *client) lookupSet(rs *RuleSet, fakes *[][]byte) error {
	matches, err := c.lookupNames(rs.names(), fakes)
	c.matches[rs] = append(c.matches[rs], matches...)
	return err
}

// Before the client's next message is judged: looks up the names of the live sets added since and stops watching
// those of the sets removed, then waits for the owners. Before Hello there's nothing to do: Hello's initialNameOps
// takes the live sets there are then. On the client's reader, so the proxy's calls never overtake its Hello
func (c *client) syncSets(done chan struct{}) error {
	var fakes [][]byte
	var err error
	c.mu.Lock()
	if c.helloSeen {
		for _, rs := range c.goneSets {
			for _, m := range c.matches[rs] {
				if err == nil {
					err = c.fakeCall(&fakes, busCall("RemoveMatch", m), expect{kind: expectFakeMatch})
				}
			}
			delete(c.matches, rs)
		}
		for _, rs := range c.newSets {
			if err == nil {
				err = c.lookupSet(rs, &fakes)
			}
		}
	}
	c.goneSets, c.newSets = nil, nil
	synced := c.synced
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := sendAll(c.toBus, fakes); err != nil {
		return err
	}
	if synced != nil {
		select {
		case <-synced:
		case <-done:
			return errClosed
		}
	}
	return nil
}

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
func (p *Proxy) current() *Rules {
	if r := p.cur.Load(); r != nil {
		return r
	}
	return p.rules
}

// Adds a live set: every message judged from here on sees it. Each client looks up its names before its next message
func (p *Proxy) addSet(rs *RuleSet) {
	p.setsMu.Lock()
	defer p.setsMu.Unlock()
	p.cur.Store(p.current().with(rs))
	for _, c := range p.connected() {
		c.mu.Lock()
		c.newSets = append(c.newSets, rs)
		c.mu.Unlock()
	}
}

// Removes a live set and ends every connection that sent or got a message under it, which drops the names, match
// rules and objects it set up on the bus. Returns how many it ended. Taken under each client's mu after the swap: a
// message judged under the set before it finishes there, and one judged after sees the rules without it
func (p *Proxy) removeSet(rs *RuleSet) int {
	p.setsMu.Lock()
	defer p.setsMu.Unlock()
	p.cur.Store(p.current().without(rs))
	ended := 0
	for _, c := range p.connected() {
		c.mu.Lock()
		used := c.used[rs]
		delete(c.used, rs)
		for i, s := range c.newSets {
			if s == rs {
				c.newSets = append(c.newSets[:i:i], c.newSets[i+1:]...)
				break
			}
		}
		if !used && c.matches[rs] != nil {
			c.goneSets = append(c.goneSets, rs)
		}
		kill := c.kill
		c.mu.Unlock()
		if used {
			kill()
			ended++
		}
	}
	return ended
}
