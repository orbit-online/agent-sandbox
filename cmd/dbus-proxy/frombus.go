package main

import (
	"encoding/binary"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// Handles a message from the bus: a reply only to a call that was let through (or the proxy's own, which the client
// never sees), broadcasts by the sender's rules, NameOwnerChanged by the name's policy, the rest passed on
func (c *client) fromBus(m *message) error {
	var fakes [][]byte
	c.mu.Lock()
	out, err := c.judgeBus(m, &fakes)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if err := sendAll(c.toBus, fakes); err != nil {
		return err
	}
	if out != nil {
		m.closeFDs()
		return c.toClient.send(out, nil)
	}
	if m.Message == nil {
		return nil
	}
	if len(m.fds) > 0 && !c.unixFDs {
		// The client didn't negotiate file descriptors; the bus passes them only because the proxy did
		m.closeFDs()
		return nil
	}
	return forward(c.toClient, m)
}

// Decides under mu, returning as judgeClient does
func (c *client) judgeBus(m *message, fakes *[][]byte) ([]byte, error) {
	drop := func() ([]byte, error) {
		m.closeFDs()
		m.Message = nil
		return nil, nil
	}
	c.cur = c.p.current()
	if isReply(m) {
		rs, _ := m.replySerial()
		e, ok := c.awaitBus[rs]
		if !ok {
			if c.p.filter {
				return drop()
			}
			return nil, nil
		}
		if e.fromBus && m.header(dbus.FieldSender) != busName {
			// Only the bus answers a call to the bus; this one stays pending for it
			return drop()
		}
		delete(c.awaitBus, rs)
		return c.reply(m, e, fakes, drop)
	}
	if !c.p.filter {
		return nil, nil
	}
	if isNameOwnerChanged(m) && !c.passNameOwnerChanged(m) {
		return drop()
	}
	sender := m.header(dbus.FieldSender)
	if m.Type == dbus.TypeSignal && m.header(dbus.FieldDestination) == "" {
		_, fs := c.lookup(sender)
		if !broadcastPasses(fs, m.header(dbus.FieldPath), m.header(dbus.FieldInterface), m.header(dbus.FieldMember)) {
			return drop()
		}
	}
	// A peer that sent the client something becomes visible to it, so it can follow the peer's lifetime
	if sender != "" && sender[0] == ':' {
		if err := c.names.raise(sender, policySee); err != nil {
			return nil, err
		}
	}
	if generatesReply(m) {
		call := peerCall{sender, m.Serial()}
		if _, ok := c.awaitPeer[call]; !ok && len(c.awaitPeer) >= maxPendingReplies {
			return nil, fmt.Errorf("Too many calls to the client awaiting replies")
		}
		c.awaitPeer[call] = struct{}{}
	}
	return nil, nil
}

// A reply to a call the proxy let through or made itself
func (c *client) reply(m *message, e expect, fakes *[][]byte, drop func() ([]byte, error)) ([]byte, error) {
	ok := m.Type == dbus.TypeMethodReply
	switch e.kind {
	case expectHello:
		if id, has := m.arg0(); ok && has {
			return nil, c.names.raise(id, policyTalk)
		}
	case expectRewrite:
		return encodeNew(e.rewrite, m.Serial())
	case expectListNames:
		if ok {
			return c.filterNames(m)
		}
	case expectFakeOwner:
		if owner, has := m.arg0(); ok && has && owner != "" {
			if err := c.names.addOwned(owner, e.name); err != nil {
				return nil, err
			}
		}
		if e.sync {
			c.syncing--
			c.syncDone()
		}
		return drop()
	case expectFakeMatch:
		return drop()
	case expectFakeList:
		if names, has := firstStrings(m); ok && has {
			for _, name := range names {
				if name == "" || name[0] == ':' {
					continue
				}
				if p, _ := c.cur.lookup(name); p == policyNone {
					continue
				}
				if err := c.fakeCall(fakes, busCall("GetNameOwner", name), expect{kind: expectFakeOwner, name: name, sync: true}); err != nil {
					return nil, err
				}
				c.syncing++
			}
		}
		c.syncing--
		c.syncDone()
		return drop()
	}
	return nil, nil
}

// Releases the client once every GetNameOwner of names under wildcards is answered; called with mu held
func (c *client) syncDone() {
	if c.syncing == 0 && c.synced != nil {
		close(c.synced)
		c.synced = nil
	}
}

// The first argument when it's a string array; only for the bus's replies, which may be as long as a message
func firstStrings(m *message) ([]string, bool) {
	if !m.decodeBody(maxMessageSize) || len(m.Body) == 0 {
		return nil, false
	}
	s, ok := m.Body[0].([]string)
	return s, ok
}

func isNameOwnerChanged(m *message) bool {
	return m.Type == dbus.TypeSignal && m.header(dbus.FieldSender) == busName &&
		m.header(dbus.FieldInterface) == busIface && m.header(dbus.FieldMember) == "NameOwnerChanged"
}

// NameOwnerChanged reaches the client only for names it may see; their new owners take on their rules. A unique name
// that left is dropped from the table, since it never comes back
func (c *client) passNameOwnerChanged(m *message) bool {
	if !m.decodeBody(maxInspectBody) || len(m.Body) != 3 {
		return false
	}
	name, ok1 := m.Body[0].(string)
	_, ok2 := m.Body[1].(string)
	newOwner, ok3 := m.Body[2].(string)
	if !ok1 || !ok2 || !ok3 || name == "" {
		return false
	}
	if p, _ := c.lookup(name); p < policySee {
		return false
	}
	if name[0] != ':' && newOwner != "" {
		if c.names.addOwned(newOwner, name) != nil {
			return false
		}
	}
	if name[0] == ':' && newOwner == "" {
		c.names.forget(name)
	}
	return true
}

// A ListNames or ListActivatableNames reply with only the names the client may see
func (c *client) filterNames(m *message) ([]byte, error) {
	names, ok := firstStrings(m)
	if !ok {
		return nil, fmt.Errorf("ListNames reply without a string array")
	}
	seen := []string{}
	for _, n := range names {
		if p, _ := c.lookup(n); p >= policySee {
			seen = append(seen, n)
		}
	}
	out := &dbus.Message{Type: m.Type, Flags: m.Flags, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf(seen)),
	}, Body: []any{seen}}
	for _, f := range []dbus.HeaderField{dbus.FieldReplySerial, dbus.FieldSender, dbus.FieldDestination} {
		if v, ok := m.Headers[f]; ok {
			out.Headers[f] = v
		}
	}
	return encodeWith(out, binary.LittleEndian, m.Serial(), nil)
}
