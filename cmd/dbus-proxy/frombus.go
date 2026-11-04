package main

import (
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// Handles a message from the bus: a reply only to a call that was let through (or the proxy's own, which the client
// never sees), broadcasts by the sender's rules, NameOwnerChanged by the name's policy, the rest passed on
func (c *client) fromBus(m *wire.Message) error {
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
		m.CloseFDs()
		return c.toClient.Send(out, nil)
	}
	if m.Message == nil {
		return nil
	}
	if len(m.FDs()) > 0 && !c.unixFDs {
		// The client didn't negotiate file descriptors; the bus passes them only because the proxy did
		m.CloseFDs()
		return nil
	}
	return forward(c.toClient, m)
}

// Decides under mu, returning as judgeClient does
func (c *client) judgeBus(m *wire.Message, fakes *[][]byte) ([]byte, error) {
	drop := func() ([]byte, error) {
		m.CloseFDs()
		m.Message = nil
		return nil, nil
	}
	c.cur = c.p.current()
	if isReply(m) {
		rs, _ := m.ReplySerial()
		e, ok := c.awaitBus[rs]
		if !ok {
			return drop()
		}
		if e.fromBus && m.Header(dbus.FieldSender) != busName {
			// Only the bus answers a call to the bus; this one stays pending for it
			return drop()
		}
		delete(c.awaitBus, rs)
		return c.reply(m, e, fakes, drop)
	}
	if isNameOwnerChanged(m) && !c.passNameOwnerChanged(m) {
		return drop()
	}
	sender := m.Header(dbus.FieldSender)
	if m.Type == dbus.TypeSignal && m.Header(dbus.FieldDestination) == "" {
		_, fs := c.lookup(sender)
		if !rules.BroadcastPasses(fs, m.Header(dbus.FieldPath), m.Header(dbus.FieldInterface), m.Header(dbus.FieldMember)) {
			return drop()
		}
	}
	// A peer that sent the client something becomes visible to it, so it can follow the peer's lifetime
	if sender != "" && sender[0] == ':' {
		if err := c.names.raise(sender, rules.See); err != nil {
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
func (c *client) reply(m *wire.Message, e expect, fakes *[][]byte, drop func() ([]byte, error)) ([]byte, error) {
	ok := m.Type == dbus.TypeMethodReply
	switch e.kind {
	case expectHello:
		if id, has := arg0(m); ok && has {
			return nil, c.names.raise(id, rules.Talk)
		}
	case expectRewrite:
		return wire.Encode(e.rewrite, m.Serial())
	case expectListNames:
		if ok {
			return c.filterNames(m)
		}
	case expectFakeOwner:
		if owner, has := arg0(m); ok && has && owner != "" {
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
	}
	return nil, nil
}

// Releases the client once every GetNameOwner it waits for is answered; called with mu held
func (c *client) syncDone() {
	if c.syncing == 0 && c.synced != nil {
		close(c.synced)
		c.synced = nil
	}
}

// The first argument when it's a string array; only for the bus's replies, which may be as long as a message
func firstStrings(m *wire.Message) ([]string, bool) {
	if !m.DecodeBody(wire.MaxMessageSize) || len(m.Body) == 0 {
		return nil, false
	}
	s, ok := m.Body[0].([]string)
	return s, ok
}

func isNameOwnerChanged(m *wire.Message) bool {
	return m.Type == dbus.TypeSignal && m.Header(dbus.FieldSender) == busName &&
		m.Header(dbus.FieldInterface) == busIface && m.Header(dbus.FieldMember) == "NameOwnerChanged"
}

// NameOwnerChanged reaches the client only for names it may see; their new owners take on their rules. A unique name
// that left is dropped from the table, since it never comes back
func (c *client) passNameOwnerChanged(m *wire.Message) bool {
	if !m.DecodeBody(maxInspectBody) || len(m.Body) != 3 {
		return false
	}
	name, ok1 := m.Body[0].(string)
	_, ok2 := m.Body[1].(string)
	newOwner, ok3 := m.Body[2].(string)
	if !ok1 || !ok2 || !ok3 || name == "" {
		return false
	}
	if p, _ := c.lookup(name); p < rules.See {
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
func (c *client) filterNames(m *wire.Message) ([]byte, error) {
	names, ok := firstStrings(m)
	if !ok {
		return nil, fmt.Errorf("ListNames reply without a string array")
	}
	seen := []string{}
	for _, n := range names {
		if p, _ := c.lookup(n); p >= rules.See {
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
	return wire.Encode(out, m.Serial())
}
