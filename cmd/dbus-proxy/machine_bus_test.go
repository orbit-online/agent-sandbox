package main

import (
	"slices"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
)

// The reference model's bus side: what the bus does when names change hands or a connection leaves, and what each
// client's proxy lets through of what the bus sends it (frombus.go)

const errNoReply = "org.freedesktop.DBus.Error.NoReply"

// fromPeer judges a call or signal from sender to client t, as judgeBus does: a broadcast passes by the sender's
// rules, and what passes makes the sender visible to t; a call then awaits t's reply. Reports whether it reaches t
func (m *model) fromPeer(t *refClient, sender string, broadcast, call bool, serial uint32, path, iface, member string) bool {
	if t == nil || t.closed || !t.helloed {
		return false
	}
	if broadcast {
		_, fs := m.lookup(t, sender)
		if !rules.BroadcastPasses(fs) {
			return false
		}
	}
	t.raise(sender, rules.See)
	if call {
		t.peer[peerKey{sender, serial}] = true
	}
	return true
}

// replyTo judges a reply from sender to client t's serial rs: only to a call let through, and to a call to the bus
// only from the bus. Returns the call it answers
func (m *model) replyTo(t *refClient, sender string, rs uint32) (refCall, bool) {
	if t == nil || t.closed || !t.helloed {
		return refCall{}, false
	}
	call, ok := t.pending[rs]
	if !ok || call.to == "bus" && sender != "bus" {
		return refCall{}, false
	}
	delete(t.pending, rs)
	return call, true
}

// nameOwnerChanged is the bus's signal, which reaches each client whose proxy watches the name, and passes there
// for names it may see; their new owners take on the name's rules (passNameOwnerChanged)
func (m *model) nameOwnerChanged(name, old, new string) {
	for _, c := range m.registered() {
		if !m.watches(name) {
			continue
		}
		if p, _ := m.lookup(c, name); p < rules.See {
			continue
		}
		c.addOwned(new, name)
		m.rec(c.role, "S NameOwnerChanged bus -> * [%s %s %s]", name, old, new)
	}
}

// acquired: role took name. The bus tells it and the watchers, and answers the starts waiting for the name
func (m *model) acquired(name, role string) {
	m.owners[name] = role
	m.rec(role, "S NameAcquired bus -> %s [%s]", role, name)
	m.nameOwnerChanged(name, "", role)
	if name != lazyName {
		return
	}
	for _, k := range m.lazy {
		if call, ok := m.replyTo(m.clients[k.caller], "bus", k.serial); ok {
			m.rec(k.caller, "R %s bus [1]", call.tok)
		}
	}
	m.lazy = nil
}

// released: role let go of name, or left the bus (lost false: nothing tells it)
func (m *model) released(name, role string, lost bool) {
	delete(m.owners, name)
	if lost {
		m.rec(role, "S NameLost bus -> %s [%s]", role, name)
	}
	m.nameOwnerChanged(name, role, "")
}

// leave: connections left the bus. Their names go, and the bus answers the calls they hadn't with NoReply
func (m *model) leave(roles ...string) {
	var gone []string
	for _, role := range roles {
		if c := m.clients[role]; c != nil {
			if c.helloed && !c.closed {
				gone = append(gone, role)
			}
			c.closed = true
		}
	}
	for _, role := range gone {
		m.left(role)
	}
}

func (m *model) left(role string) {
	for _, name := range mapsKeys(m.owners) {
		if m.owners[name] == role {
			m.released(name, role, false)
		}
	}
	for _, c := range m.registered() {
		for s, call := range c.pending {
			if call.to == role {
				delete(c.pending, s)
				m.rec(c.role, "E %s bus %s", call.tok, errNoReply)
			}
		}
	}
	for _, svc := range m.svcs {
		for s, call := range svc.out {
			if call.to == role {
				delete(svc.out, s)
				m.rec(svc.role, "E %s bus %s", call.tok, errNoReply)
			}
		}
	}
	m.lazy = slices.DeleteFunc(m.lazy, func(k peerKey) bool { return k.caller == role })
	for k := range m.busPending {
		if k.caller == role || k.callee == role {
			delete(m.busPending, k)
		}
	}
}

// owner is a name's owner as a call routes to it: a well-known name's owner, a registered unique name, or none
func (m *model) owner(name string) string {
	if strings.Contains(name, ".") {
		return m.owners[name]
	}
	if m.svcs[name] != nil {
		return name
	}
	if c := m.clients[name]; c != nil && c.helloed && !c.closed {
		return name
	}
	return ""
}
