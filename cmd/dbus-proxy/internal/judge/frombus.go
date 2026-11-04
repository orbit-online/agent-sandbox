package judge

import (
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// FromBus judges a message from the bus: a reply only to a call that was let through (or the proxy's own, which the
// client never sees), broadcasts by the sender's rules, NameOwnerChanged by the name's policy, the rest passed on.
// The proxy's own calls in the Action go to the bus. An error ends the connection
func (j *Judge) FromBus(m *wire.Message) (Action, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	var calls [][]byte
	a, err := j.judgeBus(m, &calls)
	a.Calls = calls
	if a.Verdict == Forward && len(m.FDs()) > 0 && !j.unixFDs {
		// The client didn't negotiate file descriptors; the bus passes them only because the proxy did
		a.Verdict = Drop
	}
	return a, err
}

// Decides under mu, as judgeClient does
func (j *Judge) judgeBus(m *wire.Message, fakes *[][]byte) (Action, error) {
	if isReply(m) {
		rs, _ := m.ReplySerial()
		e, ok := j.awaitBus[rs]
		if !ok {
			return dropped, nil
		}
		if e.fromBus && m.Header(dbus.FieldSender) != busName {
			// Only the bus answers a call to the bus; this one stays pending for it
			return dropped, nil
		}
		delete(j.awaitBus, rs)
		return j.reply(m, e, fakes)
	}
	if isNameOwnerChanged(m) && !j.passNameOwnerChanged(m) {
		return dropped, nil
	}
	sender := m.Header(dbus.FieldSender)
	if m.Type == dbus.TypeSignal && m.Header(dbus.FieldDestination) == "" {
		_, fs := j.lookup(sender)
		if !rules.BroadcastPasses(fs) {
			return dropped, nil
		}
	}
	// A peer that sent the client something becomes visible to it, so it can follow the peer's lifetime
	if sender != "" && sender[0] == ':' {
		if err := j.names.raise(sender, rules.See); err != nil {
			return Action{}, err
		}
	}
	if generatesReply(m) {
		call := peerCall{sender, m.Serial()}
		if _, ok := j.awaitPeer[call]; !ok && len(j.awaitPeer) >= MaxPendingReplies {
			return Action{}, fmt.Errorf("Too many calls to the client awaiting replies")
		}
		j.awaitPeer[call] = struct{}{}
	}
	return forwarded, nil
}

// A reply to a call the proxy let through or made itself
func (j *Judge) reply(m *wire.Message, e expect, fakes *[][]byte) (Action, error) {
	ok := m.Type == dbus.TypeMethodReply
	switch e.kind {
	case expectHello:
		if id, has := arg0(m); ok && has {
			return forwarded, j.names.raise(id, rules.Talk)
		}
	case expectRewrite:
		return replaced(wire.Encode(e.rewrite, m.Serial()))
	case expectListNames:
		if ok {
			return replaced(j.filterNames(m))
		}
	case expectFakeOwner:
		if owner, has := arg0(m); ok && has && owner != "" {
			if err := j.names.addOwned(owner, e.name); err != nil {
				return Action{}, err
			}
		}
		if e.sync {
			j.syncing--
			j.syncDone()
		}
		return dropped, nil
	case expectFakeMatch:
		return dropped, nil
	}
	return forwarded, nil
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
func (j *Judge) passNameOwnerChanged(m *wire.Message) bool {
	if !m.DecodeBody(maxInspectBody) || len(m.Body) != 3 {
		return false
	}
	name, ok1 := m.Body[0].(string)
	_, ok2 := m.Body[1].(string)
	newOwner, ok3 := m.Body[2].(string)
	if !ok1 || !ok2 || !ok3 || name == "" {
		return false
	}
	if p, _ := j.lookup(name); p < rules.See {
		return false
	}
	if name[0] != ':' && newOwner != "" {
		if j.names.addOwned(newOwner, name) != nil {
			return false
		}
	}
	if name[0] == ':' && newOwner == "" {
		j.names.forget(name)
	}
	return true
}

// A ListNames or ListActivatableNames reply with only the names the client may see
func (j *Judge) filterNames(m *wire.Message) ([]byte, error) {
	names, ok := firstStrings(m)
	if !ok {
		return nil, fmt.Errorf("ListNames reply without a string array")
	}
	seen := []string{}
	for _, n := range names {
		if p, _ := j.lookup(n); p >= rules.See {
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
