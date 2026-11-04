package main

import (
	"slices"

	"github.com/godbus/dbus/v5"
	"pgregory.net/rapid"
)

// The state machine's other parties: services straight on the bus (names acquired and released, calls to clients,
// replies asked and forged, broadcasts)

func (mc *machine) drawSvc(t *rapid.T) (*party, *refSvc) {
	p := mc.w.svcs[rapid.IntRange(0, len(mc.w.svcs)-1).Draw(t, "svc")]
	return p, mc.m.svcs[p.role]
}

// Acquire: a service asks for a name, without queueing
func (mc *machine) Acquire(t *rapid.T) {
	p, svc := mc.drawSvc(t)
	name := rapid.SampledFrom(svcNames).Draw(t, "name")
	r := p.takeReply(p.send(busCall("RequestName", name, uint32(dbus.NameFlagDoNotQueue))))
	want := uint32(1)
	switch mc.m.owners[name] {
	case "":
		mc.m.acquired(name, svc.role)
	case svc.role:
		want = 4
	default:
		want = 3
	}
	if r == nil || len(r.body) != 1 || r.body[0] != want {
		t.Fatalf("%s RequestName %s: %+v, want %d", svc.role, name, r, want)
	}
}

// Release: a service lets go of a name
func (mc *machine) Release(t *rapid.T) {
	p, svc := mc.drawSvc(t)
	name := rapid.SampledFrom(svcNames).Draw(t, "name")
	r := p.takeReply(p.send(busCall("ReleaseName", name)))
	want := uint32(1)
	switch mc.m.owners[name] {
	case svc.role:
		mc.m.released(name, svc.role, true)
	case "":
		want = 2
	default:
		want = 3
	}
	if r == nil || len(r.body) != 1 || r.body[0] != want {
		t.Fatalf("%s ReleaseName %s: %+v, want %d", svc.role, name, r, want)
	}
}

// CallClient: a peer calls a client, by its unique name or a name the client may own
func (mc *machine) CallClient(t *rapid.T) {
	p, svc := mc.drawSvc(t)
	var dests []string
	for _, r := range mapsKeys(mc.clients) {
		if mc.clients[r].unique != "" {
			dests = append(dests, r)
		}
	}
	dest := rapid.SampledFrom(append(dests, "org.test.Own")).Draw(t, "dest")
	tok := mc.token()
	serial := p.send(echoCall(mc.busNameOf(dest), "Echo", tok))
	p.tokens[serial] = tok
	m := mc.m
	target := m.owner(dest)
	if target == "" {
		m.rec(svc.role, "E %s bus %s", tok, errNameHasNoOwner)
		return
	}
	svc.out[serial] = refCall{target, tok}
	m.busCalls(svc.role, serial, target)
	m.callTo(target, svc.role, serial, "Echo", tok, dest)
}

// ServiceReply: a service answers a call it got, with a return or an error
func (mc *machine) ServiceReply(t *rapid.T) {
	p, svc := mc.drawSvc(t)
	if len(svc.in) == 0 {
		t.Skip("no call to answer")
	}
	i := rapid.IntRange(0, len(svc.in)-1).Draw(t, "call")
	in := svc.in[i]
	svc.in = slices.Delete(svc.in, i, i+1)
	isErr := rapid.Bool().Draw(t, "error")
	tok := mc.token()
	sent := p.send(replyMsg(mc.busNameOf(in.from), in.serial, isErr, tok))
	mc.m.answer(in.from, svc.role, in.serial, isErr, tok, sent)
}

// ForgeReply: a peer sends a client a reply it wasn't asked for: to a call of the client's that awaits another's
// reply (the bus's, as a pending start), or to a serial the client used or never did. The test's bus lets it through;
// the proxy takes it only for a call awaiting a reply, and for a call to the bus only from the bus
func (mc *machine) ForgeReply(t *rapid.T) {
	p, svc := mc.drawSvc(t)
	// Clients awaiting replies first
	var waiting, idle []string
	for _, r := range mc.registered() {
		if len(mc.m.clients[r].pending) > 0 {
			waiting = append(waiting, r)
		} else {
			idle = append(idle, r)
		}
	}
	role := pick(t, append(waiting, idle...), "client")
	c := mc.m.clients[role]
	// Calls to the bus first: rapid draws earlier entries more often
	var serials, others []uint32
	for s, call := range c.pending {
		if call.to == "bus" {
			serials = append(serials, s)
		} else {
			others = append(others, s)
		}
	}
	slices.Sort(serials)
	slices.Sort(others)
	serials = append(serials, others...)
	serials = append(append(serials, c.sent...), 9999)
	rs := rapid.SampledFrom(serials).Draw(t, "replySerial")
	isErr := rapid.Bool().Draw(t, "error")
	tok := mc.token()
	sent := p.send(replyMsg(mc.busNameOf(role), rs, isErr, tok))
	mc.m.answer(role, svc.role, rs, isErr, tok, sent)
}

// Broadcast: a service emits a signal to every connection whose match rules take it, or to one client
func (mc *machine) Broadcast(t *rapid.T) {
	p, svc := mc.drawSvc(t)
	member := rapid.SampledFrom([]string{"Ping", "Pong"}).Draw(t, "member")
	dest := ""
	if regs := mc.registered(); len(regs) > 0 && rapid.IntRange(0, 3).Draw(t, "unicast") == 0 {
		dest = rapid.SampledFrom(regs).Draw(t, "dest")
	}
	tok := mc.token()
	sig := &dbus.Message{Type: dbus.TypeSignal, Flags: dbus.FlagNoReplyExpected, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldPath:      dbus.MakeVariant(dbus.ObjectPath("/org/test")),
		dbus.FieldInterface: dbus.MakeVariant(sigIface),
		dbus.FieldMember:    dbus.MakeVariant(member),
		dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf("")),
	}, Body: []any{tok}}
	m := mc.m
	if dest != "" {
		sig.Headers[dbus.FieldDestination] = dbus.MakeVariant(mc.busNameOf(dest))
		p.send(sig)
		if m.fromPeer(m.clients[dest], svc.role, false, false, 0, "/org/test", sigIface, member) {
			m.rec(dest, "S %s %s -> %s [%s]", member, svc.role, dest, tok)
		}
		return
	}
	p.send(sig)
	for _, c := range m.registered() {
		takes := c.matches[sigMatch] > 0 || member == "Ping" && c.matches[pingMatch] > 0
		if takes && m.fromPeer(c, svc.role, true, false, 0, "/org/test", sigIface, member) {
			m.rec(c.role, "S %s %s -> * [%s]", member, svc.role, tok)
		}
	}
}
