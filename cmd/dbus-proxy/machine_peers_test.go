package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"pgregory.net/rapid"
)

// The state machine's other parties: services straight on the bus (names acquired and released, calls to clients,
// replies asked and forged, broadcasts) and the broker (live sets added and removed, its connection dropped)

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
	dest := rapid.SampledFrom(append(dests, "org.test.Own", testApp+".Live")).Draw(t, "dest")
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

// awaitExpected waits until the connections the model closed are gone from the bus and each registered client got
// as many messages as the model has for it in this step
func (mc *machine) awaitExpected(t *rapid.T) {
	for _, role := range mapsKeys(mc.m.clients) {
		if p := mc.clients[role]; mc.m.clients[role].closed && p.unique != "" && p.isClosed(true) {
			mc.w.waitGone(p.unique)
		}
	}
	for _, c := range mc.m.registered() {
		p, n := mc.clients[c.role], len(mc.m.want[c.role])
		if !p.waitUntil(func() bool { return len(p.got) >= n }) {
			t.Fatalf("%s didn't get %d messages", c.role, n)
		}
	}
}

// AddSet: the broker adds a live set from the catalog. Each registered client's proxy watches its names and looks up
// their owners before its next message (syncSets)
func (mc *machine) AddSet(t *rapid.T) {
	m := mc.m
	if len(m.live) >= 8 {
		t.Skip("enough sets")
	}
	idx := rapid.IntRange(0, len(setCatalog)-1).Draw(t, "set")
	m.setSeq++
	id := fmt.Sprintf("s%d", m.setSeq)
	req := map[string]any{"op": "add", "id": id}
	e := setCatalog[idx]
	for k, v := range e {
		req[k] = v
	}
	rs, err := rules.ParseLive(id, rules.Args{See: e["see"], Talk: e["talk"], Own: e["own"], Call: e["call"],
		Broadcast: e["broadcast"]}, "session", testApp)
	if err != nil {
		t.Fatal(err)
	}
	if res := mc.brk.do(req); res == nil || !res.OK {
		t.Fatalf("Add %v: %+v", req, res)
	}
	s := &refSet{id: id, idx: idx, rs: rs}
	m.live = append(m.live, s)
	for _, c := range m.registered() {
		c.watched[s] = true
		m.lookupNames(c, rs.Names())
	}
}

// RemoveSet: the broker removes a live set, or one that isn't there. The connections that used it end
func (mc *machine) RemoveSet(t *rapid.T) {
	m := mc.m
	// A set that isn't there last: rapid draws earlier entries more often
	var ids []string
	for _, s := range m.live {
		ids = append(ids, s.id)
	}
	ids = append(ids, "none")
	id := rapid.SampledFrom(ids).Draw(t, "id")
	res := mc.brk.do(map[string]any{"op": "remove", "id": id})
	i := slices.IndexFunc(m.live, func(s *refSet) bool { return s.id == id })
	if i < 0 {
		if res == nil || res.Error == "" {
			t.Fatalf("Removed %s, which isn't there: %+v", id, res)
		}
		return
	}
	if want := m.remove(m.live[i]); res == nil || !res.OK || res.Closed != want {
		t.Fatalf("Remove %s: %+v, want %d closed", id, res, want)
	}
}

// remove takes sets out of force, then ends the connections that used one; the others stop watching their names.
// Returns how many it ended
func (m *model) remove(sets ...*refSet) int {
	m.live = slices.DeleteFunc(m.live, func(o *refSet) bool { return slices.Contains(sets, o) })
	var ended []string
	for _, r := range mapsKeys(m.clients) {
		c := m.clients[r]
		for _, s := range sets {
			if c.used[s] && !c.closed && !slices.Contains(ended, r) {
				ended = append(ended, r)
			}
			delete(c.used, s)
			delete(c.watched, s)
		}
	}
	m.leave(ended...)
	return len(ended)
}

// BrokerGone: the broker's connection drops, and with it every live set; a new broker connects. A NameOwnerChanged
// that one set's removal causes may reach a client while another set is still there and mark it used, so a client
// that watched a set may end too: the model takes those from what happened
func (mc *machine) BrokerGone(t *rapid.T) {
	m := mc.m
	watching := map[string]bool{}
	for _, c := range m.registered() {
		watching[c.role] = len(c.watched) > 0
	}
	mc.brk.conn.Close()
	mc.brk = mc.w.dialBroker()
	m.remove(slices.Clone(m.live)...)
	time.Sleep(50 * time.Millisecond)
	for _, r := range mapsKeys(watching) {
		if c := m.clients[r]; !c.closed && watching[r] && mc.clients[r].isClosed(false) {
			m.leave(r)
		}
	}
}

// ChangeThenCall: the broker adds or removes a set and a client sends its next message right away, with nothing from
// the bus in between: the message is judged by the rules there are now (fromClient), not those of the client's last
// message from the bus
func (mc *machine) ChangeThenCall(t *rapid.T) {
	before := slices.Clone(mc.m.live)
	// Mostly a removal: after an add the proxy looks up the set's owners before the message, and their answers
	// come from the bus
	if len(mc.m.live) == 0 || rapid.IntRange(0, 3).Draw(t, "add") == 0 {
		mc.AddSet(t)
	} else {
		mc.RemoveSet(t)
	}
	// What the change sends the clients arrives first, as it would before a client's next message: the bus dropped
	// the connections it ended, and each client got what the model says it should by now. Nothing else reaches them,
	// so their proxies hold the rules of their last message
	mc.awaitExpected(t)
	// Mostly to a name of the set that changed
	mc.prefer = nil
	for _, s := range append(before, mc.m.live...) {
		if slices.Contains(before, s) != slices.Contains(mc.m.live, s) {
			mc.prefer = append(mc.prefer, s.rs.Names()...)
		}
	}
	defer func() { mc.prefer = nil }()
	if rapid.IntRange(0, 3).Draw(t, "bus") == 0 {
		mc.BusCall(t)
	} else {
		mc.Call(t)
	}
}

// The broker's end of the control socket
type broker struct {
	conn *net.UnixConn
	r    *bufio.Reader
}

// dialBroker connects as the broker, waiting for the proxy to be done with a previous broker's connection
func (w *world) dialBroker() *broker {
	var b *broker
	w.waitFor("the control socket", func() bool {
		conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: w.ctlPath, Net: "unix"})
		if err != nil {
			return false
		}
		b = &broker{conn: conn, r: bufio.NewReader(conn)}
		// A request of no effect: answered only once the proxy took the connection
		if res := b.do(map[string]any{"op": "remove", "id": "none"}); res == nil {
			conn.Close()
			return false
		}
		return true
	})
	w.t.Cleanup(func() { b.conn.Close() })
	return b
}

// Sends a request and returns the answer, or nil when the proxy closed the connection
func (b *broker) do(req map[string]any) *controlResponse {
	data, _ := json.Marshal(req)
	b.conn.SetDeadline(time.Now().Add(settle))
	if _, err := b.conn.Write(append(data, '\n')); err != nil {
		return nil
	}
	line, err := b.r.ReadBytes('\n')
	if err != nil {
		return nil
	}
	var res controlResponse
	if json.Unmarshal(line, &res) != nil {
		return nil
	}
	return &res
}
