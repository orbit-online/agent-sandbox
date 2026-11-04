package main

import (
	"fmt"
	"slices"

	"github.com/godbus/dbus/v5"
	"pgregory.net/rapid"
)

// The state machine's client actions, the attacker's moves in models/proxy.als: connect, Hello, disconnect, calls to
// names allowed and hidden with fresh, reused and forged serials, and replies to the calls it got, asked or not

const machineClients = 3

// pick draws one of roles, or skips the action when there are none
func pick(t *rapid.T, roles []string, label string) string {
	if len(roles) == 0 {
		t.Skip("no " + label)
	}
	return rapid.SampledFrom(roles).Draw(t, label)
}

// The clients connected (helloed or not), and those registered on the bus
func (mc *machine) open() []string {
	var out []string
	for _, r := range mapsKeys(mc.m.clients) {
		if !mc.m.clients[r].closed {
			out = append(out, r)
		}
	}
	return out
}

func (mc *machine) registered() []string {
	var out []string
	for _, c := range mc.m.registered() {
		out = append(out, c.role)
	}
	return out
}

// Connect: a client connects through the proxy and authenticates
func (mc *machine) Connect(t *rapid.T) {
	if len(mc.open()) >= machineClients {
		t.Skip("enough clients")
	}
	mc.connect()
}

func (mc *machine) connect() string {
	role := fmt.Sprintf("c%d", mc.nclient)
	mc.nclient++
	mc.clients[role] = mc.w.dial(role, mc.w.addr)
	mc.m.newClient(role)
	return role
}

// Hello: a client registers; a second Hello is refused. The proxy watches the static rules' names and the live sets'
// and looks up their owners (initialNameOps)
func (mc *machine) Hello(t *rapid.T) {
	var fresh []string
	for _, r := range mc.open() {
		if !mc.m.clients[r].helloed {
			fresh = append(fresh, r)
		}
	}
	if len(fresh) == 0 || rapid.IntRange(0, 4).Draw(t, "again") == 0 {
		fresh = mc.open()
	}
	role := pick(t, fresh, "client")
	c, p := mc.m.clients[role], mc.clients[role]
	if c.helloed {
		mc.busCall(t, c, p, mc.fresh(p), "Hello", "")
		return
	}
	mc.hello(t, role)
}

func (mc *machine) hello(t *rapid.T, role string) {
	c, p := mc.m.clients[role], mc.clients[role]
	r := p.hello(mc.w)
	if r == nil || r.typ != dbus.TypeMethodReply {
		t.Fatalf("Hello of %s: %+v", role, r)
	}
	c.sent = append(c.sent, p.serial)
	c.helloed = true
	c.raise(role, policyTalk)
	m := mc.m
	m.lookupNames(c, NewRules(m.static).names())
	for _, s := range m.live {
		c.watched[s] = true
		m.lookupNames(c, s.rs.names())
	}
	m.rec(role, "S NameAcquired bus -> %s [%s]", role, role)
}

// Disconnect: a client hangs up
func (mc *machine) Disconnect(t *rapid.T) {
	role := pick(t, mc.open(), "client")
	mc.clients[role].conn.Close()
	mc.m.leave(role)
}

func (mc *machine) fresh(p *party) uint32 {
	p.serial++
	return p.serial
}

// drawSerial: mostly fresh, sometimes one the client used (a pending one when there is), sometimes in the proxy's
// range
func (mc *machine) drawSerial(t *rapid.T, c *refClient, p *party) uint32 {
	switch rapid.SampledFrom([]string{"fresh", "fresh", "fresh", "fresh", "fresh", "fresh", "fresh", "fresh", "reused", "reused", "reused", "forged"}).Draw(t, "serial") {
	case "reused":
		pending := slices.Sorted(func(yield func(uint32) bool) {
			for s := range c.pending {
				if !yield(s) {
					return
				}
			}
		})
		if len(pending) > 0 && rapid.Bool().Draw(t, "pending") {
			return rapid.SampledFrom(pending).Draw(t, "reuse")
		}
		if len(c.sent) > 0 {
			return rapid.SampledFrom(c.sent).Draw(t, "reuse")
		}
	case "forged":
		return maxClientSerial + 1
	}
	return mc.fresh(p)
}

// destinations: every name a call may go to, the services' and clients' unique names included
func (mc *machine) destinations() []string {
	out := append(append([]string{}, allNames...), "svc0", "svc1")
	for _, r := range mapsKeys(mc.clients) {
		if mc.clients[r].unique != "" {
			out = append(out, r)
		}
	}
	return out
}

// The bus name of a destination: a role's unique name, or the name itself
func (mc *machine) busNameOf(name string) string {
	if p := mc.party(name); p != nil && p.unique != "" {
		return p.unique
	}
	return name
}

func echoCall(dest, member, tok string) *dbus.Message {
	return &dbus.Message{Type: dbus.TypeMethodCall, Flags: dbus.FlagNoAutoStart, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(dest),
		dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/org/test")),
		dbus.FieldInterface:   dbus.MakeVariant(svcIface),
		dbus.FieldMember:      dbus.MakeVariant(member),
		dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf("")),
	}, Body: []any{tok}}
}

// Call: a registered client calls a method of a name, a service's or another client's, with a drawn serial; or
// carrying the serial of a call it got as a reply serial
func (mc *machine) Call(t *rapid.T) {
	role := pick(t, mc.registered(), "client")
	c, p := mc.m.clients[role], mc.clients[role]
	dest := rapid.SampledFrom(mc.destinations()).Draw(t, "dest")
	if len(mc.prefer) > 0 && rapid.IntRange(0, 3).Draw(t, "changed") > 0 {
		dest = rapid.SampledFrom(mc.prefer).Draw(t, "name")
	}
	member := rapid.SampledFrom([]string{"Echo", "Other"}).Draw(t, "member")
	tok := mc.token()
	msg := echoCall(mc.busNameOf(dest), member, tok)
	withReply := len(c.peer) > 0 && rapid.IntRange(0, 9).Draw(t, "withReplySerial") == 0
	if withReply {
		k := rapid.SampledFrom(sortedKeys(c.peer)).Draw(t, "replySerial")
		msg.Headers[dbus.FieldReplySerial] = dbus.MakeVariant(k.serial)
	}
	serial := mc.drawSerial(t, c, p)
	p.tokens[serial] = tok
	_ = p.sendAs(serial, msg)
	m := mc.m
	refuse, ok := m.guard(c, serial, tok)
	if !ok {
		return
	}
	if withReply {
		refuse(errAccessDenied)
		return
	}
	pol, fs := m.lookup(c, dest)
	switch {
	case pol < policySee:
		refuse(errNameHasNoOwner)
		return
	case pol < policyTalk, pol != policyOwn && !anyMatches(fs, filterCall, "/org/test", svcIface, member):
		refuse(errAccessDenied)
		return
	}
	if !m.letThrough(c, serial) {
		return
	}
	target := m.owner(dest)
	if target == "" {
		m.rec(role, "E %s bus %s", tok, errNameHasNoOwner)
		return
	}
	c.pending[serial] = refCall{target, tok}
	if !m.busCalls(role, serial, target) {
		delete(c.pending, serial)
		m.rec(role, "E %s bus %s", tok, errAccessDenied)
		return
	}
	m.callTo(target, role, serial, member, tok, dest)
}

// busCalls records a call the bus routes from caller to callee, false when one with that serial awaits callee's reply
func (m *model) busCalls(caller string, serial uint32, callee string) bool {
	k := busKey{caller, serial, callee}
	if m.busPending[k] {
		return false
	}
	m.busPending[k] = true
	return true
}

// callTo delivers a call let through to its target, a service or a client
func (m *model) callTo(target, from string, serial uint32, member, tok, dest string) {
	if svc := m.svcs[target]; svc != nil {
		svc.in = append(svc.in, refIncoming{from, serial, tok})
		m.rec(target, "C %s %s %s -> %s", member, tok, from, dest)
		return
	}
	if m.fromPeer(m.clients[target], from, false, true, serial, "/org/test", svcIface, member) {
		m.rec(target, "C %s %s %s -> %s", member, tok, from, dest)
	}
}

// guard is what comes before any rule for a call (fromClient, judgeClient): a serial in the proxy's range ends the
// connection. It returns how the proxy refuses this call: with an error, or by ending the connection when the serial
// awaits a reply already (the refusal is a Ping on that serial)
func (m *model) guard(c *refClient, serial uint32, tok string) (func(string), bool) {
	c.sent = append(c.sent, serial)
	if serial > maxClientSerial {
		m.leave(c.role)
		return nil, false
	}
	return func(err string) {
		if m.letThrough(c, serial) {
			m.rec(c.role, "E %s proxy %s", tok, err)
		}
	}, true
}

// letThrough: a call with a serial still awaiting its reply ends the connection (expectFromBus)
func (m *model) letThrough(c *refClient, serial uint32) bool {
	if _, ok := c.pending[serial]; ok {
		m.leave(c.role)
		return false
	}
	return true
}

func sortedKeys(mp map[peerKey]bool) []peerKey {
	out := make([]peerKey, 0, len(mp))
	for k := range mp {
		out = append(out, k)
	}
	slices.SortFunc(out, func(a, b peerKey) int {
		if a.caller != b.caller {
			if a.caller < b.caller {
				return -1
			}
			return 1
		}
		return int(a.serial) - int(b.serial)
	})
	return out
}

// Reply: a registered client answers a call it got, or one it didn't (another caller's serial), with a return or an
// error. Only a reply to a call it got, sent to its caller, passes (judgeClient)
func (mc *machine) Reply(t *rapid.T) {
	role := pick(t, mc.registered(), "client")
	c, p := mc.m.clients[role], mc.clients[role]
	keys := sortedKeys(c.peer)
	var k peerKey
	if len(keys) > 0 && rapid.IntRange(0, 3).Draw(t, "asked") > 0 {
		k = rapid.SampledFrom(keys).Draw(t, "call")
	} else {
		k = peerKey{rapid.SampledFrom(append([]string{"svc0", "svc1"}, mc.registered()...)).Draw(t, "caller"),
			uint32(rapid.IntRange(1, 40).Draw(t, "forged"))}
	}
	isErr := rapid.Bool().Draw(t, "error")
	tok := mc.token()
	serial := mc.fresh(p)
	c.sent = append(c.sent, serial)
	_ = p.sendAs(serial, replyMsg(mc.busNameOf(k.caller), k.serial, isErr, tok))
	if !c.peer[k] {
		return
	}
	delete(c.peer, k)
	mc.m.answer(k.caller, role, k.serial, isErr, tok, serial)
}

func replyMsg(dest string, rs uint32, isErr bool, tok string) *dbus.Message {
	m := &dbus.Message{Type: dbus.TypeMethodReply, Flags: dbus.FlagNoReplyExpected, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(dest),
		dbus.FieldReplySerial: dbus.MakeVariant(rs),
		dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf("")),
	}, Body: []any{tok}}
	if isErr {
		m.Type = dbus.TypeError
		m.Headers[dbus.FieldErrorName] = dbus.MakeVariant(errTest)
	}
	return m
}

const errTest = "org.test.Error.Nope"

// answer: from's reply to caller's serial reaches the caller: a service gets any, a client's proxy only one to a
// call it let through. A reply to a caller gone from the bus comes back to a service as an error to its message sent
func (m *model) answer(caller, from string, serial uint32, isErr bool, tok string, sent uint32) {
	delete(m.busPending, busKey{caller, serial, from})
	if m.owner(caller) == "" {
		if m.svcs[from] != nil {
			m.rec(from, "E ?%d bus %s", sent, errServiceUnknown)
		}
		return
	}
	kind, body := "R", "["+tok+"]"
	if isErr {
		kind, body = "E", errTest
	}
	if svc := m.svcs[caller]; svc != nil {
		if call, ok := svc.out[serial]; ok {
			delete(svc.out, serial)
			m.rec(caller, "%s %s %s %s", kind, call.tok, from, body)
		} else {
			m.rec(caller, "%s ?%d %s %s", kind, serial, from, body)
		}
		return
	}
	if call, ok := m.replyTo(m.clients[caller], from, serial); ok {
		m.rec(caller, "%s %s %s %s", kind, call.tok, from, body)
	}
}
