package main

import (
	"fmt"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"pgregory.net/rapid"
)

// The end-to-end machine's generated messages: a client sends a message drawn from the grammar (internal/gen), to the
// names of the machine's world and the grammar's, to the bus driver with any method, perhaps broken at the header or
// mutated at the byte level. The specification's model says whether the proxy reads it (spec.ProxyReads), its
// verdict (spec.ProxyVerdict) whether it passes, is refused with which error, dropped, or ends the connection. One
// that would pass with a body that contradicts its signature (spec.CheckBody) isn't sent: what the bus does with it
// is the bus's. What reaches the other parties is the reference
// model's, every other client's connection going on

// What the oracle knows of client c: the reference model's state
type modelView struct {
	mc *machine
	c  *refClient
}

func (v modelView) role(name string) (string, bool) {
	if !spec.BusName(name) {
		return "", false
	}
	return v.mc.w.role(name), true
}

func (v modelView) Level(name string) spec.Level {
	role, ok := v.role(name)
	if !ok {
		return spec.None
	}
	p, _ := v.mc.m.lookup(v.c, role)
	return spec.Level(p)
}

func (v modelView) Calls(name, path, iface, member string) bool {
	role, ok := v.role(name)
	if !ok {
		return false
	}
	_, fs := v.mc.m.lookup(v.c, role)
	return rules.AnyMatches(fs, rules.Call, path, iface, member)
}

func (v modelView) Asked(caller string, serial uint32) bool {
	role, _ := v.role(caller)
	return v.c.peer[peerKey{role, serial}]
}

func (v modelView) Awaiting(serial uint32) bool { _, ok := v.c.pending[serial]; return ok }
func (v modelView) HelloSent() bool             { return v.c.helloed }

// The bus driver's methods a generated call may name: those the proxy refuses and those it passes that change
// nothing on the bus (BusCall has the rest), and the grammar's
var genDriverMembers = []string{"UpdateActivationEnvironment", "BecomeMonitor", "ReloadConfig", "GetMachineId",
	"GetConnectionUnixProcessID", "GetConnectionCredentials", "GetConnectionUnixUser", "ListQueuedOwners",
	"NameHasOwner", "GetNameOwner", "GetId", "ListNames", "ListActivatableNames", "Introspect", "Ping"}

var genDriverIfaces = []string{spec.BusIface, spec.BusIface, "", "org.freedesktop.DBus.Monitoring",
	"org.freedesktop.DBus.Introspectable", "org.freedesktop.DBus.Peer", "org.freedesktop.DBus.Properties"}

func (mc *machine) genNames() gen.Names {
	// Not the activatable name: the bus holds what goes to it, a call or one with a broken body, until someone takes
	// it (Start has it)
	var names []string
	for _, d := range mc.destinations() {
		if d != lazyName {
			names = append(names, mc.busNameOf(d))
		}
	}
	dest := rapid.OneOf(rapid.SampledFrom(names), rapid.SampledFrom(names), gen.WellKnownName(), gen.UniqueName())
	return gen.Names{Dest: dest, Path: rapid.OneOf(rapid.Just("/org/test"), gen.ObjectPath()),
		Iface: rapid.OneOf(rapid.Just(svcIface), gen.InterfaceName()), Member: rapid.OneOf(rapid.Just("Echo"),
			gen.MemberName()), ErrorName: gen.InterfaceName(), Huge: true}
}

// Generated: a registered client sends a generated message
func (mc *machine) Generated(t *rapid.T) {
	role := pick(t, mc.registered(), "client")
	c, p := mc.m.clients[role], mc.clients[role]
	names := mc.genNames()
	msg := gen.Message(names, rapid.Just(uint32(1))).Draw(t, "msg")
	if msg.Type == 2 || msg.Type == 3 {
		t.Skip("replies are Reply's")
	}
	if rapid.IntRange(0, 2).Draw(t, "driver") == 0 {
		msg.Type, msg.Fields = 1, nil
		msg.Set(gen.StrField(1, "/org/freedesktop/DBus"))
		msg.Set(gen.StrField(6, spec.DriverName))
		if iface := rapid.SampledFrom(genDriverIfaces).Draw(t, "iface"); iface != "" {
			msg.Set(gen.StrField(2, iface))
		}
		msg.Set(gen.StrField(3, rapid.OneOf(rapid.SampledFrom(genDriverMembers), gen.MemberName()).Draw(t, "member")))
		msg.Args(names.Dest.Draw(t, "arg0"))
		gen.Perturb(t, msg)
	}
	msg.Serial = mc.drawSerial(t, c, p)
	raw := msg.Encode()
	if rapid.IntRange(0, 4).Draw(t, "mutate") == 0 {
		raw = gen.Mutate(t, raw)
	}
	read, sm, _ := spec.ProxyReads(raw, 0)
	if read == spec.Judged && sm.Len < len(raw) {
		// Bytes after the message start another, which the proxy reads while the first is on its way: a race this
		// machine leaves to the judge's
		raw = raw[:sm.Len]
	}
	var v spec.Verdict
	if read == spec.Judged {
		v = spec.ProxyVerdict(sm, modelView{mc, c})
		if v.Kind == spec.Forward && spec.CheckBody(sm) != nil {
			// A body that contradicts its signature is the bus's to refuse, which it does by disconnecting the
			// proxy's connection, or, seen here, by holding it: the judge's machine has the proxy pass them
			t.Skip("a broken body the proxy passes")
		}
	}
	tok := mc.token()
	if sm != nil {
		if _, pending := c.pending[sm.Serial]; !pending {
			p.tokens[sm.Serial] = tok
		}
		mc.w.setCallTok(p.unique, sm.Serial, tok)
		c.sent = append(c.sent, sm.Serial)
	}
	// The proxy may close the connection before it read all of it
	_, _ = p.conn.Write(raw)
	m := mc.m
	switch read {
	case spec.Waiting:
		p.conn.Close()
		m.leave(role)
		return
	case spec.Closed:
		m.leave(role)
		return
	}
	switch v.Kind {
	case spec.End:
		m.leave(role)
	case spec.Refuse:
		if v.Error == spec.FalseReply {
			m.rec(role, "R %s proxy [false]", tok)
		} else {
			m.rec(role, "E %s proxy %s", tok, v.Error)
		}
	case spec.Forward:
		mc.genForwarded(role, sm, v.ToBus, tok)
	}
}

// genForwarded: what a generated message the proxy let through does on the bus
func (mc *machine) genForwarded(role string, sm *spec.Message, toBus bool, tok string) {
	m, c := mc.m, mc.m.clients[role]
	reply := sm.Type == spec.TypeCall && sm.Flags&spec.FlagNoReplyExpected == 0
	member, dest := sm.Str(spec.FieldMember), sm.Str(spec.FieldDestination)
	if toBus {
		if reply {
			// The bus driver's answer, whatever it is: a return or an error, from the bus
			m.rec(role, "? %s bus *", tok)
		}
		return
	}
	if dest == "" {
		// A broadcast: no party has a match rule for the generated interfaces
		return
	}
	destRole := mc.w.role(dest)
	target := m.owner(destRole)
	if sm.Type == spec.TypeSignal {
		switch {
		case m.svcs[target] != nil:
			m.rec(target, "S %s %s -> %s *", member, role, destRole)
		case target != "" && m.fromPeer(m.clients[target], role, false, false, 0, "", "", member):
			m.rec(target, "S %s %s -> %s *", member, role, destRole)
		}
		return
	}
	if target == "" {
		if reply {
			m.rec(role, "E %s bus *", tok)
		}
		return
	}
	if reply {
		c.pending[sm.Serial] = refCall{target, tok}
		if !m.busCalls(role, sm.Serial, target) {
			delete(c.pending, sm.Serial)
			m.rec(role, "E %s bus %s", tok, errAccessDenied)
			return
		}
	}
	m.callTo(target, role, sm.Serial, member, tok, destRole)
	if t := m.clients[target]; !reply && t != nil {
		// No reply expected: the callee's proxy awaits none
		delete(t.peer, peerKey{role, sm.Serial})
	}
}

// matches is whether a received message, as normal writes it, is what want says: want's trailing "*" matches any
// rest, a leading "?" any kind of reply
func matches(got, want string) bool {
	if strings.HasPrefix(want, "? ") {
		if len(got) < 2 || (got[0] != 'R' && got[0] != 'E') {
			return false
		}
		got, want = got[1:], want[1:]
	}
	if p, ok := strings.CutSuffix(want, "*"); ok {
		return strings.HasPrefix(got, p)
	}
	return got == want
}

// sameMessages is whether got and want pair up by matches
func sameMessages(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	left := append([]string(nil), got...)
	// Exact wants first, so a pattern doesn't take a message one of them needs
	order := append([]string(nil), want...)
	for i := range order {
		for j := i + 1; j < len(order); j++ {
			if strings.HasSuffix(order[i], "*") && !strings.HasSuffix(order[j], "*") {
				order[i], order[j] = order[j], order[i]
			}
		}
	}
	for _, w := range order {
		found := -1
		for i, g := range left {
			if matches(g, w) {
				found = i
				break
			}
		}
		if found < 0 {
			return false
		}
		left = append(left[:found], left[found+1:]...)
	}
	return true
}

func (w *world) setCallTok(unique string, serial uint32, tok string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.callToks[fmt.Sprintf("%s/%d", unique, serial)] = tok
}

func (w *world) callTok(unique string, serial uint32) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	tok, ok := w.callToks[fmt.Sprintf("%s/%d", unique, serial)]
	return tok, ok
}

// isToken is whether s is one of mc.token's
func isToken(s string) bool {
	if len(s) < 2 || s[0] != 't' {
		return false
	}
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
