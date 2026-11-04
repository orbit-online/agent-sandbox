package judge

import (
	"flag"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"pgregory.net/rapid"
)

// A stateful property test of one connection's Judge without sockets or a bus: rapid drives the judge with
// models/proxy.als's actions, the bus played by a queue of what it sends back, answered one at a time in order, so a
// live set can be added and removed while the proxy's lookups of its names are in flight, which the end-to-end
// machine (../../machine*_test.go) can't time. After every step: D1, a call forwarded to a destination only when the
// rules in force then let the client call one of its names, through every name the bus ever saw its unique name own
// (the proxy's table is sticky), and a NameOwnerChanged only for a name they let it see; a set removed ends the
// connection when it let a call through; D2, a reply forwarded only to a call let through and awaiting one, and to a
// call to the bus only from the bus. 1000 sequences take a second; more with -rapid.checks
func TestJudgeMachine(t *testing.T) {
	// Cheap without sockets: 1000 sequences unless the command line says otherwise
	set := false
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == "rapid.checks" })
	if !set {
		old := flag.Lookup("rapid.checks").Value.String()
		_ = flag.Set("rapid.checks", "1000")
		t.Cleanup(func() { _ = flag.Set("rapid.checks", old) })
	}
	rapid.Check(t, func(rt *rapid.T) { rt.Repeat(rapid.StateMachineActions(newJudgeMachine(rt))) })
}

const self = ":1.5"

var (
	peers     = []string{":1.10", ":1.11"}
	wellKnown = []string{"org.test.Talk", "org.test.A", "org.test.B", "org.test.Hidden"}
)

// A message the bus sends the client later, built when it's delivered
type busMsg func() *dbus.Message

type judgeMachine struct {
	cur     atomic.Pointer[rules.Rules]
	static  *rules.Set
	catalog []*rules.Set
	live    []*rules.Set
	j       *Judge
	hello   bool
	serial  uint32
	// The bus: who owns each name now, every name each unique name ever owned, the names a match rule watches and
	// what it has yet to send
	owner   map[string]string
	owned   map[string]map[string]bool
	watched map[string]int
	queue   []busMsg
	// The calls let through awaiting a reply, by serial: whether to the bus. The live sets a forwarded call needed
	pending  map[uint32]bool
	reliedOn map[*rules.Set]bool
}

func newJudgeMachine(t *rapid.T) *judgeMachine {
	parse := func(id string, a rules.Args) *rules.Set {
		rs, err := rules.ParseLive(id, a, "session", "")
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}
	static, err := rules.Parse(rules.Args{Talk: []string{"org.test.Talk"}})
	if err != nil {
		t.Fatal(err)
	}
	m := &judgeMachine{static: static, catalog: []*rules.Set{
		parse("a", rules.Args{Talk: []string{"org.test.A"}}),
		parse("b", rules.Args{Talk: []string{"org.test.B"}, See: []string{"org.test.A"}}),
	}, owner: map[string]string{}, owned: map[string]map[string]bool{}}
	m.cur.Store(rules.New(static))
	m.connect()
	return m
}

// A new connection, after the last one ended
func (m *judgeMachine) connect() {
	m.j = New(m.cur.Load, true)
	m.hello, m.serial = false, 0
	m.watched, m.queue = map[string]int{}, nil
	m.pending, m.reliedOn = map[uint32]bool{}, map[*rules.Set]bool{}
}

func parsed(t *rapid.T, msg *dbus.Message, serial uint32) *wire.Message {
	data, err := wire.Encode(msg, serial)
	if err != nil {
		t.Fatal(err)
	}
	w, err := wire.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func reply(serial uint32, sender string, body ...any) *dbus.Message {
	h := map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(serial),
		dbus.FieldDestination: dbus.MakeVariant(self)}
	if sender != "" {
		h[dbus.FieldSender] = dbus.MakeVariant(sender)
	}
	if len(body) > 0 {
		h[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
	}
	return &dbus.Message{Type: dbus.TypeMethodReply, Headers: h, Body: body}
}

// The policy of a well-known name under the rules in force
func (m *judgeMachine) policy(name string) rules.Policy {
	p, _ := m.cur.Load().Lookup(name)
	return p
}

// Whether the rules in force let the client call dest: the bus, itself, a well-known name with talk, or a unique name
// that ever owned one
func (m *judgeMachine) allowed(dest string) bool {
	if dest == busName || dest == self {
		return true
	}
	if dest[0] != ':' {
		return m.policy(dest) >= rules.Talk
	}
	for n := range m.owned[dest] {
		if m.policy(n) >= rules.Talk {
			return true
		}
	}
	return false
}

// The bus's side of the proxy's own calls: match rules take effect at once, the replies queue up
func (m *judgeMachine) busTakes(t *rapid.T, calls [][]byte) {
	for _, data := range calls {
		c, err := wire.Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		serial, member := c.Serial(), c.Header(dbus.FieldMember)
		arg, _ := arg0(c)
		switch member {
		case "AddMatch", "RemoveMatch":
			// The rule ends in arg0='NAME'
			_, name, _ := strings.Cut(arg, "arg0='")
			name = strings.TrimSuffix(name, "'")
			if member == "AddMatch" {
				m.watched[name]++
			} else {
				m.watched[name]--
			}
			m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName) })
		case "GetNameOwner":
			m.queue = append(m.queue, func() *dbus.Message {
				if o := m.owner[arg]; o != "" {
					return reply(serial, busName, o)
				}
				return &dbus.Message{Type: dbus.TypeError, Headers: map[dbus.HeaderField]dbus.Variant{
					dbus.FieldReplySerial: dbus.MakeVariant(serial), dbus.FieldSender: dbus.MakeVariant(busName),
					dbus.FieldErrorName: dbus.MakeVariant(ErrNameHasNoOwner)}}
			})
		default:
			t.Fatalf("A call of the proxy's own: %s", member)
		}
	}
}

// What the client sends: Sync first, as the proxy's reader does, and nothing while the client is held
func (m *judgeMachine) send(t *rapid.T, msg *dbus.Message) (Action, uint32) {
	calls, err := m.j.Sync()
	if err != nil {
		t.Fatal(err)
	}
	m.busTakes(t, calls)
	if m.j.Held() != nil {
		t.Skip("held")
	}
	m.serial++
	a, err := m.j.FromClient(parsed(t, msg, m.serial))
	if err != nil {
		t.Fatalf("A fresh serial: %v", err)
	}
	m.busTakes(t, a.Calls)
	return a, m.serial
}

func (m *judgeMachine) Hello(t *rapid.T) {
	if m.hello {
		t.Skip("once")
	}
	a, serial := m.send(t, busCall("Hello"))
	if a.Verdict != Forward {
		t.Fatalf("Hello: %v", a.Verdict)
	}
	m.hello = true
	m.pending[serial] = true
	m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName, self) })
}

// Call: the client calls a well-known or unique name
func (m *judgeMachine) Call(t *rapid.T) {
	if !m.hello {
		t.Skip("no Hello")
	}
	dest := rapid.SampledFrom(append(append([]string{}, wellKnown...), peers...)).Draw(t, "dest")
	a, serial := m.send(t, &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(dest), dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/")),
		dbus.FieldInterface: dbus.MakeVariant("org.test.I"), dbus.FieldMember: dbus.MakeVariant("M")}})
	switch a.Verdict {
	case Forward:
		if !m.allowed(dest) {
			t.Fatalf("D1: a call to %s passed outside the rules in force", dest)
		}
		for _, rs := range m.live {
			m.cur.Store(m.cur.Load().Without(rs))
			if !m.allowed(dest) {
				m.reliedOn[rs] = true
			}
			m.cur.Store(m.cur.Load().With(rs))
		}
		m.pending[serial] = false
	case Replace:
		// Refused: a Ping goes to the bus on the call's serial, whose reply becomes the refusal
		m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName) })
	case Drop:
		t.Fatal("A call awaiting a reply dropped")
	}
}

// AddSet and RemoveSet: the broker changes the live sets, the registry's way: the rules first, then the connection
func (m *judgeMachine) AddSet(t *rapid.T) {
	rs := rapid.SampledFrom(m.catalog).Draw(t, "set")
	if slices.Contains(m.live, rs) {
		t.Skip("live")
	}
	m.live = append(m.live, rs)
	m.cur.Store(m.cur.Load().With(rs))
	m.j.AddSet(rs)
}

func (m *judgeMachine) RemoveSet(t *rapid.T) {
	if len(m.live) == 0 {
		t.Skip("none")
	}
	rs := rapid.SampledFrom(m.live).Draw(t, "set")
	m.live = slices.DeleteFunc(m.live, func(s *rules.Set) bool { return s == rs })
	m.cur.Store(m.cur.Load().Without(rs))
	if m.j.RemoveSet(rs) {
		m.connect()
		return
	}
	if m.reliedOn[rs] {
		t.Fatalf("A set a call relied on was removed and the connection kept")
	}
}

// Owner: a name changes hands on the bus, which tells the connection when a match rule watches it
func (m *judgeMachine) Owner(t *rapid.T) {
	name := rapid.SampledFrom(wellKnown).Draw(t, "name")
	to := rapid.SampledFrom(append([]string{""}, peers...)).Draw(t, "owner")
	from := m.owner[name]
	if from == to {
		t.Skip("same")
	}
	m.owner[name] = to
	if to != "" {
		if m.owned[to] == nil {
			m.owned[to] = map[string]bool{}
		}
		m.owned[to][name] = true
	}
	if m.watched[name] > 0 {
		m.queue = append(m.queue, func() *dbus.Message {
			return &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
				dbus.FieldSender: dbus.MakeVariant(busName), dbus.FieldPath: dbus.MakeVariant(busPath),
				dbus.FieldInterface: dbus.MakeVariant(busIface), dbus.FieldMember: dbus.MakeVariant("NameOwnerChanged"),
				dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf("", "", ""))}, Body: []any{name, from, to}}
		})
	}
}

// Answer: the bus sends the next thing it has for the connection
func (m *judgeMachine) Answer(t *rapid.T) {
	if len(m.queue) == 0 {
		t.Skip("nothing")
	}
	msg := m.queue[0]()
	m.queue = m.queue[1:]
	m.fromBus(t, msg)
}

// Reply: a peer or the bus answers a serial, asked or not
func (m *judgeMachine) Reply(t *rapid.T) {
	serial := rapid.Uint32Range(1, m.serial+1).Draw(t, "serial")
	if rapid.Bool().Draw(t, "proxy's own") {
		serial = MaxClientSerial + rapid.Uint32Range(1, 64).Draw(t, "own")
	}
	m.fromBus(t, reply(serial, rapid.SampledFrom(append([]string{busName}, peers...)).Draw(t, "sender")))
}

func (m *judgeMachine) fromBus(t *rapid.T, msg *dbus.Message) {
	m.serial++
	w := parsed(t, msg, m.serial)
	a, err := m.j.FromBus(w)
	if err != nil {
		t.Fatal(err)
	}
	m.busTakes(t, a.Calls)
	if a.Verdict != Forward {
		return
	}
	if rs, ok := w.ReplySerial(); ok {
		toBus, ok := m.pending[rs]
		if !ok || rs > MaxClientSerial {
			t.Fatalf("D2: a reply to %d reached the client unasked", rs)
		}
		if toBus && w.Header(dbus.FieldSender) != busName {
			t.Fatalf("D2: %s's reply to a call to the bus reached the client", w.Header(dbus.FieldSender))
		}
		delete(m.pending, rs)
		return
	}
	if name, _ := arg0(w); m.policy(name) < rules.See {
		t.Fatalf("D1: NameOwnerChanged of %s passed outside the rules in force", name)
	}
}

func (m *judgeMachine) Check(t *rapid.T) {}
