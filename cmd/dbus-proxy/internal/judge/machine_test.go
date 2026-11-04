package judge

import (
	"flag"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"pgregory.net/rapid"
)

// A stateful property test of one connection's Judge without sockets or a bus: rapid drives the judge with
// models/proxy.als's actions, the bus played by a queue of what it sends back, answered one at a time in order, so
// replies and owners' changes interleave in any order the bus could send them. After every step: D1, a call forwarded
// to a destination only when the rules let the client call one of its names, through every name the bus ever saw its
// unique name own (the proxy's table is sticky), and a NameOwnerChanged only for a name they let it see, by the
// specification's model of a config generated for each sequence; D2, a reply
// forwarded only to a call let through and awaiting one, and to a call to the bus only from the bus. 1000 sequences
// take a second; more with -rapid.checks
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
	rules    *rules.Rules
	cfg      *spec.Config // The config as the specification's model reads it, for the checks
	j        *Judge
	hello    bool
	selfTalk bool // The client's Hello was answered: its own name is TALK
	// The serial of the client's Hello
	helloSerial uint32
	serial      uint32
	// The refusals made up for the client's messages, by serial: the error the oracle says (machine_oracle_test.go)
	refusals map[uint32]string
	// The refused calls whose Ping awaits the bus's reply, and the ListNames calls awaiting theirs
	rewrites  map[uint32]bool
	listNames map[uint32]bool
	// The bus: who owns each name now, every name each unique name ever owned, the names a match rule watches and
	// what it has yet to send
	owner   map[string]string
	owned   map[string]map[string]bool
	watched map[string]int
	queue   []busMsg
	// The calls let through awaiting a reply, by serial: whether to the bus
	pending map[uint32]bool
}

func newJudgeMachine(t *rapid.T) *judgeMachine {
	// A config of the machine's names, its call's path, interface and member and the grammar's
	data := gen.Config(gen.ConfigNames{Name: rapid.SampledFrom(wellKnown),
		Path:   rapid.OneOf(rapid.SampledFrom([]string{"/", "/org"}), gen.ObjectPath().Filter(spec.Path)),
		Iface:  rapid.OneOf(rapid.SampledFrom([]string{"org.test.I", "org.test"}), gen.InterfaceName().Filter(spec.Interface)),
		Member: rapid.OneOf(rapid.SampledFrom([]string{"M", "I"}), gen.MemberName().Filter(spec.Member))}, false).Draw(t, "config")
	cfg, err := spec.ParseConfig(data)
	if err != nil {
		t.Fatalf("Config %s: %v", data, err)
	}
	static, err := rules.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	m := &judgeMachine{rules: rules.New(static), cfg: cfg, owner: map[string]string{}, owned: map[string]map[string]bool{}}
	m.connect()
	return m
}

// A new connection, after the last one ended
func (m *judgeMachine) connect() {
	m.j = New(m.rules, true)
	m.hello, m.selfTalk, m.helloSerial, m.serial = false, false, 0, 0
	m.refusals, m.rewrites, m.listNames = map[uint32]string{}, map[uint32]bool{}, map[uint32]bool{}
	m.watched, m.queue = map[string]int{}, nil
	m.pending = map[uint32]bool{}
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

// Whether the config lets the client make the machine's call (/, org.test.I.M) to dest: the bus, itself, a well-known
// name that lets it, or a unique name that ever owned one
func (m *judgeMachine) allowed(dest string) bool {
	if dest == busName || dest == self {
		return true
	}
	if dest[0] != ':' {
		return m.cfg.Calls(dest, "/", "org.test.I", "M")
	}
	for n := range m.owned[dest] {
		if m.cfg.Calls(n, "/", "org.test.I", "M") {
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

// What the client sends: nothing while the client is held, as the proxy's reader does
func (m *judgeMachine) send(t *rapid.T, msg *dbus.Message) (Action, uint32) {
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
	m.hello, m.helloSerial = true, serial
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
			t.Fatalf("D1: a call to %s passed outside the rules", dest)
		}
		m.pending[serial] = false
	case Replace:
		// Refused: a Ping goes to the bus on the call's serial, whose reply becomes the refusal
		m.rewrites[serial] = true
		m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName) })
	case Drop:
		t.Fatal("A call awaiting a reply dropped")
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
	sender := rapid.SampledFrom(append([]string{busName}, peers...)).Draw(t, "sender")
	if sender == busName && m.listNames[serial] {
		// The bus answers ListNames with its names; the proxy ends a connection whose bus doesn't
		t.Skip("ListNames")
	}
	m.fromBus(t, reply(serial, sender))
}

func (m *judgeMachine) fromBus(t *rapid.T, msg *dbus.Message) {
	m.serial++
	w := parsed(t, msg, m.serial)
	a, err := m.j.FromBus(w)
	if err != nil {
		t.Fatal(err)
	}
	m.busTakes(t, a.Calls)
	sender := w.Header(dbus.FieldSender)
	if rs, ok := w.ReplySerial(); ok && sender == busName && m.rewrites[rs] {
		// The bus's reply to a refusal's Ping, or a forged one in its place: it becomes the refusal
		delete(m.rewrites, rs)
		m.checkRefusal(t, rs, a)
		return
	}
	if rs, ok := w.ReplySerial(); ok && a.Verdict == Replace {
		// A ListNames reply, filtered
		if toBus, ok := m.pending[rs]; !ok || !toBus || sender != busName {
			t.Fatalf("D2: a reply to %d made up for the client unasked", rs)
		}
		delete(m.pending, rs)
		delete(m.listNames, rs)
		return
	}
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
		if name, _ := arg0(w); rs == m.helloSerial && name == self {
			m.selfTalk = true
		}
		return
	}
	if name, _ := arg0(w); m.cfg.Level(name) < spec.See {
		t.Fatalf("D1: NameOwnerChanged of %s passed outside the rules", name)
	}
}

func (m *judgeMachine) Check(t *rapid.T) {}
