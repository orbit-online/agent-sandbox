package judge

import (
	"slices"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"pgregory.net/rapid"
)

// The judge machine's generated messages: names and bodies from the grammar (internal/gen) mixed with the machine's
// own, valid and broken, calls to the bus driver with any method, byte-level mutations. The reader takes a message
// exactly when the specification's model does, and the judge's verdict is the model's (spec.ProxyVerdict). Its
// destinations are well-known names, the bus, the client itself and unique names no one owns: the proxy's table of
// what peers own is the end-to-end machine's to check

// What the oracle knows of the connection: the machine's state
type oracleView struct {
	m        *judgeMachine
	awaiting map[uint32]bool
}

func (v oracleView) Level(name string) spec.Level {
	switch {
	case name == self && v.m.selfTalk:
		return spec.Talk
	case name[0] == ':':
		return spec.None
	}
	return v.m.cfg.Level(name)
}

func (v oracleView) Calls(name, path, iface, member string) bool {
	if name == self {
		return true
	}
	return v.m.cfg.Calls(name, path, iface, member)
}

func (v oracleView) Asked(string, uint32) bool   { return false } // No peer calls the client here
func (v oracleView) Awaiting(serial uint32) bool { return v.awaiting[serial] }
func (v oracleView) HelloSent() bool             { return v.m.hello }

// Names a generated message goes to or names: the machine's, the bus's, the client's own, the grammar's
func machineNames() gen.Names {
	names := append(append([]string{busName, self, ":1.42"}, wellKnown...), "org.test.Unruled")
	dest := rapid.OneOf(rapid.SampledFrom(names), rapid.SampledFrom(names), gen.WellKnownName(), gen.UniqueName())
	return gen.Names{Dest: dest, Path: gen.ObjectPath(), Iface: rapid.OneOf(rapid.Just("org.test.I"), gen.InterfaceName()),
		Member: rapid.OneOf(rapid.Just("M"), gen.MemberName()), ErrorName: gen.InterfaceName()}
}

// Members of the bus driver: those the proxy passes, those it doesn't, and the grammar's
var driverMembers = []string{"UpdateActivationEnvironment", "BecomeMonitor", "ReloadConfig", "GetMachineId",
	"GetConnectionUnixProcessID", "GetConnectionCredentials", "GetAdtAuditSessionData", "ListQueuedOwners",
	"GetConnectionSELinuxSecurityContext", "GetConnectionUnixUser", "NameHasOwner", "GetNameOwner",
	"RequestName", "ReleaseName", "StartServiceByName", "AddMatch", "RemoveMatch", "GetId", "ListNames",
	"ListActivatableNames", "Hello", "Introspect", "Ping", "Get"}

var driverIfaces = []string{busIface, busIface, busIface, "", "org.freedesktop.DBus.Monitoring",
	"org.freedesktop.DBus.Introspectable", "org.freedesktop.DBus.Peer", "org.freedesktop.DBus.Properties"}

// A call to the bus driver: any member on any of its interfaces, a name or a match rule as its first argument
func genDriverCall(t *rapid.T, m *gen.Msg) {
	m.Type = 1
	m.Fields = nil
	m.Set(gen.StrField(1, "/org/freedesktop/DBus"))
	m.Set(gen.StrField(6, busName))
	if iface := rapid.SampledFrom(driverIfaces).Draw(t, "iface"); iface != "" {
		m.Set(gen.StrField(2, iface))
	}
	m.Set(gen.StrField(3, rapid.OneOf(rapid.SampledFrom(driverMembers), gen.MemberName()).Draw(t, "member")))
	arg := rapid.OneOf(machineNames().Dest, rapid.SampledFrom([]string{"", "type='signal'", "eavesdrop=true",
		"type='signal',eavesdrop \t= 'false'", "member='eavesdrop'"})).Draw(t, "arg0")
	switch rapid.IntRange(0, 5).Draw(t, "args") {
	case 0:
		m.Args()
	case 1:
		m.Args(arg, uint32(4))
	case 2:
		m.Args([]string{arg})
	default:
		m.Args(arg)
	}
	if rapid.IntRange(0, 4).Draw(t, "bodyMiss") == 0 {
		m.Body = gen.BodyMiss(m.Order(), m.Str(8), m.Body).Draw(t, "miss")
	}
	gen.Perturb(t, m)
}

// Generated: the client sends a generated message, perhaps to the bus driver, perhaps mutated at the byte level
func (m *judgeMachine) Generated(t *rapid.T) {
	msg := gen.Message(machineNames(), rapid.Uint32Range(1, m.serial+1)).Draw(t, "msg")
	if rapid.Bool().Draw(t, "driver") {
		genDriverCall(t, msg)
	}
	if m.j.Held() != nil {
		t.Skip("held")
	}
	m.serial++
	msg.Serial = m.serial
	switch rapid.IntRange(0, 9).Draw(t, "serial") {
	case 0:
		msg.Serial = MaxClientSerial + 1
	case 1:
		if awaiting := m.awaiting(); len(awaiting) > 0 {
			msg.Serial = rapid.SampledFrom(awaiting).Draw(t, "reused")
		}
	}
	raw := msg.Encode()
	if rapid.IntRange(0, 4).Draw(t, "mutate") == 0 {
		raw = gen.Mutate(t, raw)
	}
	read, sm, why := spec.ProxyReads(raw, 0)
	if read == spec.Waiting {
		return
	}
	n := len(raw)
	if sm != nil {
		n = sm.Len
	}
	w, err := wire.Parse(raw[:n])
	if (err == nil) != (read == spec.Judged) {
		t.Fatalf("The reader: %v, the model: %v %s", err, read, why)
	}
	if err != nil {
		return
	}
	awaiting := map[uint32]bool{}
	for _, s := range m.awaiting() {
		awaiting[s] = true
	}
	if sm.Serial <= MaxClientSerial {
		// A mutation may have made it a later serial: the fresh ones go past it
		m.serial = max(m.serial, sm.Serial)
	}
	want := spec.ProxyVerdict(sm, oracleView{m, awaiting})
	a, err := m.j.FromClient(w)
	if (want.Kind == spec.End) != (err != nil) {
		t.Fatalf("Connection ended %v (%v), want %v", err != nil, err, want.Kind == spec.End)
	}
	if err != nil {
		m.connect()
		return
	}
	m.busTakes(t, a.Calls)
	verdict := map[spec.Kind]Verdict{spec.Forward: Forward, spec.Refuse: Replace, spec.Drop: Drop}[want.Kind]
	if a.Verdict != verdict {
		t.Fatalf("Verdict %v, want %v (%s): type %d flags %d serial %d fields %+v body %x", a.Verdict, verdict,
			want.Error, sm.Type, sm.Flags, sm.Serial, sm.Fields, sm.Body[:min(len(sm.Body), 64)])
	}
	serial, member := sm.Serial, sm.Str(spec.FieldMember)
	wantsReply := sm.Type == spec.TypeCall && sm.Flags&spec.FlagNoReplyExpected == 0
	switch a.Verdict {
	case Replace:
		m.refusals[serial] = want.Error
		m.rewrites[serial] = true
		m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName) })
	case Forward:
		m.forwarded(t, sm, want.ToBus, wantsReply, serial, member)
	}
}

// A generated message let through: D1 for its destination, and the bus's answer
func (m *judgeMachine) forwarded(t *rapid.T, sm *spec.Message, toBus, wantsReply bool, serial uint32, member string) {
	dest := sm.Str(spec.FieldDestination)
	if !toBus && dest != "" && !m.allowed(dest) {
		t.Fatalf("D1: a message to %s passed outside the rules", dest)
	}
	hello := toBus && member == "Hello" && sm.Str(spec.FieldInterface) == busIface
	if hello {
		m.hello = true
	}
	if !wantsReply {
		return
	}
	m.pending[serial] = toBus
	switch {
	case hello:
		m.helloSerial = serial
		m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName, self) })
	case toBus && (member == "ListNames" || member == "ListActivatableNames"):
		m.listNames[serial] = true
		m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName, []string{busName, self}) })
	case toBus:
		m.queue = append(m.queue, func() *dbus.Message { return reply(serial, busName) })
	}
}

// checkRefusal: a refusal's reply as the judge made it carries the error the oracle said
func (m *judgeMachine) checkRefusal(t *rapid.T, rs uint32, a Action) {
	want, ok := m.refusals[rs]
	if !ok {
		return
	}
	delete(m.refusals, rs)
	if a.Verdict != Replace {
		t.Fatalf("The refusal of %d: %v", rs, a.Verdict)
	}
	r, err := wire.Parse(a.Message)
	if err != nil {
		t.Fatal(err)
	}
	got := r.Header(dbus.FieldErrorName)
	if want == spec.FalseReply {
		r.DecodeBody(64)
		if r.Type != dbus.TypeMethodReply || len(r.Body) != 1 || r.Body[0] != false {
			t.Fatalf("NameHasOwner of a hidden name: %v %v", r.Type, r.Body)
		}
		return
	}
	if got != want {
		t.Fatalf("Refused with %q, want %q", got, want)
	}
}

// The serials of the client's calls awaiting a reply from the bus side: let through or refused through a Ping, sorted
func (m *judgeMachine) awaiting() []uint32 {
	var out []uint32
	for s := range m.pending {
		out = append(out, s)
	}
	for s := range m.rewrites {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}
