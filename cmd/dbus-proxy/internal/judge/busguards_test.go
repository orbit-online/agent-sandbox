package judge

import (
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// The error a refused call becomes, "" when it isn't refused
func refusal(t *testing.T, j *Judge, m *wire.Message) string {
	t.Helper()
	a, err := j.FromClient(m)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != Replace {
		return ""
	}
	return j.awaitBus[m.Serial()].rewrite.Headers[dbus.FieldErrorName].Value().(string)
}

// A message as the proxy would read it, with the given serial
func fakeEncoded(t *testing.T, msg *dbus.Message, serial uint32) *wire.Message {
	t.Helper()
	data, err := wire.Encode(msg, serial)
	if err != nil {
		t.Fatal(err)
	}
	m, err := wire.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func driverCall(t *testing.T, serial uint32, iface, member string, args ...any) *wire.Message {
	t.Helper()
	m := busCall(member, args...)
	if iface == "" {
		delete(m.Headers, dbus.FieldInterface)
	} else {
		m.Headers[dbus.FieldInterface] = dbus.MakeVariant(iface)
	}
	return fakeEncoded(t, m, serial)
}

// The bus driver's methods the proxy has no case for are refused (verdict's default): UpdateActivationEnvironment
// sets the environment, LD_PRELOAD included, of every service the bus activates later, and the rest of the driver's
// interface may grow. Whatever the rules: a client with talk on everything it names
func TestBusDriverDefaultDeny(t *testing.T) {
	rs, err := rules.Decode([]byte(`{"org.test.A": {"policy": "own"}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := rules.New(rs)
	j := New(r, false)
	for i, member := range []string{"UpdateActivationEnvironment", "ReloadConfig", "GetMachineId", "Ping",
		"GetAllMatchRules", "Frobnicate"} {
		m := driverCall(t, uint32(10+i), busIface, member, map[string]string{"LD_PRELOAD": "/tmp/x.so"})
		if got := refusal(t, j, m); got != ErrAccessDenied {
			t.Errorf("%s: %q", member, got)
		}
	}
}

// Monitoring is refused before any rule is looked at (readsOthersTraffic): the Monitoring interface whatever the
// member, BecomeMonitor on the bus's interface or without one. The verdict's default refuses these calls too, so this
// guard is pinned on its own here
func TestMonitoringGuard(t *testing.T) {
	for i, c := range []struct{ iface, member string }{
		{"org.freedesktop.DBus.Monitoring", "BecomeMonitor"}, {"org.freedesktop.DBus.Monitoring", "Other"},
		{busIface, "BecomeMonitor"}, {"", "BecomeMonitor"},
	} {
		if !readsOthersTraffic(driverCall(t, uint32(10+i), c.iface, c.member, []string{}, uint32(0))) {
			t.Errorf("%s.%s passed the monitoring guard", c.iface, c.member)
		}
	}
	for i, c := range []struct{ iface, member string }{
		{"org.freedesktop.DBus.Peer", "BecomeMonitor"}, {busIface, "GetId"},
	} {
		if readsOthersTraffic(driverCall(t, uint32(20+i), c.iface, c.member)) {
			t.Errorf("%s.%s taken for monitoring", c.iface, c.member)
		}
	}
}

// The bus's Introspectable interface passes, whatever the member
func TestBusIntrospectable(t *testing.T) {
	j := testJudge(t, `{}`)
	if got := refusal(t, j, driverCall(t, 10, "org.freedesktop.DBus.Introspectable", "Introspect")); got != "" {
		t.Errorf("Introspect refused: %q", got)
	}
}

// A bus call's body is decoded only up to maxInspectBody: an AddMatch whose body is a large string array costs no
// decoding (decoded, its half a million strings would cost as many allocations), and one whose rule is a string past
// the cap is refused unread, though the rule itself asks for nothing
func TestInspectCap(t *testing.T) {
	j := testJudge(t, `{}`)
	big := make([]string, (wire.MaxMessageSize-1024)/8)
	m := driverCall(t, 10, busIface, "AddMatch", big)
	if allocs := testing.AllocsPerRun(1, func() { m.DecodeBody(maxInspectBody); arg0(m) }); allocs > 100 {
		t.Errorf("Inspecting a large body took %v allocations", allocs)
	}
	if got := refusal(t, j, m); got != ErrAccessDenied {
		t.Errorf("AddMatch of a string array: %q", got)
	}
	// The cap is 4 KiB, as docs/permissions.md has it: a rule of 4 KiB with its length and nul is past it
	rule := "type='signal',arg0='" + strings.Repeat("x", 4<<10) + "'"
	if got := refusal(t, j, driverCall(t, 11, busIface, "AddMatch", rule)); got != ErrAccessDenied {
		t.Errorf("AddMatch past the cap: %q", got)
	}
	if got := refusal(t, j, driverCall(t, 12, busIface, "AddMatch", rule[:4000]+"'")); got != "" {
		t.Errorf("AddMatch under the cap: %q", got)
	}
}
