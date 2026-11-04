package judge

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// A connection's state alone, for what a real bus won't let a test arrange
func testJudge(t *testing.T, args ...string) *Judge {
	t.Helper()
	rs, err := rules.Parse(rules.Args{See: args})
	if err != nil {
		t.Fatal(err)
	}
	r := rules.New(rs)
	return New(r, false)
}

// A message as the proxy would read it
func fakeMessage(t *testing.T, typ dbus.Type, serial uint32, headers map[dbus.HeaderField]any, body ...any) *wire.Message {
	t.Helper()
	h := map[dbus.HeaderField]dbus.Variant{}
	for k, v := range headers {
		h[k] = dbus.MakeVariant(v)
	}
	if len(body) > 0 {
		h[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
	}
	data, err := wire.Encode(&dbus.Message{Type: typ, Headers: h, Body: body}, serial)
	if err != nil {
		t.Fatal(err)
	}
	m, err := wire.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A reply to a call to the bus is taken only from the bus: a peer's, with the serial of the client's pending
// GetNameOwner, is dropped and the call stays pending
func TestBusReplyOnlyFromBus(t *testing.T) {
	j := testJudge(t)
	j.awaitBus[7] = expect{kind: expectHello, fromBus: true}
	forged := fakeMessage(t, dbus.TypeMethodReply, 9, map[dbus.HeaderField]any{
		dbus.FieldReplySerial: uint32(7), dbus.FieldSender: ":1.66"}, ":1.66")
	a, err := j.FromBus(forged)
	if err != nil {
		t.Fatal(err)
	}
	if a.Verdict != Drop {
		t.Error("A peer's reply to a call to the bus passed")
	}
	if p, _ := j.names.lookup(j.rules, ":1.66"); p >= rules.Talk {
		t.Error("A peer's reply to Hello raised it to TALK")
	}
	if _, ok := j.awaitBus[7]; !ok {
		t.Error("The call no longer awaits the bus's reply")
	}
}

// A unique name the client may see is forgotten once it leaves the bus
func TestForgetLeftName(t *testing.T) {
	j := testJudge(t, "org.test.Seen")
	if err := j.names.addOwned(":1.5", "org.test.Seen"); err != nil {
		t.Fatal(err)
	}
	noc := fakeMessage(t, dbus.TypeSignal, 3, map[dbus.HeaderField]any{
		dbus.FieldSender: busName, dbus.FieldInterface: busIface, dbus.FieldMember: "NameOwnerChanged",
		dbus.FieldPath: dbus.ObjectPath("/org/freedesktop/DBus")}, ":1.5", ":1.5", "")
	if !j.passNameOwnerChanged(noc) {
		t.Fatal("The owner leaving didn't reach the client")
	}
	if _, ok := j.names.ids[":1.5"]; ok {
		t.Error("A unique name that left is still tracked")
	}
}

// The client's reply goes only to the caller that's waiting for it
func TestReplyToCaller(t *testing.T) {
	j := testJudge(t)
	j.awaitPeer[peerCall{":1.7", 4}] = struct{}{}
	for _, dest := range []string{":1.8", ""} {
		r := fakeMessage(t, dbus.TypeMethodReply, 2, map[dbus.HeaderField]any{
			dbus.FieldReplySerial: uint32(4), dbus.FieldDestination: dest})
		a, err := j.FromClient(r)
		if err != nil {
			t.Fatal(err)
		}
		if a.Verdict != Drop {
			t.Errorf("A reply to %q for :1.7's call passed", dest)
		}
	}
	r := fakeMessage(t, dbus.TypeMethodReply, 3, map[dbus.HeaderField]any{
		dbus.FieldReplySerial: uint32(4), dbus.FieldDestination: ":1.7"})
	if a, err := j.FromClient(r); err != nil || a.Verdict != Forward {
		t.Errorf("The reply to the caller was dropped: %v", err)
	}
}
