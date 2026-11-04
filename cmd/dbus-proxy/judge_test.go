package main

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// A client's state alone, for what a real bus won't let a test arrange
func testClient(t *testing.T, args ...string) *client {
	t.Helper()
	rs := NewRuleSet()
	for _, a := range args {
		if err := rs.AddPolicy(a, policySee); err != nil {
			t.Fatal(err)
		}
	}
	return &client{p: &Proxy{rules: NewRules(rs)}, awaitBus: map[uint32]expect{},
		awaitPeer: map[peerCall]struct{}{}, names: newNameTable()}
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
	c := testClient(t)
	c.awaitBus[7] = expect{kind: expectHello, fromBus: true}
	forged := fakeMessage(t, dbus.TypeMethodReply, 9, map[dbus.HeaderField]any{
		dbus.FieldReplySerial: uint32(7), dbus.FieldSender: ":1.66"}, ":1.66")
	var fakes [][]byte
	if _, err := c.judgeBus(forged, &fakes); err != nil {
		t.Fatal(err)
	}
	if forged.Message != nil {
		t.Error("A peer's reply to a call to the bus passed")
	}
	if p, _ := c.names.lookup(c.p.rules, ":1.66"); p >= policyTalk {
		t.Error("A peer's reply to Hello raised it to TALK")
	}
	if _, ok := c.awaitBus[7]; !ok {
		t.Error("The call no longer awaits the bus's reply")
	}
}

// A unique name the client may see is forgotten once it leaves the bus
func TestForgetLeftName(t *testing.T) {
	c := testClient(t, "org.test.Seen")
	if err := c.names.addOwned(":1.5", "org.test.Seen"); err != nil {
		t.Fatal(err)
	}
	noc := fakeMessage(t, dbus.TypeSignal, 3, map[dbus.HeaderField]any{
		dbus.FieldSender: busName, dbus.FieldInterface: busIface, dbus.FieldMember: "NameOwnerChanged",
		dbus.FieldPath: dbus.ObjectPath("/org/freedesktop/DBus")}, ":1.5", ":1.5", "")
	if !c.passNameOwnerChanged(noc) {
		t.Fatal("The owner leaving didn't reach the client")
	}
	if _, ok := c.names.ids[":1.5"]; ok {
		t.Error("A unique name that left is still tracked")
	}
}

// The client's reply goes only to the caller that's waiting for it
func TestReplyToCaller(t *testing.T) {
	c := testClient(t)
	c.awaitPeer[peerCall{":1.7", 4}] = struct{}{}
	for _, dest := range []string{":1.8", ""} {
		r := fakeMessage(t, dbus.TypeMethodReply, 2, map[dbus.HeaderField]any{
			dbus.FieldReplySerial: uint32(4), dbus.FieldDestination: dest})
		if _, err := c.judgeClient(r, nil); err != nil {
			t.Fatal(err)
		}
		if r.Message != nil {
			t.Errorf("A reply to %q for :1.7's call passed", dest)
		}
	}
	r := fakeMessage(t, dbus.TypeMethodReply, 3, map[dbus.HeaderField]any{
		dbus.FieldReplySerial: uint32(4), dbus.FieldDestination: ":1.7"})
	if _, err := c.judgeClient(r, nil); err != nil || r.Message == nil {
		t.Errorf("The reply to the caller was dropped: %v", err)
	}
}
