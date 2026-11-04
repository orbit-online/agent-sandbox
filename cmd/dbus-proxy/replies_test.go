package main

import (
	"context"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// A reply to a call that was let through reaches the client, an error reply too
func TestReply(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	c := connect(t, startProxy(t, bus, policy(svcName, "talk")))
	r, err := call(c, svcName, "/org/test", svcIface+".Echo", "back")
	var s string
	if err != nil || r.Store(&s) != nil || s != "back" {
		t.Errorf("Reply: %q %v", s, err)
	}
	_, err = call(c, svcName, "/org/test", svcIface+".Missing")
	wantErr(t, "error reply", err, "org.freedesktop.DBus.Error.UnknownMethod")
}

// Collects what a connection receives
func eavesdrop(conn *dbus.Conn) func(time.Duration) []*dbus.Message {
	ch := make(chan *dbus.Message, 64)
	conn.Eavesdrop(ch)
	return func(wait time.Duration) []*dbus.Message {
		var out []*dbus.Message
		deadline := time.After(wait)
		for {
			select {
			case m := <-ch:
				out = append(out, m)
			case <-deadline:
				return out
			}
		}
	}
}

func unaskedReply(dest string, serial uint32) *dbus.Message {
	return &dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(dest),
		dbus.FieldReplySerial: dbus.MakeVariant(serial),
	}}
}

func countType(ms []*dbus.Message, typ dbus.Type, member string) int {
	n := 0
	for _, m := range ms {
		if m.Type == typ && (member == "" || m.Headers[dbus.FieldMember].Value() == member) {
			n++
		}
	}
	return n
}

// A reply nobody asked for is refused both ways. The test's bus allows them, as a control shows
func TestUnaskedReply(t *testing.T) {
	bus := startBus(t)
	target := connect(t, bus)
	got := eavesdrop(target)
	direct := connect(t, bus)
	direct.Send(unaskedReply(target.Names()[0], 4242), nil)
	if n := countType(got(300*time.Millisecond), dbus.TypeMethodReply, ""); n != 1 {
		t.Fatalf("Control: the bus delivered %d unasked replies, want 1", n)
	}

	c := connect(t, startProxy(t, bus))
	c.Send(unaskedReply(target.Names()[0], 4243), nil)
	if n := countType(got(300*time.Millisecond), dbus.TypeMethodReply, ""); n != 0 {
		t.Errorf("Client's unasked reply reached the bus side %d times", n)
	}

	fromClient := eavesdrop(c)
	direct.Send(unaskedReply(c.Names()[0], 4244), nil)
	if n := countType(fromClient(300*time.Millisecond), dbus.TypeMethodReply, ""); n != 0 {
		t.Errorf("Unasked reply from the bus reached the client %d times", n)
	}
}

// A call carrying the reply serial of a pending call to the client isn't taken for its reply: xdg-dbus-proxy passes
// it unchecked
func TestReplySerialOnCall(t *testing.T) {
	bus := startBus(t)
	svc := connect(t, bus)
	if _, err := svc.RequestName(svcName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	svcGot := eavesdrop(svc)
	c := connect(t, startProxy(t, bus))
	clientGot := eavesdrop(c)
	// A peer calls the client, which never answers
	peer := connect(t, bus)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer.Object(c.Names()[0], "/").GoWithContext(ctx, "org.test.Iface.Echo", 0, nil, "x")
	var serial uint32
	for _, m := range clientGot(300 * time.Millisecond) {
		if m.Type == dbus.TypeMethodCall {
			serial = m.Serial()
		}
	}
	if serial == 0 {
		t.Fatal("The peer's call didn't reach the client")
	}
	smuggled := &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(svcName),
		dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/org/test")),
		dbus.FieldInterface:   dbus.MakeVariant(svcIface),
		dbus.FieldMember:      dbus.MakeVariant("Smuggled"),
		dbus.FieldReplySerial: dbus.MakeVariant(serial),
	}}
	c.Send(smuggled, nil)
	if n := countType(svcGot(300*time.Millisecond), dbus.TypeMethodCall, "Smuggled"); n != 0 {
		t.Errorf("A call with a reply serial reached a hidden name")
	}
	// The control: from the bus, the same call arrives
	direct := connect(t, bus)
	direct.Send(smuggled, nil)
	if n := countType(svcGot(300*time.Millisecond), dbus.TypeMethodCall, "Smuggled"); n != 1 {
		t.Errorf("Control: the bus delivered %d calls with a reply serial, want 1", n)
	}
}
