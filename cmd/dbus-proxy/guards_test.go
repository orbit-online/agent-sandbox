package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// Serials above maxClientSerial are the proxy's, and serial 0 is none: either ends the connection
func TestClientSerials(t *testing.T) {
	bus := startBus(t)
	addr := startProxy(t, bus, "--filter")
	for _, serial := range []uint32{maxClientSerial + 1, 0} {
		rc := rawConnect(t, addr)
		rc.send(serial, busCall("GetId"))
		if !rc.closed() {
			t.Errorf("Serial %d accepted", serial)
		}
	}
}

// A client that asked for file descriptors and then cancelled: the proxy agreed with the bus already, so only the
// proxy stands between the client's lack of them and fds either way
const cancelledFDs = "\x00AUTH EXTERNAL %s\r\nNEGOTIATE_UNIX_FD\r\nCANCEL\r\nAUTH EXTERNAL %s\r\nBEGIN\r\n"

func rawWithoutFDs(t *testing.T, addr string) *rawClient {
	uid := hexUID(os.Getuid())
	return rawConnectWith(t, addr, strings.ReplaceAll(cancelledFDs, "%s", uid))
}

func TestUnnegotiatedFDs(t *testing.T) {
	bus := startBus(t)
	addr := startProxy(t, bus, "--filter")
	rc := rawWithoutFDs(t, addr)
	rc.sendFDs(2, busCall("GetId"), 1)
	if !rc.closed() {
		t.Error("File descriptors from a client that didn't negotiate them passed")
	}

	rc = rawWithoutFDs(t, addr)
	peer := connect(t, bus)
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	sig := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(rc.name),
		dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/x")),
		dbus.FieldInterface:   dbus.MakeVariant(svcIface),
		dbus.FieldMember:      dbus.MakeVariant("WithFD"),
	}, Body: []any{dbus.UnixFD(r.Fd())}}
	sig.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(dbus.UnixFD(0)))
	if err := peer.Send(sig, nil).Err; err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	rc.send(3, busCall("GetId"))
	for {
		m, err := rc.r.readMessage()
		if err != nil {
			t.Fatal(err)
		}
		if m.header(dbus.FieldMember) == "WithFD" || len(m.fds) > 0 {
			t.Error("File descriptors reached a client that didn't negotiate them")
		}
		m.closeFDs()
		if rs, _ := m.replySerial(); rs == 3 {
			break
		}
	}
}

// Calls to the bus the proxy refuses on their own: without an interface, a match rule that isn't a string, the
// bus's other interfaces. The bus itself takes the first, as the control shows
func TestBusCallsRefused(t *testing.T) {
	bus := startBus(t)
	noIface := func(member string, args ...any) *dbus.Message {
		m := busCall(member, args...)
		delete(m.Headers, dbus.FieldInterface)
		return m
	}
	direct := connect(t, bus)
	if err := direct.BusObject().Call("AddMatch", 0, "eavesdrop=true").Err; err != nil {
		t.Fatalf("Control: the bus refused an AddMatch without an interface: %v", err)
	}
	for _, args := range [][]string{nil, {"--filter"}} {
		rc := rawConnect(t, startProxy(t, bus, args...))
		for i, m := range []*dbus.Message{
			noIface("AddMatch", "eavesdrop=true"),
			noIface("BecomeMonitor", []string{}, uint32(0)),
			busCall("AddMatch", uint32(1)),
		} {
			serial := uint32(10 + i)
			rc.send(serial, m)
			if r := rc.waitReply(serial); r.header(dbus.FieldErrorName) != errAccessDenied {
				t.Errorf("%v %s(%v): got %q", args, m.Headers[dbus.FieldMember], m.Body, r.header(dbus.FieldErrorName))
			}
		}
	}
	rc := rawConnect(t, startProxy(t, bus, "--filter"))
	// A member the proxy handles on the bus's own interface, on another
	for i, iface := range []string{"org.freedesktop.DBus.Properties", "org.test.Other"} {
		m := busCall("ListNames")
		m.Headers[dbus.FieldInterface] = dbus.MakeVariant(iface)
		rc.send(uint32(20+i), m)
		if r := rc.waitReply(uint32(20 + i)); r.header(dbus.FieldErrorName) != errAccessDenied {
			t.Errorf("%s.ListNames on the bus: got %q", iface, r.header(dbus.FieldErrorName))
		}
	}
}

// A method call without a destination is refused by the proxy, with and without --filter
func TestNoDestinationCall(t *testing.T) {
	bus := startBus(t)
	for _, args := range [][]string{nil, {"--filter"}} {
		rc := rawConnect(t, startProxy(t, bus, args...))
		m := echoTo("")
		delete(m.Headers, dbus.FieldDestination)
		rc.send(2, m)
		if r := rc.waitReply(2); r.header(dbus.FieldErrorName) != errAccessDenied || r.header(dbus.FieldSender) != "" {
			t.Errorf("%v: got %q from %q", args, r.header(dbus.FieldErrorName), r.header(dbus.FieldSender))
		}
	}
}

// A peer that called the client becomes visible to it
func TestCallerVisible(t *testing.T) {
	bus := startBus(t)
	c := connect(t, startProxy(t, bus, "--filter"))
	peer := connect(t, bus)
	if hasOwner(t, c, peer.Names()[0]) {
		t.Fatal("A peer is visible before it called")
	}
	if _, err := call(peer, c.Names()[0], "/", "org.freedesktop.DBus.Peer.Ping"); err != nil {
		t.Fatal(err)
	}
	if !hasOwner(t, c, peer.Names()[0]) {
		t.Error("A peer that called the client isn't visible to it")
	}
}

// A client with another uid is refused before SASL
func TestPeerUID(t *testing.T) {
	bus := startBus(t)
	addr := startProxyWith(t, bus, func(p *Proxy) { p.uid = os.Getuid() + 1 }, "--filter")
	conn := dialRaw(t, addr)
	conn.Write([]byte("\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\n"))
	if line, err := newReader(conn, nil).readLine(); err == nil {
		t.Errorf("A client of another uid got %q", line)
	}
}

// File descriptors sent along with SASL end the connection
func TestFDsDuringAuth(t *testing.T) {
	bus := startBus(t)
	conn := dialRaw(t, startProxy(t, bus, "--filter"))
	auth := []byte("\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\n")
	if err := unix.Sendmsg(rawFD(t, conn), auth, unix.UnixRights(int(os.Stdin.Fd())), nil, 0); err != nil {
		t.Fatal(err)
	}
	hello, _ := encodeNew(busCall("Hello"), 1)
	conn.Write(append([]byte("BEGIN\r\n"), hello...))
	rc := &rawClient{t: t, conn: conn, r: newReader(conn, nil)}
	if line, err := rc.r.readLine(); err != nil || !strings.HasPrefix(line, "OK ") {
		t.Fatalf("SASL: %q %v", line, err)
	}
	if !rc.closed() {
		t.Error("File descriptors during SASL passed")
	}
}

// A call right after Hello to the owner of a name under a wildcard waits until the proxy knows that owner
func TestWildcardHold(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus, "org.test.Svc.Sub")
	conn := dialRaw(t, startProxy(t, bus, "--filter", "--talk=org.test.Svc.*"))
	hello, _ := encodeNew(busCall("Hello"), 1)
	echo, _ := encodeNew(echoTo(svc.Names()[0]), 2)
	conn.Write([]byte("\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\nBEGIN\r\n"))
	conn.Write(append(hello, echo...))
	rc := &rawClient{t: t, conn: conn, r: newReader(conn, nil)}
	rc.r.readLine()
	if r := rc.waitReply(2); r.Type != dbus.TypeMethodReply {
		t.Errorf("Call to the wildcard name's owner right after Hello: %q", r.header(dbus.FieldErrorName))
	}
}
