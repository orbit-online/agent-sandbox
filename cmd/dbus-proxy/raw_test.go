package main

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"golang.org/x/sys/unix"
)

// A client speaking the wire protocol itself, for what godbus won't send: reused serials, a second Hello, crafted
// headers, file descriptors where they don't belong
type rawClient struct {
	t    *testing.T
	conn *net.UnixConn
	r    *wire.Reader
	name string
}

// Authenticates with sasl (the lines up to and including BEGIN) and says Hello with serial 1
func rawConnectWith(t *testing.T, addr, sasl string) *rawClient {
	t.Helper()
	conn := dialRaw(t, addr)
	conn.Write([]byte(sasl))
	rc := &rawClient{t: t, conn: conn, r: wire.NewReader(conn, nil)}
	t.Cleanup(rc.r.Close)
	for _, line := range strings.Split(strings.TrimSuffix(sasl, "\r\n"), "\r\n") {
		if strings.HasPrefix(line, "\x00AUTH EXTERNAL ") || strings.HasPrefix(line, "AUTH EXTERNAL ") ||
			strings.HasPrefix(line, "NEGOTIATE_UNIX_FD") || strings.HasPrefix(line, "CANCEL") {
			if _, err := rc.r.ReadLine(); err != nil {
				t.Fatalf("SASL: %v", err)
			}
		}
	}
	rc.send(1, busCall("Hello"))
	rc.name, _ = arg0(rc.waitReply(1))
	return rc
}

func rawConnect(t *testing.T, addr string) *rawClient {
	return rawConnectWith(t, addr, "\x00AUTH EXTERNAL "+hexUID(os.Getuid())+"\r\nBEGIN\r\n")
}

// Sends messages with one serial in one write
func (rc *rawClient) send(serial uint32, ms ...*dbus.Message) {
	rc.t.Helper()
	var buf []byte
	for _, m := range ms {
		d, err := wire.Encode(m, serial)
		if err != nil {
			rc.t.Fatal(err)
		}
		buf = append(buf, d...)
	}
	if _, err := rc.conn.Write(buf); err != nil {
		rc.t.Fatalf("Write: %v", err)
	}
}

// Sends a message with file descriptors (a copy of stdin's per fd claimed)
func (rc *rawClient) sendFDs(serial uint32, m *dbus.Message, n int) {
	rc.t.Helper()
	m.Headers[dbus.FieldUnixFDs] = dbus.MakeVariant(uint32(n))
	d, err := wire.Encode(m, serial)
	if err != nil {
		rc.t.Fatal(err)
	}
	fds := make([]int, n)
	for i := range fds {
		fds[i] = int(os.Stdin.Fd())
	}
	if err := unix.Sendmsg(rawFD(rc.t, rc.conn), d, unix.UnixRights(fds...), nil, 0); err != nil {
		rc.t.Fatalf("Sendmsg: %v", err)
	}
}

func rawFD(t *testing.T, conn *net.UnixConn) int {
	sc, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var fd int
	sc.Control(func(f uintptr) { fd = int(f) })
	return fd
}

// The next message replying to serial, skipping others
func (rc *rawClient) waitReply(serial uint32) *wire.Message {
	rc.t.Helper()
	for {
		m, err := rc.r.ReadMessage()
		if err != nil {
			rc.t.Fatalf("Waiting for the reply to %d: %v", serial, err)
		}
		if rs, ok := m.ReplySerial(); ok && rs == serial {
			return m
		}
	}
}

// Whether the proxy ends the connection (rather than the read timing out), reading what comes before
func (rc *rawClient) closed() bool {
	rc.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		m, err := rc.r.ReadMessage()
		if err != nil {
			return !errors.Is(err, os.ErrDeadlineExceeded)
		}
		m.CloseFDs()
	}
}

func echoTo(dest string) *dbus.Message {
	return &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant(dest),
		dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/org/test")),
		dbus.FieldInterface:   dbus.MakeVariant(svcIface),
		dbus.FieldMember:      dbus.MakeVariant("Echo"),
		dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf("")),
	}, Body: []any{"x"}}
}

// A serial reused while its call awaits a reply ends the connection: otherwise the bus's reply to GetNameOwner,
// read as the reply to a second Hello, would give the name's owner TALK
func TestSerialReuse(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	got := eavesdrop(svc)
	rc := rawConnect(t, startProxy(t, bus, policy(svcName, "see")))
	rc.send(3, busCall("GetNameOwner", svcName), busCall("Hello"))
	if !rc.closed() {
		t.Error("Serial reuse didn't end the connection")
	}
	if n := countType(got(300*time.Millisecond), dbus.TypeMethodCall, "Echo"); n != 0 {
		t.Errorf("The service got %d calls", n)
	}
	// ListNames, then GetId on its serial: the ListNames reply mustn't pass unfiltered
	rc = rawConnect(t, startProxy(t, bus))
	rc.send(5, busCall("ListNames"), busCall("GetId"))
	if !rc.closed() {
		t.Error("Serial reuse didn't end the connection")
	}
}

// A second Hello is refused by the proxy, so its reply can't raise anyone to TALK
func TestSecondHello(t *testing.T) {
	bus := startBus(t)
	svc := startService(t, bus)
	rc := rawConnect(t, startProxy(t, bus, policy(svcName, "see")))
	rc.send(2, busCall("Hello"))
	if r := rc.waitReply(2); r.Header(dbus.FieldErrorName) != errAccessDenied {
		t.Errorf("Second Hello: %v %q", r.Type, r.Header(dbus.FieldErrorName))
	}
	rc.send(3, echoTo(svc.Names()[0]))
	if r := rc.waitReply(3); r.Header(dbus.FieldErrorName) != errAccessDenied {
		t.Errorf("Call to a seen name's owner after a second Hello: %v %q", r.Type, r.Header(dbus.FieldErrorName))
	}
}
