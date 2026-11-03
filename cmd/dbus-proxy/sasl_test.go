package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// libdbus's client (dbus-send) through the proxy
func TestLibdbusClient(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	addr := startProxy(t, bus, "--filter", "--talk="+svcName)
	out, err := exec.Command("dbus-send", "--bus="+addr, "--print-reply", "--dest="+svcName, "/org/test",
		svcIface+".Echo", "string:from-libdbus").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "from-libdbus") {
		t.Errorf("dbus-send: %v %s", err, out)
	}
}

func hexUID(uid int) string { return hex.EncodeToString([]byte(strconv.Itoa(uid))) }

// sd-bus's way: EXTERNAL without an initial response, everything up to the first message in one write
func TestPipelinedSASL(t *testing.T) {
	bus := startBus(t)
	conn := dialRaw(t, startProxy(t, bus, "--filter"))
	hello, err := encodeNew(busCall("Hello"), 1)
	if err != nil {
		t.Fatal(err)
	}
	conn.Write(append([]byte("\x00AUTH EXTERNAL\r\nDATA\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n"), hello...))
	r := newReader(conn)
	for _, want := range []string{"DATA", "OK ", "AGREE_UNIX_FD"} {
		line, err := r.readLine()
		if err != nil || !strings.HasPrefix(line, want) {
			t.Fatalf("Got %q (%v), want %q", line, err, want)
		}
	}
	m, err := r.readMessage()
	if err != nil {
		t.Fatalf("Hello reply: %v", err)
	}
	if id, _ := m.arg0(); !strings.HasPrefix(id, ":") {
		t.Errorf("Hello reply %v", m.Message)
	}
}

// Another uid, a mechanism other than EXTERNAL and junk are refused
func TestSASLRefused(t *testing.T) {
	bus := startBus(t)
	addr := startProxy(t, bus, "--filter")
	for _, tc := range []struct{ send, want string }{
		{"\x00AUTH EXTERNAL " + hexUID(os.Getuid()+1) + "\r\n", "REJECTED EXTERNAL"},
		{"\x00AUTH EXTERNAL\r\nDATA " + hexUID(os.Getuid()+1) + "\r\n", "DATA"},
		{"\x00AUTH ANONYMOUS\r\n", "REJECTED EXTERNAL"},
		{"\x00NEGOTIATE_UNIX_FD\r\n", "ERROR"},
	} {
		conn := dialRaw(t, addr)
		conn.Write([]byte(tc.send))
		r := newReader(conn)
		line, err := r.readLine()
		if err != nil || line != tc.want {
			t.Errorf("%q: got %q (%v), want %q", tc.send, line, err, tc.want)
		}
		if tc.want == "DATA" {
			if line, _ := r.readLine(); line != "REJECTED EXTERNAL" {
				t.Errorf("DATA with another uid: got %q", line)
			}
		}
	}
	// BEGIN before OK, and a line with control characters, end the connection
	for _, send := range []string{"\x00BEGIN\r\n", "\x00AUTH EXTERNAL\x01\r\n", "x"} {
		conn := dialRaw(t, addr)
		conn.Write([]byte(send))
		if _, err := newReader(conn).readLine(); err == nil {
			t.Errorf("%q: connection still open", send)
		}
	}
}

// After authenticating, a message longer than the limit ends the connection before the proxy reads it
func TestMessageBounds(t *testing.T) {
	bus := startBus(t)
	addr := startProxy(t, bus, "--filter")
	auth := "\x00AUTH EXTERNAL " + hexUID(os.Getuid()) + "\r\nBEGIN\r\n"
	long := make([]byte, 16)
	copy(long, "l\x01\x00\x01")
	binary.LittleEndian.PutUint32(long[4:], maxMessageSize)
	binary.LittleEndian.PutUint32(long[8:], 1)
	binary.LittleEndian.PutUint32(long[12:], 8)

	for name, msg := range map[string][]byte{"too long": long} {
		conn := dialRaw(t, addr)
		conn.Write([]byte(auth))
		conn.Write(msg)
		r := newReader(conn)
		if line, _ := r.readLine(); !strings.HasPrefix(line, "OK ") {
			t.Fatalf("%s: auth: %q", name, line)
		}
		_, err := r.readMessage()
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s: the connection is still open: %v", name, err)
		}
	}
}

func withUnixFDs(m *dbus.Message, n uint32) *dbus.Message {
	m.Headers[dbus.FieldUnixFDs] = dbus.MakeVariant(n)
	return m
}

// A message claiming more file descriptors than arrived is refused; one that claims those that came gets them
func TestFDClaim(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(fds[0]), "a"), os.NewFile(uintptr(fds[1]), "b")
	defer a.Close()
	defer b.Close()
	fc, err := net.FileConn(b)
	if err != nil {
		t.Fatal(err)
	}
	defer fc.Close()
	r := newReader(fc.(*net.UnixConn))
	defer r.close()
	for _, tc := range []struct {
		claim, send uint32
		ok          bool
	}{{1, 1, true}, {2, 1, false}} {
		msg, err := encodeNew(withUnixFDs(busCall("Hello"), tc.claim), 1)
		if err != nil {
			t.Fatal(err)
		}
		pass := make([]int, tc.send)
		for i := range pass {
			pass[i] = int(a.Fd())
		}
		if err := unix.Sendmsg(int(a.Fd()), msg, unix.UnixRights(pass...), nil, 0); err != nil {
			t.Fatal(err)
		}
		m, err := r.readMessage()
		if (err == nil) != tc.ok {
			t.Errorf("Claim %d, send %d: %v", tc.claim, tc.send, err)
		}
		if m != nil {
			if len(m.fds) != int(tc.claim) {
				t.Errorf("Got %d fds, want %d", len(m.fds), tc.claim)
			}
			m.closeFDs()
		}
	}
}
