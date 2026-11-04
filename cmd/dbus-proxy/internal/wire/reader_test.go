package wire

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// A Hello to the bus
func hello() *dbus.Message {
	return &dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant("org.freedesktop.DBus"),
		dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/DBus")),
		dbus.FieldInterface:   dbus.MakeVariant("org.freedesktop.DBus"),
		dbus.FieldMember:      dbus.MakeVariant("Hello"),
	}}
}

func stdinFDs(n int) []int {
	fds := make([]int, n)
	for i := range fds {
		fds[i] = int(os.Stdin.Fd())
	}
	return fds
}

// A message without a serial is refused as it's read
func TestSerialZero(t *testing.T) {
	r, w := readerPair(t)
	msg, _ := Encode(hello(), 0)
	unix.Write(w, msg)
	if _, err := r.ReadMessage(); err == nil {
		t.Error("A message with serial 0 was read")
	}
}

// A message may claim at most MaxMessageFDs, even when that many arrived (in two sendmsgs)
func TestMaxMessageFDs(t *testing.T) {
	r, w := readerPair(t)
	msg, err := Encode(withUnixFDs(hello(), MaxMessageFDs+1), 1)
	if err != nil {
		t.Fatal(err)
	}
	unix.Sendmsg(w, msg[:8], unix.UnixRights(stdinFDs(MaxMessageFDs)...), nil, 0)
	unix.Sendmsg(w, msg[8:], unix.UnixRights(stdinFDs(1)...), nil, 0)
	if m, err := r.ReadMessage(); err == nil {
		m.CloseFDs()
		t.Error("A message with more file descriptors than one sendmsg carries was read")
	}
}

// File descriptors that no message claims stop at MaxPendingFDs
func TestMaxPendingFDs(t *testing.T) {
	r, w := readerPair(t)
	for i := 0; i*MaxMessageFDs <= MaxPendingFDs; i++ {
		unix.Sendmsg(w, []byte("l"), unix.UnixRights(stdinFDs(MaxMessageFDs)...), nil, 0)
	}
	_, err := r.ReadMessage()
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Pending file descriptors past the limit: %v", err)
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
	r := NewReader(fc.(*net.UnixConn), nil)
	defer r.Close()
	for _, tc := range []struct {
		claim, send uint32
		ok          bool
	}{{1, 1, true}, {2, 1, false}} {
		msg, err := Encode(withUnixFDs(hello(), tc.claim), 1)
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
		m, err := r.ReadMessage()
		if (err == nil) != tc.ok {
			t.Errorf("Claim %d, send %d: %v", tc.claim, tc.send, err)
		}
		if m != nil {
			if len(m.fds) != int(tc.claim) {
				t.Errorf("Got %d fds, want %d", len(m.fds), tc.claim)
			}
			m.CloseFDs()
		}
	}
}

// Bodies stay bytes unless the proxy looks into them
func TestBodyNotDecoded(t *testing.T) {
	r, w := readerPair(t)
	msg, _ := Encode(big(10), 1)
	unix.Write(w, msg)
	m, err := r.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if m.Body != nil || m.decoded {
		t.Error("A body was decoded on reading")
	}
	if !m.DecodeBody(MaxMessageSize) || m.Body[0] != "xxxxxxxxxx" {
		t.Errorf("The body decoded: %v", m.Body)
	}
}
