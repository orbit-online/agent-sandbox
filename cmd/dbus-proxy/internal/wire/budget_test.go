package wire

import (
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// Each client's share and the whole bound bytes and file descriptors; what's given back can be taken again
func TestBudget(t *testing.T) {
	b := &Budget{MaxBytes: 100, MaxFDs: 10, ClientBytes: 60, ClientFDs: 6}
	a1, a2 := b.Account(), b.Account()
	if err := a1.take(61, 0); err == nil {
		t.Error("A client took more bytes than its share")
	}
	if err := a1.take(0, 7); err == nil {
		t.Error("A client took more file descriptors than its share")
	}
	if err := a1.take(60, 6); err != nil {
		t.Fatal(err)
	}
	if err := a2.take(41, 0); err == nil {
		t.Error("Clients took more bytes than the whole")
	}
	if err := a2.take(0, 5); err == nil {
		t.Error("Clients took more file descriptors than the whole")
	}
	a1.give(60, 6)
	if err := a2.take(60, 6); err != nil {
		t.Errorf("Taking what was given back: %v", err)
	}
	var none *Account
	if err := none.take(1<<40, 1<<20); err != nil {
		t.Error("A nil Account counts")
	}
}

// A signal carrying n bytes
func big(n int) *dbus.Message {
	return &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/a")), dbus.FieldInterface: dbus.MakeVariant("a.b"),
		dbus.FieldMember: dbus.MakeVariant("C"), dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf("")),
	}, Body: []any{strings.Repeat("x", n)}}
}

// A reader on one end of a socket pair, and the other end
func readerPair(t *testing.T) (*Reader, int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[1]), "b")
	fc, err := net.FileConn(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	r := NewReader(fc.(*net.UnixConn), nil)
	t.Cleanup(func() { r.Close(); fc.Close(); unix.Close(fds[0]) })
	fc.(*net.UnixConn).SetReadDeadline(time.Now().Add(3 * time.Second))
	return r, fds[0]
}

// A message read counts on top of the reader's buffer, until it's released
func TestReaderAccounting(t *testing.T) {
	for _, tc := range []struct {
		share int64
		ok    bool
	}{{300 << 10, false}, {500 << 10, true}} {
		r, w := readerPair(t)
		b := &Budget{MaxBytes: 1 << 30, MaxFDs: 100, ClientBytes: tc.share, ClientFDs: 10}
		r.acct = b.Account()
		msg, _ := Encode(big(200<<10), 1)
		go unix.Write(w, msg)
		m, err := r.ReadMessage()
		if (err == nil) != tc.ok {
			t.Errorf("Share %d: %v", tc.share, err)
		}
		if m != nil {
			m.Release()
			if r.acct.bytes != 0 {
				t.Errorf("%d bytes held after the message was released", r.acct.bytes)
			}
		}
	}
}

// What a sender queues counts until it's written
func TestSenderAccounting(t *testing.T) {
	b := &Budget{MaxBytes: 1 << 30, MaxFDs: 100, ClientBytes: 100 << 10, ClientFDs: 10}
	acct := b.Account()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "a")
	fc, _ := net.FileConn(f)
	f.Close()
	defer fc.Close()
	s := NewSender(fc.(*net.UnixConn), acct)
	if err := s.Send(make([]byte, 200<<10), nil); err == nil {
		t.Error("A sender queued more than the client's share")
	}
	if err := s.Send(make([]byte, 50<<10), nil); err != nil || acct.bytes != 50<<10 {
		t.Errorf("Queued 50 KiB: %v, %d bytes held", err, acct.bytes)
	}
}
