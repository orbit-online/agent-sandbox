package main

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// Each client's share and the whole bound bytes and file descriptors; what's given back can be taken again
func TestBudget(t *testing.T) {
	b := &budget{maxBytes: 100, maxFDs: 10, clientBytes: 60, clientFDs: 6}
	a1, a2 := b.account(), b.account()
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
	var none *account
	if err := none.take(1<<40, 1<<20); err != nil {
		t.Error("A nil account counts")
	}
}

func big(n int) *dbus.Message {
	m := echoTo(svcName)
	m.Body = []any{strings.Repeat("x", n)}
	return m
}

// A message read counts on top of the reader's buffer, until it's released
func TestReaderAccounting(t *testing.T) {
	for _, tc := range []struct {
		share int64
		ok    bool
	}{{300 << 10, false}, {500 << 10, true}} {
		r, w := readerPair(t)
		b := &budget{maxBytes: 1 << 30, maxFDs: 100, clientBytes: tc.share, clientFDs: 10}
		r.acct = b.account()
		msg, _ := encodeNew(big(200<<10), 1)
		go unix.Write(w, msg)
		m, err := r.readMessage()
		if (err == nil) != tc.ok {
			t.Errorf("Share %d: %v", tc.share, err)
		}
		if m != nil {
			m.release()
			if r.acct.bytes != 0 {
				t.Errorf("%d bytes held after the message was released", r.acct.bytes)
			}
		}
	}
}

// What a sender queues counts until it's written
func TestSenderAccounting(t *testing.T) {
	b := &budget{maxBytes: 1 << 30, maxFDs: 100, clientBytes: 100 << 10, clientFDs: 10}
	acct := b.account()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	f := os.NewFile(uintptr(fds[0]), "a")
	fc, _ := net.FileConn(f)
	f.Close()
	defer fc.Close()
	s := newSender(fc.(*net.UnixConn), acct)
	if err := s.send(make([]byte, 200<<10), nil); err == nil {
		t.Error("A sender queued more than the client's share")
	}
	if err := s.send(make([]byte, 50<<10), nil); err != nil || acct.bytes != 50<<10 {
		t.Errorf("Queued 50 KiB: %v, %d bytes held", err, acct.bytes)
	}
}
