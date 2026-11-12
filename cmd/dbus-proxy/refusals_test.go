package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// A buffer the proxy's goroutines write and the test reads; the replies that order them pass through a socket, which
// the race detector doesn't see
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// The log lines a proxy's refusals write, one string each
func captureRefusals(p *Proxy) func() []string {
	b := &lockedBuffer{}
	p.refusals = newRefusals(slog.New(slog.NewTextHandler(b, nil)))
	return func() []string {
		b.mu.Lock()
		defer b.mu.Unlock()
		return strings.Split(strings.TrimSpace(b.buf.String()), "\n")
	}
}

// A refused call is logged with its header fields, at its 1st and 10th time; a call the rules allow isn't, nor is
// its body. A call that wants no reply is dropped, and logged all the same
func TestRefusalsLogged(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	var lines func() []string
	c := connect(t, startProxyWith(t, bus, func(p *Proxy) { lines = captureRefusals(p) },
		ruled(svcName, "call", svcIface+".Echo")))
	if _, err := call(c, svcName, "/org/test", svcIface+".Echo", "allowed"); err != nil {
		t.Fatal(err)
	}
	for range 12 {
		_, err := call(c, svcName, "/org/test", svcIface+".Other", "secret body")
		wantErr(t, "Other", err, errAccessDenied)
	}
	c.Object(svcName, "/org/test/noreply").Go(svcIface+".Other", dbus.FlagNoReplyExpected, nil, "x")
	// The no-reply call has no reply to wait for: a refused call after it is logged after it
	_, err := call(c, svcName, "/org/test/sub/obj", svcIface+".Other", "y")
	wantErr(t, "Other", err, errAccessDenied)
	got := lines()
	want := []string{
		"member=Other error=org.freedesktop.DBus.Error.AccessDenied count=1",
		"member=Other error=org.freedesktop.DBus.Error.AccessDenied count=10",
		"path=/org/test/noreply",
		"path=/org/test/sub/obj",
	}
	if len(got) != len(want) {
		t.Fatalf("%d lines, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i, w := range want {
		if !strings.Contains(got[i], w) || !strings.Contains(got[i], "level=WARN msg=Refused") {
			t.Errorf("Line %d: %s\nwant it to contain %q", i, got[i], w)
		}
	}
	for _, l := range got {
		if strings.Contains(l, "secret") || strings.Contains(l, "Echo") {
			t.Errorf("Logged a body or an allowed call: %s", l)
		}
	}
}

// Ten refused calls at the same time, from clients of their own, count up to one 10th line
func TestRefusalsConcurrent(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	var lines func() []string
	addr := startProxyWith(t, bus, func(p *Proxy) { lines = captureRefusals(p) }, policy(svcName, "see"))
	done := make(chan error)
	for range 10 {
		go func() {
			_, err := call(connect(t, addr), svcName, "/org/test", svcIface+".Echo", "x")
			done <- err
		}()
	}
	for range 10 {
		select {
		case err := <-done:
			wantErr(t, "Echo", err, errAccessDenied)
		case <-time.After(10 * time.Second):
			t.Fatal("Timed out")
		}
	}
	if got := lines(); len(got) != 2 || !strings.Contains(got[1], "count=10") {
		t.Errorf("Lines:\n%s", strings.Join(got, "\n"))
	}
}

func refusedCall(t *testing.T, member string) *wire.Message {
	t.Helper()
	data, err := wire.Encode(&dbus.Message{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldDestination: dbus.MakeVariant("org.test.Svc"),
		dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/org/test")),
		dbus.FieldMember:      dbus.MakeVariant(member),
	}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	m, err := wire.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Past maxRefusalKeys kinds the rest share one count, logged as "other"; long fields are cut
func TestRefusalsBounded(t *testing.T) {
	var buf bytes.Buffer
	r := newRefusals(slog.New(slog.NewTextHandler(&buf, nil)))
	for i := range maxRefusalKeys + 10 {
		r.note(refusedCall(t, fmt.Sprintf("M%d", i)), "e")
	}
	if len(r.counts) != maxRefusalKeys || r.other != 10 {
		t.Errorf("%d kinds, %d other", len(r.counts), r.other)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != maxRefusalKeys+2 || !strings.Contains(lines[maxRefusalKeys], "kind=other count=1") ||
		!strings.Contains(lines[maxRefusalKeys+1], "kind=other count=10") {
		t.Errorf("%d lines, the last: %v", len(lines), lines[maxRefusalKeys:])
	}
	if s := cut(strings.Repeat("a", 300)); len(s) != maxRefusalField+len("…") {
		t.Errorf("Cut to %d bytes", len(s))
	}
}

func TestMilestone(t *testing.T) {
	var got []uint64
	for n := range uint64(10001) {
		if milestone(n) {
			got = append(got, n)
		}
	}
	if fmt.Sprint(got) != "[1 10 100 1000 10000]" {
		t.Errorf("%v", got)
	}
}
