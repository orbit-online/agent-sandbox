package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// SASL: at most maxAuthCommands commands, lines at most wire.MaxAuthLine long
func TestSASLLimits(t *testing.T) {
	bus := startBus(t)
	addr := startProxy(t, bus)
	conn := dialRaw(t, addr)
	conn.Write([]byte("\x00" + strings.Repeat("ERROR\r\n", maxAuthCommands+8)))
	r := wire.NewReader(conn, nil)
	n := 0
	var err error
	for err == nil {
		_, err = r.ReadLine()
		if err == nil {
			n++
		}
	}
	if n > maxAuthCommands || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("%d SASL replies, connection ended: %v", n, err)
	}

	conn = dialRaw(t, addr)
	conn.Write([]byte("\x00AUTH " + strings.Repeat("A", wire.MaxAuthLine)))
	if _, err := wire.NewReader(conn, nil).ReadLine(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("A SASL line past the limit: %v", err)
	}
}

// A service that never answers: it eavesdrops its own traffic
func silentService(t *testing.T, bus string) {
	svc := connect(t, bus)
	if _, err := svc.RequestName(svcName, dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	ch := make(chan *dbus.Message, 1024)
	svc.Eavesdrop(ch)
	go func() {
		for range ch {
		}
	}()
}

// Calls awaiting replies stop at maxPendingReplies each way
func TestPendingReplyCaps(t *testing.T) {
	bus := startBus(t)
	silentService(t, bus)
	addr := startProxy(t, bus, "--talk="+svcName)
	rc := rawConnect(t, addr)
	var buf []byte
	for i := 0; i <= maxPendingReplies; i++ {
		d, _ := wire.Encode(echoTo(svcName), uint32(10+i))
		buf = append(buf, d...)
	}
	go rc.conn.Write(buf)
	if !rc.closed() {
		t.Error("Calls from the client past the cap")
	}

	rc = rawConnect(t, addr)
	peer := connect(t, bus)
	for i := 0; i <= maxPendingReplies; i++ {
		peer.Object(rc.name, "/").Go(svcIface+".Echo", 0, nil, "x")
	}
	if !rc.closed() {
		t.Error("Calls to the client past the cap")
	}
}

// A client over its share of memory is disconnected; others go on
func TestMemoryBudget(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	addr := startProxyWith(t, bus, func(p *Proxy) { p.budget.MaxBytes = 1 << 20 }, "--talk="+svcName)
	rc := rawConnect(t, addr)
	big := echoTo(svcName)
	big.Body = []any{strings.Repeat("x", 2<<20)}
	data, err := wire.Encode(big, 2)
	if err != nil {
		t.Fatal(err)
	}
	// The proxy may close before it's all written
	go rc.conn.Write(data)
	if !rc.closed() {
		t.Error("A message over the budget passed")
	}
	if _, err := call(connect(t, addr), svcName, "/org/test", svcIface+".Echo", "x"); err != nil {
		t.Errorf("Another client after one went over: %v", err)
	}
}

// File descriptors queued for a client that doesn't read count against its share: past it, it's disconnected
func TestQueuedFDs(t *testing.T) {
	bus := startBus(t)
	const share = 256
	rc := rawConnectWith(t, startProxyWith(t, bus, func(p *Proxy) { p.budget.ClientFDs = share }),
		"\x00AUTH EXTERNAL "+hexUID(os.Getuid())+"\r\nNEGOTIATE_UNIX_FD\r\nBEGIN\r\n")
	peer := connect(t, bus)
	r, w, _ := os.Pipe()
	defer r.Close()
	defer w.Close()
	fds := make([]dbus.UnixFD, 64)
	for i := range fds {
		fds[i] = dbus.UnixFD(r.Fd())
	}
	// Padded, so the client's socket buffer fills and the rest wait in the proxy's queue
	pad := strings.Repeat("x", 50<<10)
	for i := 0; i*64 <= share+12*64; i++ {
		sig := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldDestination: dbus.MakeVariant(rc.name),
			dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/x")),
			dbus.FieldInterface:   dbus.MakeVariant(svcIface),
			dbus.FieldMember:      dbus.MakeVariant("FDs"),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf(pad, fds)),
		}, Body: []any{pad, fds}}
		if err := peer.Send(sig, nil).Err; err != nil {
			t.Logf("Send %d: %v", i, err)
			break
		}
	}
	// The client reads nothing: the proxy holds what's queued for it until it ends the client, which the bus sees
	// as the client's name gone
	watcher := connect(t, bus)
	for i := 0; i < 100 && hasOwner(t, watcher, rc.name); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	if hasOwner(t, watcher, rc.name) {
		t.Error("A client holding more file descriptors than its share stays connected")
	}
}

// Out of file descriptors, the proxy keeps accepting once clients free some
func TestAcceptEMFILE(t *testing.T) {
	bus := startBus(t)
	startService(t, bus)
	sock := filepath.Join(t.TempDir(), "proxy")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], bus, sock, "--filter", "--talk="+svcName)
	cmd.Env = append(os.Environ(), "DBUS_PROXY_MAIN=1", "DBUS_PROXY_NOFILE=40")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	waitFor(t, func() bool { _, err := os.Stat(sock); return err == nil })
	var conns []*net.UnixConn
	for i := 0; i < 40; i++ {
		if c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"}); err == nil {
			conns = append(conns, c)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, c := range conns {
		c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := call(connect(t, "unix:path="+sock), svcName, "/org/test", svcIface+".Echo", "x"); err != nil {
		t.Errorf("Call after running out of file descriptors: %v", err)
	}
}
