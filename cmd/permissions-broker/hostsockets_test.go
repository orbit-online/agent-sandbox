package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// testSocket gives b a host socket capability vm whose instances are echo servers at <dir>/<name>.sock, one per name
func testSocket(t *testing.T, b *broker, names ...string) *capability {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		e := startEcho(t, dir, n+".sock")
		t.Cleanup(e.stop)
	}
	c := &capability{Name: "vm", Type: "socket", Description: "a VM's console", Params: map[string]json.RawMessage{
		"vm": json.RawMessage(`{"type": "string", "description": "the VM", "instances": "` + dir + `/*.sock"}`)}}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	return c
}

// echoes connects to addr in b's grant directory, sends a line and returns what comes back: the line, or "" when the
// connection is closed first
func echoes(t *testing.T, b *broker, addr string) (*net.UnixConn, string) {
	t.Helper()
	conn, err := dialPath(filepath.Join(b.cfg.GrantDir, addr), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(conn, "ping\n")
	line, err := bufio.NewReader(conn).ReadString('\n')
	// A connection closed with what was sent unread is reset
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Read from %s: %v", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, line
}

// closed reports whether the connection's end comes within three seconds
func closed(conn *net.UnixConn) bool {
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	return errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)
}

// What the broker refuses to declare: a D-Bus bus, $XDG_RUNTIME_DIR as a whole, the launchers' own sockets, and a
// declaration without exactly one of a path and an instances glob
func TestSocketDeclarations(t *testing.T) {
	run := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", run)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/tmp/other-bus,guid=x")
	glob := `{"type": "string", "description": "d", "instances": "%s"}`
	for name, sc := range map[string]socketConfig{
		"session bus":       {Path: "$XDG_RUNTIME_DIR/bus"},
		"bus address":       {Path: "/tmp/other-bus"},
		"system bus":        {Path: "/run/dbus/system_bus_socket"},
		"runtime dir":       {Path: "$XDG_RUNTIME_DIR"},
		"above it":          {Path: filepath.Dir(run)},
		"control socket":    {Path: "$XDG_RUNTIME_DIR/claude-desktop/permissions-control.sock"},
		"nixpak's proxy":    {Path: "$XDG_RUNTIME_DIR/nixpak-bus-1234"},
		"flatpak instances": {Path: "$XDG_RUNTIME_DIR/.flatpak/nixpak-app-1/bwrapinfo.json"},
		"locks":             {Path: "$XDG_RUNTIME_DIR/agent-sandbox-permissions/x"},
		"relative":          {Path: "agent.sock"},
		"unset variable":    {Path: "$NO_SUCH_VARIABLE/agent.sock"},
		"neither":           {},
		"both":              {Path: "/srv/a.sock", Bounding: map[string]json.RawMessage{"vm": json.RawMessage(strings.ReplaceAll(glob, "%s", "/srv/*.sock"))}},
		"no glob":           {Bounding: map[string]json.RawMessage{"vm": json.RawMessage(`{"type": "string", "description": "d"}`)}},
		"glob over all":     {Bounding: map[string]json.RawMessage{"vm": json.RawMessage(strings.ReplaceAll(glob, "%s", "$XDG_RUNTIME_DIR/*"))}},
		"launchers' glob":   {Bounding: map[string]json.RawMessage{"bus": json.RawMessage(strings.ReplaceAll(glob, "%s", "$XDG_RUNTIME_DIR/nixpak-*"))}},
		"glob and another": {Bounding: map[string]json.RawMessage{"vm": json.RawMessage(strings.ReplaceAll(glob, "%s", "/srv/*.sock")),
			"mode": json.RawMessage(`{"type": "string", "description": "d"}`)}},
	} {
		sc.Name, sc.Description = "test", "a test socket"
		if err := loadSockets([]socketConfig{sc}, map[string]*capability{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, sc := range map[string]socketConfig{
		"bad name":       {Name: "a/b", Description: "d", Path: "/srv/a.sock"},
		"no description": {Name: "a", Path: "/srv/a.sock"},
	} {
		if err := loadSockets([]socketConfig{sc}, map[string]*capability{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	caps := map[string]*capability{}
	if err := loadSockets([]socketConfig{
		{Name: "ssh-agent", Description: "d", Path: "$XDG_RUNTIME_DIR/ssh-agent.sock"},
		{Name: "vms", Description: "d", Bounding: map[string]json.RawMessage{"vm": json.RawMessage(strings.ReplaceAll(glob, "%s", "$XDG_RUNTIME_DIR/vms/*/console.sock"))}},
		{Name: "nixpak", Description: "d", Bounding: map[string]json.RawMessage{"bus": json.RawMessage(strings.ReplaceAll(glob, "%s", "$XDG_RUNTIME_DIR/vms/nixpak-*"))}},
	}, caps); err != nil {
		t.Fatal(err)
	}
	// A match that isn't a socket is no instance
	if err := os.MkdirAll(filepath.Join(run, "vms"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(run, "vms", "nixpak-bus-1"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := caps["nixpak"].globMatches(); err != nil || len(found) != 0 {
		t.Errorf("A file that isn't a socket as an instance: %v, %v", found, err)
	}
	if err := loadSockets([]socketConfig{{Name: "ssh-agent", Description: "d", Path: "/srv/a.sock"}}, caps); err == nil {
		t.Error("A capability declared twice")
	}
}

// A host socket's address is there from the start. A connection without a grant is closed at once; under one it
// reaches the host socket; a revoke closes it
func TestSocketSplice(t *testing.T) {
	b, _ := testBroker(t, "allow", "allow")
	c := testSocket(t, b, "a")
	b.syncSockets(c)
	addr := filepath.Join(socketsDir, "vm", "a")
	if _, line := echoes(t, b, addr); line != "" {
		t.Fatalf("Spliced without a grant: %q", line)
	}
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "a"}`, ""))
	if err != nil {
		t.Fatal(err)
	}
	if g.Socket != "/run/permissions/sockets/vm/a" || g.Lease != "PT1H" {
		t.Errorf("Grant %+v", g)
	}
	first, line := echoes(t, b, addr)
	second, line2 := echoes(t, b, addr)
	if line != "ping\n" || line2 != "ping\n" {
		t.Fatalf("Under a grant: %q, %q", line, line2)
	}
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if !closed(first) || !closed(second) {
		t.Error("A revoke left a connection open")
	}
	if _, line := echoes(t, b, addr); line != "" {
		t.Errorf("Spliced after the revoke: %q", line)
	}
}

// An instance's address appears with it and goes with it, looked for every instanceEvery; its grant ends with it
func TestSocketInstances(t *testing.T) {
	b, _ := testBroker(t, "allow")
	clk := newFakeClock()
	b.clock = clk
	c := testSocket(t, b, "a")
	b.syncSockets(c)
	go b.syncSocketsEvery()
	dir := filepath.Dir(c.glob)
	at := func(n string) bool {
		_, err := os.Stat(filepath.Join(b.cfg.GrantDir, socketsDir, "vm", n))
		return err == nil
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal(what)
			}
		}
	}
	if !at("a") || at("b") {
		t.Fatal("Addresses at the start")
	}
	e := startEcho(t, dir, "b.sock")
	t.Cleanup(e.stop)
	c.listedAt = time.Time{}
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "b"}`, "PT1H"))
	if err != nil || !at("b") {
		t.Fatalf("A new instance's grant: %v, listening %v", err, at("b"))
	}
	if err := os.Remove(filepath.Join(dir, "a.sock")); err != nil {
		t.Fatal(err)
	}
	e.stop()
	c.listedAt = time.Time{}
	// Once the grant's watch and the daemon's look for instances wait for their time
	waitFor("The watches didn't start", func() bool { return clk.asked(instanceEvery) >= 2 })
	clk.advance(instanceEvery)
	waitFor("The address of an instance gone is still there", func() bool { return !at("a") && !at("b") })
	select {
	case <-g.ended:
	case <-time.After(3 * time.Second):
		t.Error("The grant outlived its instance")
	}
	e2 := startEcho(t, dir, "a.sock")
	t.Cleanup(e2.stop)
	clk.advance(instanceEvery)
	waitFor("No address for an instance that appeared", func() bool { return at("a") })
}

// Each host socket's address takes maxConns connections at a time: past that one is closed at once, until another
// ends
func TestSpliceBudget(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testSocket(t, b, "a")
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "a"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	addr := filepath.Join(socketsDir, "vm", "a")
	var conns []*net.UnixConn
	for range maxConns {
		conn, line := echoes(t, b, addr)
		if line != "ping\n" {
			t.Fatalf("Connection %d: %q", len(conns), line)
		}
		conns = append(conns, conn)
	}
	if _, line := echoes(t, b, addr); line != "" {
		t.Errorf("Spliced past the budget: %q", line)
	}
	conns[0].Close()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if _, line := echoes(t, b, addr); line == "ping\n" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("No connection once one ended")
		}
	}
}

// An address and a host socket past a socket path's 108 bytes still work
func TestSocketLongPath(t *testing.T) {
	b, _ := testBroker(t, "allow")
	long := filepath.Join(t.TempDir(), strings.Repeat("d", 120))
	b.cfg.GrantDir = filepath.Join(long, "grants")
	e := startEcho(t, long, "echo.sock")
	t.Cleanup(e.stop)
	c := &capability{Name: "echo", Type: "socket", Description: "an echo", Path: filepath.Join(long, "echo.sock")}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if _, line := echoes(t, b, filepath.Join(socketsDir, "echo")); line != "ping\n" {
		t.Errorf("Through long paths: %q", line)
	}
}
