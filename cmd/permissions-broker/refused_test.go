package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// What a host socket may not be: buses beyond the session and system bus (the systemd user manager's, the
// accessibility bus, proxies), /proc aliases, /var/run, a path that isn't clean, and globs that could match any of
// those; and nothing at all without $XDG_RUNTIME_DIR
func TestSocketRefusals(t *testing.T) {
	run := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", run)
	for _, path := range []string{
		run + "/systemd/private", run + "/at-spi/bus_0", run + "/.dbus-proxy/session-bus-proxy-1", run + "/dbus-1/x",
		run + "/bus", "/proc/self/root" + run + "/ssh-agent.sock", "/proc/1/cwd/agent.sock",
		"/var/run/user/1000/bus", "/var/run/agent.sock", "/run/dbus/other", run + "/a/../bus", run + "//bus",
		run + "/./bus", run, filepath.Dir(run),
	} {
		if err := refusedSocket(path); err == nil {
			t.Errorf("%s: accepted", path)
		}
	}
	for _, glob := range []string{
		run + "/systemd/*", run + "/*.sock", run + "/*/x.sock", "/run/*/x.sock", "/*/x", "/var/*/bus",
		"/proc/*/root/agent.sock", run + "/at-spi/*", run + "/dbus-*", run + "/vms/../*.sock",
	} {
		if err := refusedGlob(glob); err == nil {
			t.Errorf("Glob %s: accepted", glob)
		}
	}
	for _, path := range []string{run + "/ssh-agent.sock", "/srv/agent.sock", run + "/vms/a/console.sock"} {
		if err := refusedSocket(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, glob := range []string{run + "/vms/*/console.sock", "/srv/*.sock", run + "/vms/vm-*.sock"} {
		if err := refusedGlob(glob); err != nil {
			t.Errorf("Glob %s: %v", glob, err)
		}
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	if err := refusedSocket("/srv/agent.sock"); err == nil {
		t.Error("Accepted without $XDG_RUNTIME_DIR")
	}
	if err := refusedGlob("/srv/*.sock"); err == nil {
		t.Error("Accepted a glob without $XDG_RUNTIME_DIR")
	}
}

// A glob's match that's a link, or reached through one, or isn't a socket, is no instance: a link planted where the
// glob looks can't lead the broker to a refused socket
func TestSocketLinkedMatch(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testSocket(t, b, "a")
	dir := filepath.Dir(c.glob)
	bus := startEcho(t, t.TempDir(), "bus")
	t.Cleanup(bus.stop)
	if err := os.Symlink(bus.path, filepath.Join(dir, "evil.sock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, linkedDir); err != nil {
		t.Fatal(err)
	}
	found, err := c.globMatches()
	if err != nil || len(found) != 1 || found["a"] == "" {
		t.Errorf("Instances %v, %v: want a alone", found, err)
	}
	c.glob = linkedDir + "/*.sock"
	if found, err := c.globMatches(); err != nil || len(found) != 0 {
		t.Errorf("Instances through a linked directory %v, %v", found, err)
	}
}

// A declared socket swapped for a link after the grant: the next connection isn't spliced to where the link leads.
// Nor is one to a path through /proc, or to something that isn't a socket
func TestSocketLinkSwapped(t *testing.T) {
	b, _ := testBroker(t, "allow")
	dir := t.TempDir()
	e := startEcho(t, dir, "agent.sock")
	t.Cleanup(e.stop)
	c := &capability{Name: "agent", Type: "socket", Description: "an agent", Path: e.path}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	b.caps[c.id()] = c
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	addr := filepath.Join(socketsDir, "agent")
	if _, line := echoes(t, b, addr); line != "ping\n" {
		t.Fatalf("Before the swap: %q", line)
	}
	bus := startEcho(t, t.TempDir(), "bus")
	t.Cleanup(bus.stop)
	moved := filepath.Join(dir, "moved.sock")
	if err := os.Rename(e.path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(bus.path, e.path); err != nil {
		t.Fatal(err)
	}
	if _, line := echoes(t, b, addr); line != "" {
		t.Errorf("Spliced through a link: %q", line)
	}
	if _, err := dialHost(moved, time.Second); err != nil {
		t.Errorf("The socket itself: %v", err)
	}
	for _, path := range []string{"/proc/self/root" + moved, filepath.Join(dir, "file")} {
		_ = os.WriteFile(filepath.Join(dir, "file"), nil, 0o600)
		if conn, err := dialHost(path, time.Second); err == nil {
			conn.Close()
			t.Errorf("Connected to %s", path)
		}
	}
}

// An instance's name is its address's: one too long for a socket path, even through /proc/self/fd, isn't an instance,
// and a request naming it is refused for its length
func TestInstanceNameLength(t *testing.T) {
	b, _ := testBroker(t, "allow")
	b.cfg.GrantDir = filepath.Join(t.TempDir(), strings.Repeat("g", 120))
	long, fits := strings.Repeat("x", maxAddrName+1), strings.Repeat("y", maxAddrName)
	c := testSocket(t, b)
	dir := filepath.Dir(c.glob)
	for _, n := range []string{long, fits} {
		e := startEcho(t, dir, n+".sock")
		t.Cleanup(func() { e.ln.Close() })
	}
	found, _ := c.globMatches()
	if len(found) != 1 || found[fits] == "" {
		t.Errorf("Instances %v", found)
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "`+long+`"}`, "PT1H")); err == nil ||
		!strings.Contains(err.Error(), "at most 80 characters") {
		t.Errorf("A name too long: %v", err)
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "`+fits+`"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if _, line := echoes(t, b, filepath.Join(socketsDir, "vm", fits)); line != "ping\n" {
		t.Errorf("At the longest name: %q", line)
	}
}

// A sync that looked for instances before a grant's did can't close the listener the grant opened
func TestSyncRacesGrant(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testSocket(t, b)
	looked, release := make(chan struct{}), make(chan struct{})
	first := true
	globbed = func() {
		if first {
			first = false
			close(looked)
			select {
			case <-release:
			case <-time.After(time.Second):
			}
		}
	}
	t.Cleanup(func() { globbed = func() {} })
	synced := make(chan struct{})
	go func() { b.syncSockets(c); close(synced) }()
	<-looked
	e := startEcho(t, filepath.Dir(c.glob), "a.sock")
	t.Cleanup(e.stop)
	c.listMu.Lock()
	c.listedAt = time.Time{}
	c.listMu.Unlock()
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"vm": "a"}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-synced
	if _, line := echoes(t, b, filepath.Join(socketsDir, "vm", "a")); line != "ping\n" {
		t.Errorf("The grant's address after the earlier sync: %q", line)
	}
}

// A socket swapped for a link between the broker's check and its connect: the connect reaches the socket checked, by
// its fd, not where the link leads
func TestSocketSwappedWhileDialing(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()
	e := startEcho(t, dir, "agent.sock")
	t.Cleanup(e.stop)
	busDir := t.TempDir()
	bus, err := listenIn(busDir, "bus")
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	hostOpened = func() {
		_ = os.Rename(e.path, e.path+".moved")
		_ = os.Symlink(filepath.Join(busDir, "bus"), e.path)
	}
	t.Cleanup(func() { hostOpened = func() {} })
	conn, err := dialHost(e.path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = bus.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if c, err := bus.Accept(); err == nil {
		c.Close()
		t.Error("Connected where the link swapped in leads")
	}
}
