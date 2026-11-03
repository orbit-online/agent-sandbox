package hostsock

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// echoAt listens at name in dir and sends back what each connection sends
func echoAt(t *testing.T, dir, name string) string {
	t.Helper()
	ln, err := Listen(dir, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); conn.Close() }()
		}
	}()
	return filepath.Join(dir, name)
}

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
		if err := Refused(path); err == nil {
			t.Errorf("%s: accepted", path)
		}
	}
	for _, glob := range []string{
		run + "/systemd/*", run + "/*.sock", run + "/*/x.sock", "/run/*/x.sock", "/*/x", "/var/*/bus",
		"/proc/*/root/agent.sock", run + "/at-spi/*", run + "/dbus-*", run + "/vms/../*.sock",
	} {
		if err := RefusedGlob(glob); err == nil {
			t.Errorf("Glob %s: accepted", glob)
		}
	}
	for _, path := range []string{run + "/ssh-agent.sock", "/srv/agent.sock", run + "/vms/a/console.sock"} {
		if err := Refused(path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
	for _, glob := range []string{run + "/vms/*/console.sock", "/srv/*.sock", run + "/vms/vm-*.sock"} {
		if err := RefusedGlob(glob); err != nil {
			t.Errorf("Glob %s: %v", glob, err)
		}
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	if err := Refused("/srv/agent.sock"); err == nil {
		t.Error("Accepted without $XDG_RUNTIME_DIR")
	}
	if err := RefusedGlob("/srv/*.sock"); err == nil {
		t.Error("Accepted a glob without $XDG_RUNTIME_DIR")
	}
}

// The broker makes an address only in a directory of its own, not through a link put where the directory goes
func TestListenNoFollow(t *testing.T) {
	dir, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(dir, "sockets")); err != nil {
		t.Fatal(err)
	}
	if ln, err := Listen(dir, filepath.Join("sockets", "agent")); err == nil {
		ln.Close()
		t.Error("Listened through a link")
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Made %v where the link leads", entries)
	}
}

// An address a daemon before left behind, a socket nobody listens at, is taken over
func TestListenStale(t *testing.T) {
	dir := t.TempDir()
	old, err := Listen(dir, filepath.Join("sockets", "agent"))
	if err != nil {
		t.Fatal(err)
	}
	old.Close()
	ln, err := Listen(dir, filepath.Join("sockets", "agent"))
	if err != nil {
		t.Fatalf("A stale address: %v", err)
	}
	ln.Close()
}

// A socket swapped for a link between the broker's check and its connect: the connect reaches the socket checked, by
// its fd, not where the link leads
func TestSocketSwappedWhileDialing(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	dir := t.TempDir()
	path := echoAt(t, dir, "agent.sock")
	busDir := t.TempDir()
	bus, err := Listen(busDir, "bus")
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	hostOpened = func() {
		_ = os.Rename(path, path+".moved")
		_ = os.Symlink(filepath.Join(busDir, "bus"), path)
	}
	t.Cleanup(func() { hostOpened = func() {} })
	conn, err := Dial(path, time.Second)
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
