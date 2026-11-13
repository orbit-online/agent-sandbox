package main

import (
	"bufio"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// fakeResolved is systemd-resolved on a dbus-daemon of the test's: one DNS server on link 2, or an error for every
// property while failing. Link 2 is a default route unless noDefaultRoute, and unknown to GetLink with noLink
type fakeResolved struct {
	mu             sync.Mutex
	server         string
	failing        bool
	noDefaultRoute bool
	noLink         bool
}

const fakeLinkPath = resolvedPath + "/link/_32"

// fakeManager is the GetLink of fakeResolved
type fakeManager struct{ f *fakeResolved }

func (m fakeManager) GetLink(ifindex int32) (dbus.ObjectPath, *dbus.Error) {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	if ifindex != 2 || m.f.noLink {
		return "", dbus.NewError("org.freedesktop.resolve1.NoSuchLink", []any{"no such link"})
	}
	return fakeLinkPath, nil
}

// fakeLink is the properties of link 2 of fakeResolved
type fakeLink struct{ f *fakeResolved }

func (l fakeLink) Get(iface, prop string) (dbus.Variant, *dbus.Error) {
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	if iface != "org.freedesktop.resolve1.Link" || prop != "DefaultRoute" {
		return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.UnknownProperty", []any{prop})
	}
	return dbus.MakeVariant(!l.f.noDefaultRoute), nil
}

func (f *fakeResolved) set(server string, failing bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.server, f.failing = server, failing
}

func (f *fakeResolved) Get(iface, prop string) (dbus.Variant, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing {
		return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.Failed", []any{"failing"})
	}
	if prop == "Domains" {
		return dbus.MakeVariant([]resolvedDomain{}), nil
	}
	a := netip.MustParseAddr(f.server)
	return dbus.MakeVariant([]resolvedServer{{Ifindex: 2, Family: 2, Addr: a.AsSlice()}}), nil
}

// systemBus starts a dbus-daemon at dir/bus, the system bus of the test, with f as resolved on it, and returns how to
// stop it
func systemBus(t *testing.T, dir string, f *fakeResolved) func() {
	t.Helper()
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(`<busconfig><type>system</type><listen>unix:path=`+dir+`/bus</listen>
<auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/></policy></busconfig>`),
		0o600); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	os.Remove(filepath.Join(dir, "bus"))
	daemon := exec.Command("dbus-daemon", "--nofork", "--nopidfile", "--config-file="+conf, "--print-address=3")
	daemon.ExtraFiles = []*os.File{w}
	err = daemon.Start()
	w.Close()
	if err != nil {
		t.Fatal("No dbus-daemon:", err)
	}
	stop := func() { daemon.Process.Kill(); daemon.Wait() }
	t.Cleanup(stop)
	// The address once it listens
	if _, err := bufio.NewReader(r).ReadString('\n'); err != nil {
		t.Fatalf("dbus-daemon's address: %v", err)
	}
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+dir+"/bus")
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.Export(f, resolvedPath, "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Export(fakeManager{f}, resolvedPath, resolvedIface); err != nil {
		t.Fatal(err)
	}
	if err := conn.Export(fakeLink{f}, fakeLinkPath, "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.RequestName(resolvedName, 0); err != nil {
		t.Fatal(err)
	}
	return stop
}

// The DNS of the host followed: a read that fails keeps what the file holds, what changed before follow subscribed is
// read once it did, and the system bus going away and coming back is followed again
func TestDNSFollow(t *testing.T) {
	w := newWorld(t)
	out := filepath.Join(w.dir, "resolv.conf")
	w.cfg.State = w.script("state", "cat >"+out)
	w.script("netns-netkit", "echo 2 0")
	w.cfg.Tools.WrapperDir = filepath.Join(w.dir, "bin")
	w.cfg.Network = true
	f := &fakeResolved{server: "192.0.2.53"}
	stop := systemBus(t, w.dir, f)
	d := newDNS(w.cfg)
	d.route = func(netip.Addr) (int, bool, error) { return 2, false, nil }
	file := func() string { data, _ := os.ReadFile(out); return string(data) }
	waitFor := func(what, want string) {
		t.Helper()
		for deadline := time.Now().Add(15 * time.Second); file() != want; time.Sleep(10 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %q, want %q", what, file(), want)
			}
		}
	}
	if err := d.update(); err != nil || file() != "nameserver 192.0.2.53\n" {
		t.Fatalf("Update: %v, %q", err, file())
	}
	f.set("192.0.2.53", true)
	if err := d.update(); !errors.Is(err, errUnread) || file() != "nameserver 192.0.2.53\n" {
		t.Errorf("Unread: %v, %q", err, file())
	}
	// Changed without a signal, before follow subscribed
	f.set("192.0.2.54", false)
	d.follow()
	waitFor("Changed during the start", "nameserver 192.0.2.54\n")
	stop()
	f = &fakeResolved{server: "192.0.2.55"}
	systemBus(t, w.dir, f)
	waitFor("After the system bus came back", "nameserver 192.0.2.55\n")
}

// A server on a link resolved doesn't take as a default route is split DNS, left out; one on a link GetLink doesn't
// know (gone meanwhile) is kept
func TestDNSLinkDefaultRoute(t *testing.T) {
	w := newWorld(t)
	w.script("netns-netkit", "echo 2 0")
	w.cfg.Tools.WrapperDir = filepath.Join(w.dir, "bin")
	w.cfg.Network = true
	f := &fakeResolved{server: "192.0.2.53"}
	systemBus(t, w.dir, f)
	d := newDNS(w.cfg)
	d.route = func(netip.Addr) (int, bool, error) { return 2, false, nil }
	for _, c := range []struct {
		noDefaultRoute, noLink bool
		want                   string
	}{
		{false, false, "nameserver 192.0.2.53\n"},
		{true, false, ""},
		{true, true, "nameserver 192.0.2.53\n"},
	} {
		f.mu.Lock()
		f.noDefaultRoute, f.noLink = c.noDefaultRoute, c.noLink
		f.mu.Unlock()
		d.mu.Lock()
		got, src, err := d.read()
		d.mu.Unlock()
		if err != nil || got != c.want || src != "systemd-resolved" {
			t.Errorf("Default route %v, link known %v: %q from %s, %v; want %q", !c.noDefaultRoute, !c.noLink, got, src, err,
				c.want)
		}
	}
}
