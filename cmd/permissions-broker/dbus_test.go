package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProxy stands in for a D-Bus proxy's control socket: it records each request and answers ok, or the error set
type fakeProxy struct {
	mu     sync.Mutex
	got    []dbusSet
	refuse string
	conns  []net.Conn
}

func startFakeProxy(t *testing.T) (*fakeProxy, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeProxy{}
	t.Cleanup(func() { ln.Close(); f.drop() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns = append(f.conns, conn)
			f.mu.Unlock()
			go func() {
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadBytes('\n')
					if err != nil {
						return
					}
					var s dbusSet
					_ = json.Unmarshal(line, &s)
					f.mu.Lock()
					f.got = append(f.got, s)
					res := `{"ok":true}`
					if f.refuse != "" {
						res = `{"error":"` + f.refuse + `"}`
					}
					f.mu.Unlock()
					_, _ = conn.Write([]byte(res + "\n"))
				}
			}()
		}
	}()
	return f, path
}

// drop closes the broker's connections, as a proxy that went away
func (f *fakeProxy) drop() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.conns {
		c.Close()
	}
	f.conns = nil
}

// ops is what the broker sent, in order
func (f *fakeProxy) ops() []dbusSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]dbusSet{}, f.got...)
}

func dbusCap(t *testing.T, name string, dc dbusConfig) *capability {
	t.Helper()
	dc.Name, dc.Description = name, "a test rule set"
	caps := map[string]*capability{}
	if err := loadDBus([]dbusConfig{dc}, caps); err != nil {
		t.Fatal(err)
	}
	return caps[name]
}

// What the broker refuses to declare: rules that would undo the proxies' static guards, wildcards and own on the
// system bus, and what the proxy wouldn't take
func TestDBusDeclarations(t *testing.T) {
	for name, dc := range map[string]dbusConfig{
		"no bus":                    {Talk: []string{"org.test.A"}},
		"another bus":               {Bus: "accessibility", Talk: []string{"org.test.A"}},
		"no rules":                  {Bus: "session"},
		"the bus driver":            {Bus: "session", Talk: []string{"org.freedesktop.DBus"}},
		"the bus driver, system":    {Bus: "system", Talk: []string{"org.freedesktop.DBus"}},
		"below the bus driver":      {Bus: "session", See: []string{"org.freedesktop.DBus.Monitoring"}},
		"a wildcard over the bus":   {Bus: "session", Talk: []string{"org.freedesktop.*"}},
		"a call over the bus":       {Bus: "session", Call: map[string][]string{"org.*": {"*"}}},
		"notifications":             {Bus: "session", Call: map[string][]string{"org.freedesktop.Notifications": {"*"}}},
		"the user manager":          {Bus: "session", Talk: []string{"org.freedesktop.systemd1"}},
		"flatpak's HostCommand":     {Bus: "session", Talk: []string{"org.freedesktop.Flatpak"}},
		"a portal backend":          {Bus: "session", Talk: []string{"org.freedesktop.impl.portal.desktop.kde"}},
		"the accessibility bus":     {Bus: "session", Broadcast: map[string][]string{"org.a11y.Bus": {"*"}}},
		"a wildcard, system":        {Bus: "system", Talk: []string{"org.freedesktop.timedate1.*"}},
		"own, system":               {Bus: "system", Own: []string{"org.test.A"}},
		"not a name":                {Bus: "session", Talk: []string{"nodots"}},
		"a unique name":             {Bus: "session", Talk: []string{":1.2"}},
		"not a rule":                {Bus: "session", Call: map[string][]string{"org.test.A": {"x@bad"}}},
		"a name without rules":      {Bus: "session", Call: map[string][]string{"org.test.A": {}}},
		"too many rules":            {Bus: "session", See: strings.Split(strings.Repeat("org.test.A,", maxDBusRules+1), ",")[:maxDBusRules+1]},
		"a session system cap name": {Bus: "session", Talk: []string{"org.test.A"}, Name: "a/b"},
	} {
		dc.Description = "d"
		if dc.Name == "" {
			dc.Name = "test"
		}
		if err := loadDBus([]dbusConfig{dc}, map[string]*capability{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := loadDBus([]dbusConfig{{Name: "x", Bus: "session", Talk: []string{"org.test.A"}}}, map[string]*capability{}); err == nil {
		t.Error("No description: accepted")
	}
	caps := map[string]*capability{}
	if err := loadDBus([]dbusConfig{
		{Name: "timedate", Description: "d", Bus: "system", Talk: []string{"org.freedesktop.timedate1"}},
		{Name: "hostname", Description: "d", Bus: "system",
			Call: map[string][]string{"org.freedesktop.hostname1": {"org.freedesktop.DBus.Properties.Get@/org/freedesktop/hostname1"}}},
		{Name: "portal", Description: "d", Bus: "session", See: []string{"org.freedesktop.portal.*"},
			Call:      map[string][]string{"org.freedesktop.portal.Desktop": {"*@/org/freedesktop/portal/*", "*@/"}},
			Broadcast: map[string][]string{"org.freedesktop.portal.Desktop": {"org.freedesktop.portal.Settings.*"}}},
	}, caps); err != nil {
		t.Fatal(err)
	}
	if err := loadDBus([]dbusConfig{{Name: "portal", Description: "d", Bus: "session", Talk: []string{"org.test.A"}}}, caps); err == nil {
		t.Error("A capability declared twice")
	}
	if got := caps["hostname"].dbusScope(); got != "On the system bus: call org.freedesktop.hostname1: "+
		"org.freedesktop.DBus.Properties.Get@/org/freedesktop/hostname1." {
		t.Errorf("The scope: %q", got)
	}
}

// A grant adds its rule set to its bus's proxy, after a consent naming the bus and the rules; its end removes it
func TestDBusGrant(t *testing.T) {
	b, f := testBroker(t, "allow", "allow")
	session, sessionPath := startFakeProxy(t)
	system, systemPath := startFakeProxy(t)
	b.cfg.DBusControl = map[string]string{"session": sessionPath, "system": systemPath}
	c := dbusCap(t, "timedate", dbusConfig{Bus: "system", Talk: []string{"org.freedesktop.timedate1"},
		Call: map[string][]string{"org.freedesktop.hostname1": {"org.freedesktop.DBus.Properties.Get"}}})
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req("timedate", `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 1 || !strings.Contains(f.asked[0].Scope, "On the system bus: call any method of org.freedesktop.timedate1") ||
		!strings.Contains(f.asked[0].Scope, "org.freedesktop.hostname1: org.freedesktop.DBus.Properties.Get") {
		t.Errorf("The consent: %+v", f.asked)
	}
	ops := system.ops()
	if len(ops) != 1 || ops[0].Op != "add" || ops[0].ID != g.ID || strings.Join(ops[0].Talk, " ") != "org.freedesktop.timedate1" ||
		strings.Join(ops[0].Call, " ") != "org.freedesktop.hostname1=org.freedesktop.DBus.Properties.Get" {
		t.Errorf("The system proxy got %+v", ops)
	}
	if len(session.ops()) != 0 {
		t.Errorf("The session proxy got %+v", session.ops())
	}
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if ops := system.ops(); len(ops) != 2 || ops[1].Op != "remove" || ops[1].ID != g.ID {
		t.Errorf("After the revoke the system proxy got %+v", ops)
	}
	// A set the proxy refuses is no grant
	system.mu.Lock()
	system.refuse = "no"
	system.mu.Unlock()
	if _, err := b.request(peerAt(t, os.Getpid()), req("timedate", `{}`, "PT1H")); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Errorf("A refused set granted: %v", err)
	}
	if len(b.liveGrants()) != 0 {
		t.Errorf("Grants left: %v", b.liveGrants())
	}
}

// A standing grant's set goes to the proxy at start; a proxy whose connection broke ends the grants on its bus, and
// the next grant reaches it again
func TestDBusStandingAndLost(t *testing.T) {
	proxy, path := startFakeProxy(t)
	c := dbusCap(t, "portal", dbusConfig{Bus: "session", Talk: []string{"org.test.A"}})
	b, _ := testBroker(t)
	b.cfg.DBusControl = map[string]string{"session": path}
	b.cfg.Grants = []standingConfig{{Capability: "portal"}}
	b.caps[c.id()] = c
	other := dbusCap(t, "other", dbusConfig{Bus: "session", See: []string{"org.test.B"}})
	b.caps[other.id()] = other
	b.cfg.Grants = append(b.cfg.Grants, standingConfig{Capability: "other"})
	b, err := newBroker(b.cfg, b.caps, b.sb, (&fakeAsker{}).ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.endAll("test over") })
	b.grantStanding()
	if ops := proxy.ops(); len(ops) != 2 || ops[0].Op != "add" || ops[1].Op != "add" {
		t.Fatalf("At start the proxy got %+v", ops)
	}
	grants := b.liveGrants()
	proxy.drop()
	if err := b.release(grants[0].ID, "testing"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(b.liveGrants()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(b.liveGrants()) != 0 {
		t.Errorf("A grant outlived its proxy's connection: %v", b.liveGrants())
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req("other", `{}`, "")); err != nil {
		t.Fatalf("The standing grant after the proxy's connection broke: %v", err)
	}
	if ops := proxy.ops(); ops[len(ops)-1].Op != "add" || ops[len(ops)-1].ID != b.liveGrants()[0].ID {
		t.Errorf("The proxy got %+v", ops)
	}
}
