package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	c := testCap(t, "B")
	got, err := c.validate(json.RawMessage(`{"ro": true, "path": "/a"}`))
	if err != nil || string(got) != `{"path":"/a","ro":true}` {
		t.Errorf("validate = %s, %v; want sorted keys", got, err)
	}
	for _, bad := range []string{`{"other": 1}`, `{"ro": "yes"}`, `{"path": 1}`, `[1]`} {
		if _, err := c.validate(json.RawMessage(bad)); err == nil {
			t.Errorf("validate(%s) accepted", bad)
		}
	}
	if d := c.describe(got); d != `the test thing (path="/a", ro=true)` {
		t.Errorf("describe = %q", d)
	}
}

func TestTypeA(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	b.cfg.Unit = "daemon.service"
	c := testCap(t, "A")
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Socket != "/run/permissions/"+g.ID+".sock" {
		t.Errorf("Socket %q", g.Socket)
	}
	if err := b.release(g.ID, "test"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	unit := unitName("test", g.ID)
	for _, bound := range []string{"--property=BindsTo=daemon.service", "--socket-property=BindsTo=daemon.service"} {
		if !strings.Contains(string(data), bound) {
			t.Errorf("Not bound to the daemon (%s):\n%s", bound, data)
		}
	}
	if !strings.Contains(string(data), "--unit="+unit+" --socket-property=ListenStream="+filepath.Join(b.cfg.GrantDir, g.ID+".sock")) ||
		!strings.Contains(string(data), "systemctl --user stop "+unit+".socket "+unit+".service") {
		t.Errorf("systemd calls:\n%s", data)
	}
}

func TestExclusive(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	other, _ := testBroker(t, "allow", "allow") // both now see its XDG_RUNTIME_DIR, the host-wide lock directory
	other.cfg.Launcher = "other"
	c := testCap(t, "A")
	c.Exclusive = true
	b.caps[c.id()], other.caps[c.id()] = c, c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H")); err == nil ||
		!strings.Contains(err.Error(), "launcher test") {
		t.Errorf("Another launcher got an exclusive instance: %v", err)
	}
	_ = b.release(g.ID, "test")
	if _, _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H")); err != nil {
		t.Errorf("Not granted once released: %v", err)
	}
}

func TestUnitPrefixes(t *testing.T) {
	log := fakeSystemd(t)
	stopAllServes("work")
	stopAllServes("")
	data, _ := os.ReadFile(log)
	if string(data) != "systemctl --user stop perm-work_*\nsystemctl --user stop perm_*\n" {
		t.Errorf("Stopped:\n%s", data)
	}
	// work's pattern doesn't reach work-2's units, nor the default launcher's
	for _, other := range []string{unitName("work-2", "x"), unitName("", "x")} {
		if ok, _ := filepath.Match("perm-work_*", other); ok {
			t.Errorf("perm-work_* matches %s", other)
		}
	}
}
