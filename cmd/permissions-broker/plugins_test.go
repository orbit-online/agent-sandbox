package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	c := testCap(t, "command")
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

func TestService(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	b.cfg.Unit = "daemon.service"
	c := testCap(t, "service")
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Socket != "/run/permissions/"+g.ID+".sock" {
		t.Errorf("Socket %q", g.Socket)
	}
	if err := b.release(g.ID, nil, "test"); err != nil {
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
	c := testCap(t, "service")
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
	_ = b.release(g.ID, nil, "test")
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

// P13: the lock is on the instance list prints, not on all the parameters: another value of a parameter list doesn't
// print doesn't get a second launcher the same VM
func TestExclusiveInstance(t *testing.T) {
	fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	other, _ := testBroker(t, "allow")
	other.cfg.Launcher = "other"
	c := testCap(t, "service")
	c.Exclusive = true
	writeList(t, c, `[{"path": "/vm"}]`)
	b.caps[c.id()], other.caps[c.id()] = c, c
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm", "ro": true}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm", "ro": false}`, "PT1H")); err == nil {
		t.Error("Another launcher got the instance with another value of a parameter list doesn't print")
	}
}

// P14: one capability whose commands hang holds one plugin slot: another's commands run, and the window's list of
// the hanging one isn't held up
func TestPluginSlotsPerCapability(t *testing.T) {
	hang, other := testCap(t, "command"), testCap(t, "command")
	hang.Name, other.Name = "hang", "other"
	listed := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(listed, []byte("#!/bin/sh\necho '[]'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hang.List = []string{listed}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range cap(pluginSlots) + 2 {
		wg.Go(func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { <-stop; cancel() }()
			hang.runPlugin(exec.CommandContext(ctx, "sleep", "60"))
		})
	}
	t.Cleanup(func() { close(stop); wg.Wait() })
	time.Sleep(200 * time.Millisecond)
	done := make(chan error, 2)
	go func() { done <- other.runPlugin(exec.Command("true")) }()
	go func() { _, err := hang.listInstances(context.Background()); done <- err }()
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("A hanging capability held up another's command or its own list")
		}
	}
}
