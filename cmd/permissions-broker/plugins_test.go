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

// An opaque parameter (a CSR) is data for the plugin: longer than the notification could show, so it shows a digest,
// and still free of control characters, so it can't forge lines of its own
func TestOpaqueParam(t *testing.T) {
	c := testCap(t, "command")
	c.Params["csr"] = json.RawMessage(`{"type": "string", "opaque": true, "description": "a CSR"}`)
	if err := c.check(); err != nil {
		t.Fatalf("check: %v", err)
	}
	csr := strings.Repeat("MIIB", maxOpaque/4)
	got, err := c.validate(json.RawMessage(`{"csr": "` + csr + `"}`))
	if err != nil {
		t.Fatalf("validate refused %d characters: %v", len(csr), err)
	}
	d := c.describe(got)
	if strings.Contains(d, "MIIB") || !strings.Contains(d, "csr=sha256:") || !strings.Contains(d, "(8192 characters)") {
		t.Errorf("describe = %.120q", d)
	}
	other, _ := c.validate(json.RawMessage(`{"csr": "` + csr[1:] + `"}`))
	if c.describe(other) == d {
		t.Error("two different values describe the same")
	}
	for _, bad := range []string{
		`{"csr": "` + csr + `A"}`,
		`{"csr": "MIIB\nAllowed by the host"}`,
		`{"path": "` + strings.Repeat("x", maxParam+1) + `"}`,
	} {
		if _, err := c.validate(json.RawMessage(bad)); err == nil {
			t.Errorf("validate accepted %.60s", bad)
		}
	}
	c.Params["big"] = json.RawMessage(`{"type": "boolean", "opaque": true}`)
	if err := c.check(); err == nil {
		t.Error("check accepted an opaque boolean")
	}
}

func TestService(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t, "allow")
	b.cfg.Unit = "daemon.service"
	c := testCap(t, "service")
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
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
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H")); err == nil ||
		!strings.Contains(err.Error(), "launcher test") {
		t.Errorf("Another launcher got an exclusive instance: %v", err)
	}
	_ = b.release(g.ID, nil, "test")
	if _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H")); err != nil {
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
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm", "ro": true}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm", "ro": false}`, "PT1H")); err == nil {
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

// P13: the default launcher's cleanup removes its own locks, and not one another daemon is making: a lock is never
// visible without its launcher's name
func TestRemoveLocksDefault(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	c := testCap(t, "service")
	c.Exclusive = true
	release, err := c.exclusiveLock(context.Background(), "", json.RawMessage(`{"path":"/vm"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	dir := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "agent-sandbox-permissions")
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("Locks: %v", entries)
	}
	if data, _ := os.ReadFile(filepath.Join(dir, entries[0].Name())); string(data) != "\n" {
		t.Errorf("The default launcher's lock holds %q", data)
	}
	making := filepath.Join(dir, "test_thing-other")
	if err := os.WriteFile(making, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	removeLocks("")
	if _, err := os.Stat(making); err != nil {
		t.Error("Removed a lock without content, another daemon's in the making")
	}
	if _, err := os.Stat(filepath.Join(dir, entries[0].Name())); err == nil {
		t.Error("Left the default launcher's own lock")
	}
}

// writeList gives c a list command printing instances
func writeList(t *testing.T, c *capability, instances string) {
	t.Helper()
	list := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(list, []byte("#!/bin/sh\necho '"+instances+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.List, c.listedAt = []string{list}, time.Time{}
}
