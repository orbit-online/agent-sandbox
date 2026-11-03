package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// An opaque parameter (a CSR) is data for a host command: longer than the notification could show, so it shows a digest,
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

func TestExclusive(t *testing.T) {
	b, _ := testBroker(t, "allow")
	other, _ := testBroker(t, "allow", "allow") // both now see its XDG_RUNTIME_DIR, the host-wide lock directory
	other.cfg.Launcher = "other"
	c := testCap(t, "command")
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
	_ = b.release(g.ID, "test")
	if _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/vm"}`, "PT1H")); err != nil {
		t.Errorf("Not granted once released: %v", err)
	}
}

func TestUnitPrefixes(t *testing.T) {
	log := fakeSystemd(t)
	stopAllCalls("work")
	stopAllCalls("")
	data, _ := os.ReadFile(log)
	if string(data) != "systemctl --user stop perm-work_*\nsystemctl --user stop perm_*\n" {
		t.Errorf("Stopped:\n%s", data)
	}
	// work's pattern doesn't reach work-2's units, nor the default launcher's
	for _, other := range []string{unitPrefix("work-2") + "x", unitPrefix("") + "x"} {
		if ok, _ := filepath.Match("perm-work_*", other); ok {
			t.Errorf("perm-work_* matches %s", other)
		}
	}
}

// P13: the lock is on the instance, not on all the parameters: another value of a parameter that isn't the instance
// doesn't get a second launcher the same VM
func TestExclusiveInstance(t *testing.T) {
	b, _ := testBroker(t, "allow")
	other, _ := testBroker(t, "allow")
	other.cfg.Launcher = "other"
	c := testCap(t, "command")
	c.Exclusive = true
	instancesIn(t, c, "vm")
	b.caps[c.id()], other.caps[c.id()] = c, c
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "vm", "ro": true}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	if _, err := other.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "vm", "ro": false}`, "PT1H")); err == nil {
		t.Error("Another launcher got the instance with another value of a parameter that isn't the instance")
	}
}

// P13: the default launcher's cleanup removes its own locks, and not one another daemon is making: a lock is never
// visible without its launcher's name
func TestRemoveLocksDefault(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	c := testCap(t, "command")
	c.Exclusive = true
	release, err := c.exclusiveLock("", json.RawMessage(`{"path":"/vm"}`))
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
