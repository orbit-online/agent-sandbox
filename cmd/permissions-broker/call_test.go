package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/hostcmd"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
)

// commandBroker is a broker with the test command capability, its run replaced by script
func commandBroker(t *testing.T, script string, answers ...string) (*broker, *capability, *fakeAsker) {
	t.Helper()
	b, f := testBroker(t, answers...)
	c := testCap(t, "command")
	path := filepath.Join(t.TempDir(), "run")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.Commands["run"].Run = []string{path}
	b.caps[c.id()] = c
	return b, c, f
}

// A gate the test command waits at, so a call runs until the test lets it end: each run says it started, then waits
// until the gate is open
type cmdGate struct{ dir string }

func newGate(t *testing.T) *cmdGate { return &cmdGate{dir: t.TempDir()} }

// script is a test command that waits at the gate, then runs rest
func (g *cmdGate) script(rest string) string {
	return fmt.Sprintf("mktemp -p %[1]s started.XXXXXX >/dev/null; while [ ! -e %[1]s/open ]; do sleep 0.01; done; %[2]s",
		g.dir, rest)
}

// waitStarted waits until n runs reached the gate
func (g *cmdGate) waitStarted(t *testing.T, n int) {
	t.Helper()
	waitUntil(t, fmt.Sprintf("%d calls to start", n), func() bool {
		m, _ := filepath.Glob(filepath.Join(g.dir, "started.*"))
		return len(m) >= n
	})
}

func (g *cmdGate) open(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(g.dir, "open"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

// waitSlotTaken waits until a call holds one of c's instance slots, so it's past the grant's lookup
func waitSlotTaken(t *testing.T, c *capability) {
	t.Helper()
	waitUntil(t, "a call to take its instance's slot", func() bool {
		c.slotsMu.Lock()
		defer c.slotsMu.Unlock()
		for _, s := range c.slots {
			if len(s) > 0 {
				return true
			}
		}
		return false
	})
}

// Everything a call carries is checked before the user is asked
func TestCallChecksFirst(t *testing.T) {
	b, c, f := commandBroker(t, "cat", "allow")
	c.Commands["run"].Arguments = map[string]json.RawMessage{
		"n": json.RawMessage(`{"type": "integer", "maximum": 9, "description": "a number"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []wire.Request{
		{Command: "other", Arguments: json.RawMessage(`{"n": 1}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 10}`)},
		{Command: "run", Arguments: json.RawMessage(`{}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1, "m": 2}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1}`), Params: json.RawMessage(`{"other": 1}`)},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1}`), Reason: "\n"},
		{Command: "run", Arguments: json.RawMessage(`{"n": 1}`), Lease: "forever"},
	} {
		r.Op, r.Capability = "call", c.id()
		if r.Reason == "" {
			r.Reason = "testing"
		}
		if _, err := b.call(peerAt(t, os.Getpid()), r); err == nil {
			t.Errorf("%+v called", r)
		}
	}
	if f.count() != 0 {
		t.Errorf("Asked %d times", f.count())
	}
	if _, err := b.call(peerAt(t, os.Getpid()), wire.Request{Op: "call", Capability: c.id(), Command: "run",
		Arguments: json.RawMessage(`{"n": 9}`), Reason: "testing"}); err != nil || f.count() != 1 {
		t.Errorf("A valid call: %v, asked %d times", err, f.count())
	}
	// The user was told what the grant covers
	if f.asked[0].Scope != hostcmd.Covers(c.Commands) || f.asked[0].Lease != defaultLease {
		t.Errorf("Asked %+v", f.asked[0])
	}
}

// A once grant covers the call it was made for, not one running beside it, and ends with it
func TestCallOnce(t *testing.T) {
	// A third allow, for the request that mustn't get a once grant
	g := newGate(t)
	b, c, f := commandBroker(t, g.script("cat"), "allow", "allow", "allow")
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once")
		first <- err
	}()
	g.waitStarted(t, 1)
	if gs := b.liveGrants(); len(gs) != 1 || gs[0].Lease != "once" {
		t.Fatalf("Grants while the first call runs: %v", gs)
	}
	// It waits for the first's slot once the user was asked
	go func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once")
		second <- err
	}()
	waitUntil(t, "the user to be asked for a second call beside it", func() bool { return f.count() == 2 })
	g.open(t)
	for _, ch := range []chan error{first, second} {
		if err := <-ch; err != nil {
			t.Error(err)
		}
	}
	if gs := b.liveGrants(); len(gs) != 0 {
		t.Errorf("Once grants left: %v", gs)
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "once")); err == nil || f.count() != 2 {
		t.Errorf("A request for a once grant: %v, asked %d times", err, f.count())
	}
}

// A grant whose instance went away ends; a call on an instance that isn't there is refused without asking
func TestInstanceGone(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VMS", dir)
	if err := os.WriteFile(filepath.Join(dir, "win11.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	b, c, f := commandBroker(t, "cat", "allow")
	clk := newFakeClock()
	b.clock = clk
	c.Params = map[string]json.RawMessage{"vm": json.RawMessage(`{"type": "string", "description": "the VM",
		"instances": "$VMS/*.sock"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{"vm": "win10"}`, ""); err == nil || f.count() != 0 {
		t.Errorf("No such VM: %v, asked %d times", err, f.count())
	}
	if _, err := callRun(b, peerAt(t, os.Getpid()), `{"vm": "win11"}`, ""); err != nil {
		t.Fatal(err)
	}
	g := b.liveGrants()[0]
	if err := os.Remove(filepath.Join(dir, "win11.sock")); err != nil {
		t.Fatal(err)
	}
	c.listedAt = time.Time{}
	clk.advance(instanceEvery)
	select {
	case <-g.ended:
	case <-time.After(settle):
		t.Error("The grant outlived its instance")
	}
}

// What a call can't do: carry an array or multiline bounding value, and run once its grant ended while it waited
func TestCallParamsRefused(t *testing.T) {
	for _, schema := range []string{`{"type": "array", "items": {"type": "string"}, "description": "d"}`,
		`{"type": "string", "multiline": true, "description": "d"}`} {
		c := testCap(t, "command")
		c.Params["hosts"] = json.RawMessage(schema)
		if err := c.check(); err == nil {
			t.Errorf("Bounding %s accepted", schema)
		}
	}
}

// Once grants of an exclusive capability beside each other: the lock is the launcher's, held by both
func TestCallOnceExclusive(t *testing.T) {
	g := newGate(t)
	b, c, f := commandBroker(t, g.script("cat"), "allow", "allow")
	c.Exclusive = true
	calls := make(chan error, 2)
	run := func() {
		_, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "once")
		calls <- err
	}
	go run()
	g.waitStarted(t, 1)
	go run()
	waitUntil(t, "the user to be asked for a second once call", func() bool { return f.count() == 2 })
	g.open(t)
	for range 2 {
		if err := <-calls; err != nil {
			t.Error(err)
		}
	}
	if locks := lockHolders([]string{"a", "b", "c"}); len(locks) != 0 {
		t.Errorf("Locks left: %v", locks)
	}
}

// The window may change a host command grant's lease, not its bounding values
func TestWindowKeepsBounding(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "options")
	go func() {
		for {
			b.mu.Lock()
			var id string
			for _, p := range b.pending {
				if p.Options {
					id = p.ID
				}
			}
			b.mu.Unlock()
			if id != "" {
				_ = b.answer(wire.Request{Pending: id, Allow: true, Lease: "PT8H", Params: json.RawMessage(`{"path": "/b"}`)})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Errorf("Granted %+v", g)
	}
}
