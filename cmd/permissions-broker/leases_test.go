package main

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestParseDuration(t *testing.T) {
	for s, want := range map[string]time.Duration{"PT1H": time.Hour, "PT30M": 30 * time.Minute, "PT1H30M": 90 * time.Minute,
		"PT2S": 2 * time.Second} {
		if got, err := parseDuration(s); err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "PT", "1H", "PT0H", "P1D", "PT1h", "session"} {
		if _, err := parseDuration(s); err == nil {
			t.Errorf("parseDuration(%q) accepted", s)
		}
	}
}

func TestDurationLease(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1S"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-g.ended:
	case <-time.After(3 * time.Second):
		t.Error("A one-second lease didn't end")
	}
}

func TestLockLease(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock")); err == nil {
		t.Error("Lock lease granted without the screen lock watched")
	}
	b.lockOK = true
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock"))
	if err != nil {
		t.Fatal(err)
	}
	b.lockEvent("test lock")
	select {
	case <-g.ended:
	case <-time.After(time.Second):
		t.Error("The lock didn't end the lease")
	}
}

func TestSession(t *testing.T) {
	anchor, child := startAnchor(t, "claude")
	s, err := ownSandbox(t, os.Getpid()).sessionOf(child)
	if err != nil || s == nil {
		t.Fatalf("sessionOf = %v, %v", s, err)
	}
	if s.id != "session-1" || s.anchor != anchor.Process.Pid {
		t.Errorf("Session %q anchored at %d, want session-1 at %d", s.id, s.anchor, anchor.Process.Pid)
	}
	unix.Close(s.pidfd)

	// The session lease ends with the anchor
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, child), req(c.id(), `{}`, "session"))
	if err != nil {
		t.Fatal(err)
	}
	if sessions := b.view(g).Sessions; !slices.Equal(sessions, []string{"session-1"}) {
		t.Errorf("Grant tied to %q", sessions)
	}
	anchor.Process.Kill()
	select {
	case <-g.ended:
	case <-time.After(10 * time.Second):
		t.Error("The session lease outlived its anchor")
	}
}

func TestSessionNeedsClaude(t *testing.T) {
	_, child := startAnchor(t, "not-claude")
	if s, err := ownSandbox(t, os.Getpid()).sessionOf(child); err != nil || s != nil {
		t.Errorf("Anchored at a process that isn't Claude Code: %v, %v", s, err)
	}
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	if _, _, err := b.request(peerAt(t, child), req(c.id(), `{}`, "session")); err == nil {
		t.Error("Session lease granted without a session")
	}
}

func TestSessionStopsAtSandbox(t *testing.T) {
	anchor, child := startAnchor(t, "claude")
	// With the anchor as the sandbox's pid, the walk stops below it: nothing above the sandbox anchors a session
	if s, err := ownSandbox(t, anchor.Process.Pid).sessionOf(child); err != nil || s != nil {
		t.Errorf("Anchored at the sandbox: %v, %v", s, err)
	}
	// A carrier of the variable above the sandbox (the launcher started from a host Claude Code shell) doesn't
	// count for a caller in the sandbox without one
	_, pids := startAnchorMode(t, "claude", "anchor-deep", 2)
	sandboxInit, caller := pids[0], pids[1]
	if s, err := ownSandbox(t, sandboxInit).sessionOf(caller); err != nil || s != nil {
		t.Errorf("Anchored above the sandbox: %v, %v", s, err)
	}
}

func TestRanOut(t *testing.T) {
	b, _ := testBroker(t, "allow")
	clk := newFakeClock()
	b.clock = clk
	c := testCap(t, "command")
	b.caps[c.id()] = c
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	// The lease is over, its timer not yet fired: no output without a validity
	clk.jump(2 * time.Hour)
	if _, cred, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err == nil {
		t.Errorf("Issued %q after the lease ran out", cred)
	}
}

// P4: a request a live command grant covers waits for a plugin slot; the grant is revoked meanwhile. No output
func TestNoOutputAfterEnd(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	for range cap(pluginSlots) {
		pluginSlots <- struct{}{}
	}
	type result struct {
		cred string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		_, cred, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
		done <- result{cred, err}
	}()
	time.Sleep(200 * time.Millisecond)
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	for range cap(pluginSlots) {
		<-pluginSlots
	}
	if r := <-done; r.err == nil || r.cred != "" {
		t.Errorf("Issued %q for a grant revoked while waiting for a plugin slot", r.cred)
	}
}

// P9: the screen lock stops being watched while the user is asked about a lock lease. Allow grants nothing
func TestLockLostWhileAsking(t *testing.T) {
	b, _ := testBroker(t)
	b.lockOK = true
	b.ask = func(context.Context, prompt) (string, error) {
		b.mu.Lock()
		b.lockOK = false
		b.mu.Unlock()
		b.lockEvent("lost the system bus")
		return "allow", nil
	}
	c := testCap(t, "command")
	b.caps[c.id()] = c
	if g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock")); err == nil {
		t.Errorf("Granted a lock lease nothing watches: %+v", g)
	}
	if gs := b.liveGrants(""); len(gs) != 0 {
		t.Errorf("Live: %+v", gs)
	}
	// Made live after the bus went, it is refused there too
	if g, err := b.grant(c, json.RawMessage(`{}`), "x", "lock", nil); err == nil {
		t.Errorf("grant made a lock lease nothing watches: %+v", g)
	}
}

// A release drops the releasing session's hold only: the grant ends once no session that was given it holds it. A
// caller without a session ends it outright
func TestReleaseHold(t *testing.T) {
	b, _ := testBroker(t, "allow", "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	_, a := startAnchor(t, "claude")
	t.Setenv("SESSION_ID", "session-2")
	_, other := startAnchor(t, "claude")
	g, _, err := b.request(peerAt(t, a), req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.request(peerAt(t, other), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	release := func(pid int) {
		t.Helper()
		if res := b.handleRequest(nil, peerAt(t, pid), request{Op: "release", Grant: g.ID}); res.Error != "" {
			t.Fatal(res.Error)
		}
	}
	release(a)
	if !b.isLive(g) {
		t.Fatal("A release by one session ended the grant the other holds")
	}
	if gs := b.grantViews("session-1"); len(gs) != 0 {
		t.Errorf("The released session still holds %+v", gs)
	}
	release(other)
	if b.isLive(g) {
		t.Error("The grant outlived its last holder's release")
	}

	g, _, err = b.request(peerAt(t, a), req(c.id(), `{"path": "/b"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	release(os.Getpid())
	if b.isLive(g) {
		t.Error("A release without a session didn't end the grant")
	}
}
