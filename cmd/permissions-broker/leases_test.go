package main

import (
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
	c := testCap(t, "B")
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
	c := testCap(t, "B")
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
	s, err := sessionOf(child, os.Getpid())
	if err != nil || s == nil {
		t.Fatalf("sessionOf = %v, %v", s, err)
	}
	if s.id != "session-1" || s.anchor != anchor.Process.Pid {
		t.Errorf("Session %q anchored at %d, want session-1 at %d", s.id, s.anchor, anchor.Process.Pid)
	}
	unix.Close(s.pidfd)

	// The session lease ends with the anchor
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
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
	if s, err := sessionOf(child, os.Getpid()); err != nil || s != nil {
		t.Errorf("Anchored at a process that isn't Claude Code: %v, %v", s, err)
	}
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if _, _, err := b.request(peerAt(t, child), req(c.id(), `{}`, "session")); err == nil {
		t.Error("Session lease granted without a session")
	}
}

func TestSessionStopsAtSandbox(t *testing.T) {
	anchor, child := startAnchor(t, "claude")
	// With the anchor as the sandbox's pid, the walk stops below it: nothing above the sandbox anchors a session
	if s, err := sessionOf(child, anchor.Process.Pid); err != nil || s != nil {
		t.Errorf("Anchored at the sandbox: %v, %v", s, err)
	}
	// A carrier of the variable above the sandbox (the launcher started from a host Claude Code shell) doesn't
	// count for a caller in the sandbox without one
	_, pids := startAnchorMode(t, "claude", "anchor-deep", 2)
	sandboxInit, caller := pids[0], pids[1]
	if s, err := sessionOf(caller, sandboxInit); err != nil || s != nil {
		t.Errorf("Anchored above the sandbox: %v, %v", s, err)
	}
}

func TestRanOut(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	// The lease is over, its timer not yet fired: no credential without a validity
	b.skew.Store(int64(2 * time.Hour))
	if _, cred, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err == nil {
		t.Errorf("Issued %q after the lease ran out", cred)
	}
}
