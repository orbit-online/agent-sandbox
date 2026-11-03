package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A release drops the releasing session's hold only: the grant ends once no session that was given it holds it. A
// caller without a session ends it outright
func TestReleaseHold(t *testing.T) {
	b, _ := testBroker(t, "allow", "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	_, a := startAnchor(t, "claude")
	t.Setenv("SESSION_ID", "session-2")
	_, other := startAnchor(t, "claude")
	g, err := b.request(peerAt(t, a), req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.request(peerAt(t, other), req(c.id(), `{}`, "PT1H")); err != nil {
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

	g, err = b.request(peerAt(t, a), req(c.id(), `{"path": "/b"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	release(os.Getpid())
	if b.isLive(g) {
		t.Error("A release without a session didn't end the grant")
	}
}

// watches counts the goroutines watching a session
func watches() int {
	buf := make([]byte, 1<<22)
	return strings.Count(string(buf[:runtime.Stack(buf, true)]), ").watchSession(")
}

// A session given a session lease before its lease's watches started is watched once: watched twice, a release would
// have both watches close its pidfd
func TestSessionWatchedOnce(t *testing.T) {
	// The grant's lease starts after the hold
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	b, _ := testBroker(t)
	c := testCap(t, "command")
	b.caps[c.id()] = c
	_, a := startAnchor(t, "claude")
	t.Setenv("SESSION_ID", "session-2")
	_, other := startAnchor(t, "claude")
	s1, _ := b.sb.sessionOf(a)
	s2, _ := b.sb.sessionOf(other)
	if s1 == nil || s2 == nil {
		t.Fatal("No sessions")
	}
	before := watches()
	g, err := b.grant(c, json.RawMessage(`{}`), "x", "session", s1)
	if err != nil {
		t.Fatal(err)
	}
	b.hold(g, s2)
	time.Sleep(100 * time.Millisecond)
	if n := watches() - before; n > 2 {
		t.Errorf("%d watches of two sessions", n)
	}
}

// A session that ends drops its hold on a grant of any lease: once the other holder releases a duration grant, nobody
// holds it and it ends. One whose last holder ended runs on, and a release from any session ends it
func TestEndedSessionDropsHold(t *testing.T) {
	b, _ := testBroker(t)
	c := testCap(t, "command")
	b.caps[c.id()] = c
	// The child's pid is printed before it execs with the variable: retried until it has
	start := func(id string) (*exec.Cmd, *session) {
		t.Helper()
		t.Setenv("SESSION_ID", id)
		anchor, child := startAnchor(t, "claude")
		for range 100 {
			if s, _ := b.sb.sessionOf(child); s != nil {
				return anchor, s
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("No session %s", id)
		return nil, nil
	}
	hold := func(g *grant, s *session) {
		if !b.hold(g, s) {
			unix.Close(s.pidfd)
		}
	}
	sessions := map[string]*session{}
	anchors := map[string]*exec.Cmd{}
	for _, id := range []string{"session-1", "session-2"} {
		anchors[id], sessions[id] = start(id)
	}
	dropped := func(g *grant, id string) {
		t.Helper()
		for range 100 {
			b.mu.Lock()
			_, held := g.sessions[id]
			b.mu.Unlock()
			if !held {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s's hold outlived its anchor", id)
	}
	ended := func(g *grant) bool {
		select {
		case <-g.ended:
			return true
		default:
			return false
		}
	}

	g, err := b.grant(c, json.RawMessage(`{}`), "x", "PT1H", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		hold(g, s)
	}
	anchors["session-1"].Process.Kill()
	dropped(g, "session-1")
	if ended(g) {
		t.Fatal("Ended with the first of two holders")
	}
	if slices.Contains(b.view(g).Sessions, "session-1") {
		t.Errorf("Held by the ended session: %v", b.view(g).Sessions)
	}
	if err := b.release(g.ID, &session{id: "session-2"}, "test"); err != nil {
		t.Fatal(err)
	}
	if !ended(g) {
		t.Error("Live after its last live holder released it")
	}

	// The last holder ends: the grant runs on until a release from any session
	anchor, s3 := start("session-3")
	g, err = b.grant(c, json.RawMessage(`{}`), "x", "PT1H", nil)
	if err != nil {
		t.Fatal(err)
	}
	hold(g, s3)
	anchor.Process.Kill()
	dropped(g, "session-3")
	if ended(g) {
		t.Fatal("A duration grant ended with its last holder's session")
	}
	if err := b.release(g.ID, &session{id: "session-2"}, "test"); err != nil {
		t.Fatal(err)
	}
	if !ended(g) {
		t.Error("Live after a release with nobody holding it")
	}
}
