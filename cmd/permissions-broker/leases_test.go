package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
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
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1S"))
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
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock")); err == nil {
		t.Error("Lock lease granted without the screen lock watched")
	}
	b.lockOK = true
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock"))
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

func TestRanOut(t *testing.T) {
	b, _ := testBroker(t, "allow")
	clk := newFakeClock()
	b.clock = clk
	c := testCap(t, "command")
	b.caps[c.id()] = c
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	// The lease is over, its timer not yet fired: no output without a validity
	clk.jump(2 * time.Hour)
	if res, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "PT1H"); err == nil {
		t.Errorf("Ran with %q after the lease ran out", res.Output)
	}
}

// P4: a call a live grant covers waits for a call slot; the grant is revoked meanwhile. No output
func TestNoOutputAfterEnd(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	for range cap(callSlots) {
		callSlots <- struct{}{}
	}
	type result struct {
		cred string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		res, err := callRun(b, peerAt(t, os.Getpid()), `{}`, "PT1H")
		done <- result{res.Output, err}
	}()
	time.Sleep(200 * time.Millisecond)
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	for range cap(callSlots) {
		<-callSlots
	}
	if r := <-done; r.err == nil || r.cred != "" {
		t.Errorf("Issued %q for a grant revoked while waiting for a call slot", r.cred)
	}
}

// A lock lease asked for right after the daemon starts: watchLogind returns only once the watch is set up, however
// slowly the bus answers, and the signals' end refuses lock leases again
func TestLockWatchedOnReturn(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c
	signals := make(chan *dbus.Signal)
	watchLogind(b, func() (<-chan *dbus.Signal, string, error) {
		time.Sleep(100 * time.Millisecond)
		return signals, "1", nil
	})
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock")); err != nil {
		t.Fatalf("Lock lease refused right after watchLogind: %v", err)
	}
	close(signals)
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		b.mu.Lock()
		ok := b.lockOK
		b.mu.Unlock()
		if !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Lock still watched after the signals ended")
		}
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
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "lock")); err == nil {
		t.Errorf("Granted a lock lease nothing watches: %+v", g)
	}
	if gs := b.liveGrants(); len(gs) != 0 {
		t.Errorf("Live: %+v", gs)
	}
	// Made live after the bus went, it is refused there too
	if g, err := b.grant(c, json.RawMessage(`{}`), "x", "", "lock"); err == nil {
		t.Errorf("grant made a lock lease nothing watches: %+v", g)
	}
}
