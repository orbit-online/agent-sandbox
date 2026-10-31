package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConsent(t *testing.T) {
	b, f := testBroker(t, "deny", "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c

	if _, _, err := b.request(peerAt(t, os.Getpid()), request{Op: "request", Capability: c.id(), Lease: "PT1H"}); err == nil {
		t.Error("Granted without a reason")
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Error("Granted when the user denied")
	}
	g, cred, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatalf("Not granted when the user allowed: %v", err)
	}
	if f.asked[1].Summary != `the test thing (path="/a")` || f.asked[1].Reason != "testing" {
		t.Errorf("Asked %+v", f.asked[1])
	}
	// The credential's validity is the shorter of the lease's remainder and maxValidity
	var in pluginInput
	if err := json.Unmarshal([]byte(cred), &in); err != nil || in.Validity != "PT3600S" {
		t.Errorf("Issued with %q (%v), want the lease's hour", in.Validity, err)
	}
	// A live grant covers the same request without asking; other parameters ask again
	if again, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err != nil || again.ID != g.ID {
		t.Errorf("Same request got %v, %v", again, err)
	}
	if f.count() != 2 {
		t.Errorf("Asked %d times, want 2", f.count())
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a", "ro": true}`, "PT1H")); err == nil {
		t.Error("Other parameters granted without asking")
	}
}

// With a list, a request matching none of its instances is refused without asking; one matches when it has each of
// the instance's keys at the same value
func TestListed(t *testing.T) {
	b, f := testBroker(t, "allow")
	c := testCap(t, "B")
	list := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(list, []byte("#!/bin/sh\necho '[{\"path\": \"/a\"}, {\"path\": \"/b\", \"ro\": true}]'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.List = []string{list}
	b.caps[c.id()] = c
	for _, params := range []string{`{"path": "/c"}`, `{"path": "/b"}`, `{"ro": true}`} {
		if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), params, "PT1H")); err == nil {
			t.Errorf("Granted %s, which list doesn't name", params)
		}
	}
	if f.count() != 0 {
		t.Errorf("Asked about an instance list doesn't name: %+v", f.asked)
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a", "ro": true}`, "PT1H")); err != nil {
		t.Errorf("Refused an instance list names: %v", err)
	}
	// The window's answer can't name another instance either
	b, _ = testBroker(t, "options")
	b.caps[c.id()] = c
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
				_ = b.answer(request{Pending: id, Allow: true, Lease: "PT1H", Params: json.RawMessage(`{"path": "/c"}`)})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/b", "ro": true}`, "PT1H")); err == nil {
		t.Error("Granted the window's answer of an instance list doesn't name")
	}

	// A list that fails refuses, and type C's sources decide instead of its list
	if err := os.WriteFile(list, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.listedAt = time.Time{}
	if err := c.inList(context.Background(), json.RawMessage(`{"path":"/a"}`)); err == nil {
		t.Error("A failed list let a request through")
	}
	c.Type, c.listedAt = "C", time.Time{}
	if err := c.inList(context.Background(), json.RawMessage(`{"path":"/c"}`)); err != nil {
		t.Errorf("Type C checked against its list: %v", err)
	}
}

func TestRefusalLimit(t *testing.T) {
	b, f := testBroker(t)
	c := testCap(t, "B")
	b.caps[c.id()] = c
	for i := range maxRefusals {
		if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err == nil {
			t.Fatalf("Request %d granted", i)
		}
	}
	_, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
	if err == nil || !strings.Contains(err.Error(), "in a row") || f.count() != maxRefusals {
		t.Errorf("After %d refusals: %v, asked %d times", maxRefusals, err, f.count())
	}
	b.skew.Store(int64(blockFor + time.Second))
	f.answers = []string{"allow"}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Errorf("Not asked again after the block: %v", err)
	}
}

func TestAlwaysOnlyFromWindow(t *testing.T) {
	b, _ := testBroker(t, "allow")
	c := testCap(t, "B")
	b.caps[c.id()] = c
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "always"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Lease != "PT1H" || len(b.store.Always) != 0 {
		t.Errorf("A notification's Allow on always gave lease %q, stored %v", g.Lease, b.store.Always)
	}
}

func TestWindowAnswer(t *testing.T) {
	b, _ := testBroker(t, "options")
	c := testCap(t, "B")
	b.caps[c.id()] = c
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
				_ = b.answer(request{Pending: id, Allow: true, Lease: "always", Params: json.RawMessage(`{"path": "/a", "ro": true}`)})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Lease != "always" || string(g.Params) != `{"path":"/a","ro":true}` {
		t.Errorf("Window's answer gave %+v", g)
	}
	// Stored with exact parameters: read-only doesn't cover read-write
	if !b.isAlways(c, json.RawMessage(`{"path":"/a","ro":true}`)) || b.isAlways(c, json.RawMessage(`{"path":"/a"}`)) {
		t.Errorf("Always grants: %v", b.store.Always)
	}
	b2, err := newBroker(b.cfg, b.caps, b.sb, nil)
	if err != nil || len(b2.store.Always) != 1 {
		t.Errorf("Store not saved: %v, %v", b2.store.Always, err)
	}
}

func TestAnsweredInWindow(t *testing.T) {
	b, _ := testBroker(t)
	c := testCap(t, "B")
	b.caps[c.id()] = c
	cause := make(chan error, 1)
	// The notification stays up until it's taken down
	b.ask = func(ctx context.Context, p prompt) (string, error) {
		<-ctx.Done()
		cause <- context.Cause(ctx)
		return "deny", nil
	}
	go func() {
		for {
			b.mu.Lock()
			var id string
			for _, p := range b.pending {
				id = p.ID
			}
			b.mu.Unlock()
			if id != "" {
				_ = b.answer(request{Pending: id, Allow: true})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-cause:
		if !errors.Is(err, errAnswered) {
			t.Errorf("Notification taken down with %v, so it says the request timed out", err)
		}
	case <-time.After(time.Second):
		t.Error("The notification wasn't taken down")
	}
}

// P3: the instance goes away while the user is asked. Allow grants nothing
func TestListChangedWhileAsking(t *testing.T) {
	b, _ := testBroker(t)
	c := testCap(t, "B")
	writeList(t, c, `[{"path": "/a"}]`)
	b.caps[c.id()] = c
	b.ask = func(context.Context, prompt) (string, error) {
		writeList(t, c, `[]`)
		return "allow", nil
	}
	if g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Errorf("Granted an instance list no longer prints: %+v", g)
	}
}
