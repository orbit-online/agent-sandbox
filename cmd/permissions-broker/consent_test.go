package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestConsent(t *testing.T) {
	b, f := testBroker(t, "deny", "allow")
	c := testCap(t, "command")
	b.caps[c.id()] = c

	if _, err := b.request(peerAt(t, os.Getpid()), request{Op: "request", Capability: c.id(), Lease: "PT1H"}); err == nil {
		t.Error("Granted without a reason")
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Error("Granted when the user denied")
	}
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatalf("Not granted when the user allowed: %v", err)
	}
	if f.asked[1].Summary != `the test thing (path="/a")` || f.asked[1].Reason != "testing" {
		t.Errorf("Asked %+v", f.asked[1])
	}
	// The window shows the grant with the reason it was allowed for
	if g.Reason != "testing" {
		t.Errorf("Grant's reason %q", g.Reason)
	}
	// A call's validity is the shorter of the lease's remainder and maxValidity
	res, err := callRun(b, peerAt(t, os.Getpid()), `{"path": "/a"}`, "")
	if err != nil {
		t.Fatalf("Call under the grant: %v", err)
	}
	if in := calledWith(t, res); in.Validity != "PT3600S" || string(in.Bounding) != `{"path":"/a"}` || in.Grant != g.ID {
		t.Errorf("Called with %+v, want the lease's hour", in)
	}
	// A live grant covers the same request without asking; other parameters ask again
	if again, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err != nil || again.ID != g.ID {
		t.Errorf("Same request got %v, %v", again, err)
	}
	if f.count() != 2 {
		t.Errorf("Asked %d times, want 2", f.count())
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a", "ro": true}`, "PT1H")); err == nil {
		t.Error("Other parameters granted without asking")
	}
}

// With a list, a request matching none of its instances is refused without asking; one matches when it has each of
// the instance's keys at the same value
func TestListed(t *testing.T) {
	b, f := testBroker(t, "allow")
	c := testCap(t, "command")
	list := filepath.Join(t.TempDir(), "list")
	if err := os.WriteFile(list, []byte("#!/bin/sh\necho '[{\"path\": \"/a\"}, {\"path\": \"/b\", \"ro\": true}]'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.List = []string{list}
	b.caps[c.id()] = c
	for _, params := range []string{`{"path": "/c"}`, `{"path": "/b"}`, `{"ro": true}`} {
		if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), params, "PT1H")); err == nil {
			t.Errorf("Granted %s, which list doesn't name", params)
		}
	}
	if f.count() != 0 {
		t.Errorf("Asked about an instance list doesn't name: %+v", f.asked)
	}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a", "ro": true}`, "PT1H")); err != nil {
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
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/b", "ro": true}`, "PT1H")); err == nil {
		t.Error("Granted the window's answer of an instance list doesn't name")
	}

	// A list that fails refuses, and an attach capability's sources decide instead of its list
	if err := os.WriteFile(list, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	c.listedAt = time.Time{}
	if err := c.inList(context.Background(), json.RawMessage(`{"path":"/a"}`)); err == nil {
		t.Error("A failed list let a request through")
	}
	c.Type, c.listedAt = "attach", time.Time{}
	if err := c.inList(context.Background(), json.RawMessage(`{"path":"/c"}`)); err != nil {
		t.Errorf("Attach capability checked against its list: %v", err)
	}
}

func TestRefusalLimit(t *testing.T) {
	b, f := testBroker(t)
	clk := newFakeClock()
	b.clock = clk
	c := testCap(t, "command")
	b.caps[c.id()] = c
	for i := range maxRefusals {
		if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err == nil {
			t.Fatalf("Request %d granted", i)
		}
	}
	_, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
	if err == nil || !strings.Contains(err.Error(), "in a row") || f.count() != maxRefusals {
		t.Errorf("After %d refusals: %v, asked %d times", maxRefusals, err, f.count())
	}
	clk.advance(blockFor + time.Second)
	f.answers = []string{"allow"}
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
		t.Errorf("Not asked again after the block: %v", err)
	}
}

func TestWindowAnswer(t *testing.T) {
	b, _ := testBroker(t, "options")
	fakeSystemd(t)
	c := testCap(t, "service")
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
				_ = b.answer(request{Pending: id, Allow: true, Lease: "PT8H", Params: json.RawMessage(`{"path": "/a", "ro": true}`)})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil {
		t.Fatal(err)
	}
	if g.Lease != "PT8H" || string(g.Params) != `{"path":"/a","ro":true}` {
		t.Errorf("Window's answer gave %+v", g)
	}
}

func TestAnsweredInWindow(t *testing.T) {
	b, _ := testBroker(t)
	c := testCap(t, "command")
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
	if _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err != nil {
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
	c := testCap(t, "command")
	writeList(t, c, `[{"path": "/a"}]`)
	b.caps[c.id()] = c
	b.ask = func(context.Context, prompt) (string, error) {
		writeList(t, c, `[]`)
		return "allow", nil
	}
	if g, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil {
		t.Errorf("Granted an instance list no longer prints: %+v", g)
	}
}

// The window gets pending requests in the order they came, every time
func TestPendingOrder(t *testing.T) {
	b, _ := testBroker(t)
	var want []string
	for i := range 8 {
		id := fmt.Sprintf("p%d", i)
		b.pending[id] = &pending{ID: id, seq: uint64(i + 1)}
		want = append(want, id)
	}
	for range 20 {
		var got []string
		for _, p := range b.handleControl(nil, peerAt(t, os.Getpid()), request{Op: "state"}).Pending {
			got = append(got, p.ID)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("Pending in the order %v", got)
		}
	}
}

// The window gets the call that asks: its command and free arguments whole, opaque ones by digest
func TestPendingCall(t *testing.T) {
	b, c, _ := commandBroker(t, "cat", "options")
	c.Commands["run"].Arguments = map[string]json.RawMessage{
		"script": json.RawMessage(`{"type": "string", "multiline": true, "description": "a script"}`),
		"csr":    json.RawMessage(`{"type": "string", "opaque": true, "description": "a CSR"}`)}
	if err := c.check(); err != nil {
		t.Fatal(err)
	}
	script, csr := strings.Repeat("Get-Item\n", 40), strings.Repeat("A", 64)
	seen := make(chan *pending, 1)
	go func() {
		for {
			var asked *pending
			b.mu.Lock()
			for _, p := range b.pending {
				if p.Options {
					asked = p
				}
			}
			b.mu.Unlock()
			if asked != nil {
				seen <- asked
				_ = b.answer(request{Pending: asked.ID})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	args, _ := json.Marshal(map[string]string{"script": script, "csr": csr})
	_, _ = b.call(peerAt(t, os.Getpid()), request{Op: "call", Capability: c.id(), Command: "run", Arguments: args,
		Reason: "testing"})
	p := <-seen
	var got map[string]string
	_ = json.Unmarshal(p.Arguments, &got)
	if p.Command != "run" || got["script"] != script || got["csr"] != opaqueDigest(csr) || p.Scope != c.scope() {
		t.Errorf("Pending %s %v, scope %q", p.Command, got, p.Scope)
	}
}
