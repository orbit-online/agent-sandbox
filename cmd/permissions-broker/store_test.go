package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAlwaysConcurrent(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t)
	c := testCap(t, "service")
	b.caps[c.id()] = c
	b.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{}`)}}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
		}()
	}
	wg.Wait()
	data, _ := os.ReadFile(log)
	if n := strings.Count(string(data), "systemd-run"); n != 1 {
		t.Errorf("%d units started for one always grant", n)
	}
	if len(b.store.Log) != 0 {
		t.Errorf("Always hits logged: %d", len(b.store.Log))
	}
}

func TestBrokenStore(t *testing.T) {
	b, _ := testBroker(t)
	if err := os.WriteFile(b.cfg.Store, []byte(`{"always": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newBroker(b.cfg, b.caps, b.sb, nil); err != nil {
		t.Errorf("A broken store keeps the daemon from starting: %v", err)
	}
	if _, err := os.Stat(b.cfg.Store + ".broken"); err != nil {
		t.Errorf("The broken store wasn't set aside: %v", err)
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

// P12: replaying the service type starts only the stored always grants whose instance list still prints
func TestReplayListed(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t)
	c := testCap(t, "service")
	writeList(t, c, `[{"path": "/a"}]`)
	b.caps[c.id()] = c
	b.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{"path":"/b"}`)},
		{Capability: c.id(), Params: json.RawMessage(`{"path":"/a"}`)}}
	b.replay("service")
	gs := b.liveGrants("")
	if len(gs) != 1 || string(gs[0].Params) != `{"path":"/a"}` {
		t.Errorf("Replayed %+v", gs)
	}
	if data, _ := os.ReadFile(log); strings.Count(string(data), "systemd-run") != 1 {
		t.Errorf("Units started:\n%s", data)
	}
}

// Revoking an always grant ends it for good: the next request asks
func TestRevokeAlways(t *testing.T) {
	b, f := testBroker(t)
	c := testCap(t, "command")
	b.caps[c.id()] = c
	b.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{}`)}}
	g, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H"))
	if err != nil || f.count() != 0 {
		t.Fatalf("The always grant: %v, asked %d times", err, f.count())
	}
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")); err == nil || f.count() != 1 {
		t.Errorf("A revoked always grant came back: %v, asked %d times", err, f.count())
	}
}

// An always grant from the store a daemon started with (saved indented) counts as granted, and revoke and forget remove
// it: neither asks again nor comes back at the next start
func TestAlwaysAfterRestart(t *testing.T) {
	b, f := testBroker(t)
	c := testCap(t, "command")
	b.caps[c.id()] = c
	b.addAlways(c, json.RawMessage(`{"path":"/a"}`))
	b.addAlways(c, json.RawMessage(`{"path":"/b"}`))
	again, err := newBroker(b.cfg, b.caps, b.sb, f.ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.endAll("test over") })
	g, _, err := again.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil || f.count() != 0 {
		t.Fatalf("The stored always grant: %v, asked %d times", err, f.count())
	}
	if _, err := again.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if err := again.forget(c.id(), json.RawMessage(`{"path":"/b"}`)); err != nil {
		t.Fatal(err)
	}
	if third, err := newBroker(b.cfg, b.caps, b.sb, nil); err != nil || len(third.store.Always) != 0 {
		t.Errorf("Revoked and forgotten, still stored: %+v, %v", third.store.Always, err)
	}
}
