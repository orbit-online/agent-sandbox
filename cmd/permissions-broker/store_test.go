package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestAlwaysConcurrent(t *testing.T) {
	log := fakeSystemd(t)
	b, _ := testBroker(t)
	c := testCap(t, "A")
	b.caps[c.id()] = c
	b.store.Always = []alwaysGrant{{Capability: c.id(), Params: json.RawMessage(`{}`)}}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = b.request(os.Getpid(), req(c.id(), `{}`, "PT1H"))
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
