package main

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
)

// standingBroker is a test broker with c and the standing grants given, as the config names them
func standingBroker(t *testing.T, c *capability, grants ...string) (*broker, *fakeAsker) {
	t.Helper()
	b, f := testBroker(t)
	b.caps[c.id()] = c
	for _, p := range grants {
		b.cfg.Grants = append(b.cfg.Grants, standingConfig{Capability: c.id(), Params: json.RawMessage(p)})
	}
	again, err := newBroker(b.cfg, b.caps, b.sb, f.ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.endAll("test over") })
	return again, f
}

// A config error stops the daemon: a capability no plugin has, an attach one, parameters it doesn't take, one twice
func TestStandingConfig(t *testing.T) {
	cmd, attach := testCap(t, "command"), folders(t, `{"path": "/srv"}`)
	caps := map[string]*capability{cmd.id(): cmd, attach.id(): attach}
	for _, tc := range []struct {
		grants []standingConfig
		want   string
	}{
		{[]standingConfig{{Capability: "test/none"}}, "no such capability"},
		{[]standingConfig{{Capability: attach.id(), Params: json.RawMessage(`{"path": "/srv"}`)}}, "attach"},
		{[]standingConfig{{Capability: cmd.id(), Params: json.RawMessage(`{"unit": "x"}`)}}, "takes no parameter"},
		{[]standingConfig{{Capability: cmd.id(), Params: json.RawMessage(`{"path": "/a"}`)},
			{Capability: cmd.id(), Params: json.RawMessage(`{ "path":"/a" }`)}}, "twice"},
	} {
		if _, err := checkStanding(tc.grants, caps); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Standing grants %+v: %v, want %q", tc.grants, err, tc.want)
		}
	}
	if s, err := checkStanding([]standingConfig{{Capability: cmd.id(), Params: json.RawMessage(`{}`)}}, caps); err != nil ||
		len(s) != 1 {
		t.Errorf("A valid standing grant: %v", err)
	}
}

// At start: a service's standing grants whose instance list prints, one unit each; not one list doesn't print
func TestStandingAtStart(t *testing.T) {
	log := fakeSystemd(t)
	c := testCap(t, "service")
	writeList(t, c, `[{"path": "/a"}]`)
	b, f := standingBroker(t, c, `{"path": "/a"}`, `{"path": "/b"}`)
	b.grantStanding()
	gs := b.liveGrants("")
	if len(gs) != 1 || string(gs[0].Params) != `{"path":"/a"}` || gs[0].Lease != "standing" || f.count() != 0 {
		t.Fatalf("Standing grants at start: %+v, asked %d times", gs, f.count())
	}
	if data, _ := os.ReadFile(log); strings.Count(string(data), "systemd-run") != 1 {
		t.Errorf("Units started:\n%s", data)
	}
	if v := b.standingViews(); len(v) != 2 || v[0].Grant != gs[0].ID || v[1].Grant != "" {
		t.Errorf("The window's standing grants: %+v", v)
	}
}

// A command's standing grant runs without asking, for the ceiling's maxValidity; other parameters ask. Revoked, it's
// asked for until the daemon starts again
func TestStandingRevoke(t *testing.T) {
	c := testCap(t, "command")
	b, f := standingBroker(t, c, `{"path": "/a"}`)
	b.grantStanding()
	g, out, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H"))
	if err != nil || f.count() != 0 || g.Lease != "standing" || !strings.Contains(out, `"validity":"PT28800S"`) {
		t.Fatalf("The standing grant: %+v, %q, %v, asked %d times", g, out, err, f.count())
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/b"}`, "PT1H")); err == nil || f.count() != 1 {
		t.Errorf("Other parameters: %v, asked %d times", err, f.count())
	}
	if _, err := b.revoke(g.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil || f.count() != 2 {
		t.Errorf("A revoked standing grant came back: %v, asked %d times", err, f.count())
	}
	if v := b.standingViews(); !v[0].Ended || v[0].Grant != "" {
		t.Errorf("The window's standing grant: %+v", v)
	}
	// Started again: back
	again, err := newBroker(b.cfg, b.caps, b.sb, f.ask)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { again.endAll("test over") })
	again.grantStanding()
	if gs := again.liveGrants(""); len(gs) != 1 || gs[0].Lease != "standing" {
		t.Errorf("Started again: %+v", gs)
	}
}

// Released from inside so that it ends, a standing grant stays ended too
func TestStandingRelease(t *testing.T) {
	c := testCap(t, "command")
	b, f := standingBroker(t, c, `{"path": "/a"}`)
	b.grantStanding()
	g := b.liveGrants("")[0]
	if err := b.release(g.ID, nil, "released from inside"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.request(peerAt(t, os.Getpid()), req(c.id(), `{"path": "/a"}`, "PT1H")); err == nil || f.count() != 1 {
		t.Errorf("A released standing grant came back: %v, asked %d times", err, f.count())
	}
}

// A standing grant not live (its instance wasn't listed at start) is granted once however many ask at once
func TestStandingConcurrent(t *testing.T) {
	log := fakeSystemd(t)
	c := testCap(t, "service")
	b, f := standingBroker(t, c, `{}`)
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, _, _ = b.request(peerAt(t, os.Getpid()), req(c.id(), `{}`, "PT1H")) })
	}
	wg.Wait()
	data, _ := os.ReadFile(log)
	if n := strings.Count(string(data), "systemd-run"); n != 1 || f.count() != 0 {
		t.Errorf("%d units started for one standing grant, asked %d times", n, f.count())
	}
	if len(b.log) != 0 {
		t.Errorf("Standing grants logged: %d", len(b.log))
	}
}
