package main

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"

	"pgregory.net/rapid"
)

// The state machine's other actions: ends of grants (release, revoke, forget, leases), the daemon's life (crash,
// start, replay, share), the environment (sessions, instances, the other launcher) and the attacker's reach for
// control.sock. protocol_events.als and protocol_system.als

// drawGrant picks a live grant's id, or one that isn't
func (mc *machine) drawGrant(t *rapid.T) string {
	ids := []string{"0123456789abcdef"}
	for _, g := range mc.m.ordered() {
		ids = append(ids, g.id)
	}
	return ids[rapid.IntRange(0, len(ids)-1).Draw(t, "grant")]
}

// Release: release from inside, by a session or a caller without one. A release drops only the caller's hold; the
// grant ends once nobody holds it
func (mc *machine) Release(t *rapid.T) {
	id := mc.drawGrant(t)
	who := mc.drawCaller(t)
	pr, done := mc.w.peerOfPid(who.pid)
	res := mc.b.handleRequest(nil, pr, request{Op: "release", Grant: id})
	done()
	g := mc.m.grants[id]
	if g == nil {
		if res.Error == "" {
			mc.fatalf(t, "Released %s, which isn't granted", id)
		}
		return
	}
	if res.Error != "" {
		mc.fatalf(t, "Release %s: %s", id, res.Error)
	}
	if mc.m.release(g, who.sess) {
		mc.waitEnded(t, id)
	}
}

// NewSession: a Claude Code session starts in the sandbox
func (mc *machine) NewSession(t *rapid.T) {
	if len(mc.w.sessions) >= 3 {
		t.Skip("Sessions enough")
	}
	mc.w.session()
}

// EndSession: a session's anchor exits, dropping its holds; the session leases it was the last holder of end (P8)
func (mc *machine) EndSession(t *rapid.T) {
	if len(mc.w.sessions) == 0 {
		t.Skip("No session")
	}
	id := rapid.SampledFrom(slices.Sorted(maps.Keys(mc.w.sessions))).Draw(t, "session")
	mc.w.endSession(id)
	mc.waitEnded(t, mc.m.sessionEnd(id)...)
	// The grants that go on drop it too
	mc.waitFor(t, "the session's holds dropped", func() bool {
		mc.b.mu.Lock()
		defer mc.b.mu.Unlock()
		for _, g := range mc.b.grants {
			if g.sessions[id] != nil {
				return false
			}
		}
		return true
	})
}

// Lock: the screen locks or the machine sleeps; lock leases end (P9)
func (mc *machine) Lock(t *rapid.T) {
	mc.b.lockEvent("the screen locked")
	mc.waitEnded(t, mc.m.endWhere(func(g *refGrant) bool { return g.lease == "lock" })...)
}

// LockLost: the system bus is gone, as at watchLogind's end: no lock leases any more, and those there end (P9)
func (mc *machine) LockLost(t *rapid.T) {
	mc.b.mu.Lock()
	mc.b.lockOK = false
	mc.b.mu.Unlock()
	mc.b.lockEvent("the screen lock isn't watched any more")
	mc.m.lockOK = false
	mc.waitEnded(t, mc.m.endWhere(func(g *refGrant) bool { return g.lease == "lock" })...)
}

// LockWatched: watchLogind found the graphical session
func (mc *machine) LockWatched(t *rapid.T) {
	mc.b.mu.Lock()
	mc.b.lockOK = true
	mc.b.mu.Unlock()
	mc.m.lockOK = true
}

// Advance: time passes. Duration leases run out, unanswered notifications and the window time out, blocks lift
func (mc *machine) Advance(t *rapid.T) {
	d := rapid.SampledFrom([]time.Duration{time.Second, 59 * time.Second, askTimeout, optionsTimeout, 31 * time.Minute,
		time.Hour}).Draw(t, "by")
	mc.clk.advance(d)
	m := mc.m
	m.now = m.now.Add(d)
	mc.waitEnded(t, m.endWhere(func(g *refGrant) bool { return !g.expires.IsZero() && !g.expires.After(m.now) })...)
	for _, p := range slices.Clone(m.pending) {
		if !p.options && !p.asked.Add(askTimeout).After(m.now) || p.options && !p.optionsAt.Add(optionsTimeout).After(m.now) {
			mc.refused(t, p, mc.waitDone(t, p))
		}
	}
}

// Revoke: the user revokes a grant in the window; an always grant leaves the store too
func (mc *machine) Revoke(t *rapid.T) {
	id := mc.drawGrant(t)
	res := mc.b.handleControl(nil, mc.w.host, request{Op: "revoke", Grant: id})
	g := mc.m.grants[id]
	if g == nil {
		if res.Error == "" {
			mc.fatalf(t, "Revoked %s, which isn't granted", id)
		}
		return
	}
	if res.Error != "" {
		mc.fatalf(t, "Revoke %s: %s", id, res.Error)
	}
	if g.lease == "always" {
		mc.m.removeAlways(storeKey{g.cap, g.params})
	}
	delete(mc.m.grants, id)
	mc.waitEnded(t, id)
}

// Forget: the user forgets an always grant in the window: out of the store, and its live grants end
func (mc *machine) Forget(t *rapid.T) {
	var k storeKey
	if len(mc.m.store) > 0 && rapid.Bool().Draw(t, "stored") {
		k = rapid.SampledFrom(mc.m.store).Draw(t, "always")
	} else {
		k.cap = rapid.SampledFrom(caps).Draw(t, "capability")
		k.params = mc.drawParams(t, k.cap)
	}
	if res := mc.b.handleControl(nil, mc.w.host, request{Op: "forget", Capability: k.cap,
		Params: json.RawMessage(k.params)}); res.Error != "" {
		mc.fatalf(t, "Forget %v: %s", k, res.Error)
	}
	mc.m.removeAlways(k)
	mc.waitEnded(t, mc.m.endWhere(func(g *refGrant) bool {
		return g.cap == k.cap && g.params == k.params && g.lease == "always"
	})...)
}

// Restart: the daemon dies and systemd starts it again. What it had dies with it: its timers and session watches,
// its questions. The new one cleans up, replays the stored always services, and folders once it finds the grant
// directory shared (P12)
func (mc *machine) Restart(t *rapid.T) {
	old := mc.b
	old.mu.Lock()
	for _, g := range old.grants {
		for _, s := range g.sessions {
			close(s.dropped)
		}
		clear(g.sessions)
	}
	old.mu.Unlock()
	mc.view.die()
	m := mc.m
	clear(m.grants)
	clear(m.gates)
	m.pending, m.lockOK, m.shareAsked = nil, false, m.shared
	before := mc.grantedCount()
	mc.startBroker()
	mc.replayed(t, "service", before)
	if m.shared {
		mc.replayed(t, "attach", before)
	}
}

// replayed expects the stored always grants of a type that pass the ceiling and the exclusive locks, in store order,
// and finds them among the grants made since before
func (mc *machine) replayed(t *rapid.T, typ string, before int) {
	m := mc.m
	var want []storeKey
	for _, k := range m.store {
		if mc.caps[k.cap].Type != typ || !m.passes(k.cap, k.params, mc.w.root) || m.matching(k.cap, k.params) != nil ||
			slices.Contains(want, k) {
			continue
		}
		if m.lockFree(k.cap, k.params) {
			// Granted, here under a provisional id, so the next one sees its lock
			m.grant("replay-"+k.cap+k.params, k.cap, k.params, "always", "")
			want = append(want, k)
		}
	}
	// Folders replay in the background: wait for as many grants as expected
	mc.waitFor(t, "the replay of "+typ, func() bool {
		n := 0
		for _, id := range mc.grantedSince(before) {
			mc.b.mu.Lock()
			if g := mc.b.grants[id]; g != nil && g.cap.Type == typ {
				n++
			}
			mc.b.mu.Unlock()
		}
		return n >= len(want)
	})
	mc.b.mu.Lock()
	defer mc.b.mu.Unlock()
	for _, k := range want {
		g := m.grants["replay-"+k.cap+k.params]
		delete(m.grants, g.id)
		for id, bg := range mc.b.grants {
			if bg.Capability == k.cap && string(bg.Params) == k.params {
				g.id = id
			}
		}
		m.grants[g.id] = g
	}
}

// Share: the sandbox's outer mount namespace asks for the grant directory shared, once; then folders replay
func (mc *machine) Share(t *rapid.T) {
	pr, done := mc.w.peerOfPid(mc.w.sb.pid)
	before := mc.grantedCount()
	res := mc.b.handleRequest(nil, pr, request{Op: "share"})
	done()
	if mc.m.shareAsked {
		if res.Error == "" {
			t.Fatal("Shared twice")
		}
		return
	}
	if res.Error != "" {
		mc.fatalf(t, "Share: %s", res.Error)
	}
	mc.m.shared, mc.m.shareAsked = true, true
	mc.replayed(t, "attach", before)
}

// ShareFromElsewhere: a process outside the sandbox's outer mount namespace asks for the share: refused (S9)
func (mc *machine) ShareFromElsewhere(t *rapid.T) {
	pr, done := mc.w.peerOfPid(mc.w.anonymous().pid)
	defer done()
	if res := mc.b.handleRequest(nil, pr, request{Op: "share"}); res.Error == "" {
		t.Fatal("Shared from another mount namespace")
	}
}

// Instances: what the service's list prints changes (a VM started or shut down)
func (mc *machine) Instances(t *rapid.T) {
	var names []string
	for _, n := range []string{"a", "b", "c"} {
		if rapid.Bool().Draw(t, "listed "+n) {
			names = append(names, n)
		}
	}
	mc.setListed(names)
}

// OtherLauncher: another launcher's daemon takes or lets go of an instance of the exclusive service (P13)
func (mc *machine) OtherLauncher(t *rapid.T) {
	n := rapid.SampledFrom([]string{"a", "b", "c"}).Draw(t, "instance")
	if mc.m.other[n] {
		mc.otherLocks[n]()
		delete(mc.otherLocks, n)
		delete(mc.m.other, n)
		return
	}
	unlock, err := mc.caps[capVM].exclusiveLock(context.Background(), "other", json.RawMessage(params(map[string]any{"name": n})))
	free := mc.m.lockFree(capVM, params(map[string]any{"name": n})) && mc.m.listed[n]
	if free != (err == nil) {
		mc.fatalf(t, "The other launcher took %s: %v, want it free %v", n, err, free)
	}
	if err == nil {
		mc.otherLocks[n] = unlock
		mc.m.other[n] = true
	}
}

// AttackControl: the sandbox sends control.sock's operations (S6, P6): answering, revoking, forgetting
func (mc *machine) AttackControl(t *rapid.T) {
	req := request{Op: rapid.SampledFrom([]string{"answer", "revoke", "forget", "state", "end"}).Draw(t, "op"),
		Allow: true, Lease: "always", Grant: mc.drawGrant(t), Grants: slices.Collect(maps.Keys(mc.m.grants))}
	if len(mc.m.pending) > 0 {
		req.Pending = mc.m.pending[0].id
	}
	if len(mc.m.store) > 0 {
		req.Capability, req.Params = mc.m.store[0].cap, json.RawMessage(mc.m.store[0].params)
	}
	pr, done := mc.w.peerOfPid(mc.w.anonymous().pid)
	defer done()
	if res := mc.b.handleControl(nil, pr, req); res.Error != "Only from the host" {
		mc.fatalf(t, "control.sock served the sandbox's %s: %+v", req.Op, res)
	}
}
