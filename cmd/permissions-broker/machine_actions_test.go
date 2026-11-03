package main

import (
	"encoding/json"
	"maps"
	"slices"
	"time"

	"pgregory.net/rapid"
)

// The state machine's other actions: ends of grants (release, revoke, leases), the daemon's life (crash, start,
// share), the environment (instances, the other launcher) and the attacker's reach for control.sock.
// protocol_events.als and protocol_system.als. Connections to host sockets are in machine_connect_test.go

// drawGrant picks a live grant's id, or one that isn't
func (mc *machine) drawGrant(t *rapid.T) string {
	ids := []string{"0123456789abcdef"}
	for _, g := range mc.m.ordered() {
		ids = append(ids, g.id)
	}
	return ids[rapid.IntRange(0, len(ids)-1).Draw(t, "grant")]
}

// Release: release from inside, which ends the grant
func (mc *machine) Release(t *rapid.T) {
	id := mc.drawGrant(t)
	pr, done := mc.w.peerOfPid(mc.w.anonymous().pid)
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
	mc.m.endedByUser(g)
	delete(mc.m.grants, id)
	mc.waitEnded(t, id)
}

// Lock: the screen locks or the machine sleeps; lock leases end (P9)
func (mc *machine) Lock(t *rapid.T) {
	mc.b.lockEvent("the screen locked")
	mc.waitEnded(t, mc.m.endWhere(func(g *refGrant) bool { return g.lease == "lock" })...)
}

// LockLost: the system bus is gone, as at lockSignals' end: no lock leases any more, and those there end (P9)
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

// Revoke: the user revokes a grant in the window; a standing grant stays ended until a restart
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
	mc.m.endedByUser(g)
	delete(mc.m.grants, id)
	mc.waitEnded(t, id)
}

// Restart: the daemon dies and systemd starts it again. What it had dies with it: its grants, timers, listeners and
// spliced connections, its questions. The new one cleans up and starts from its standing grants alone, the ended ones
// too (P12)
func (mc *machine) Restart(t *rapid.T) {
	old := mc.b
	old.closeSockets()
	for _, g := range old.liveGrants() {
		old.closeConns(g)
	}
	mc.view.die()
	m := mc.m
	clear(m.grants)
	clear(m.gates)
	clear(m.ended)
	m.pending, m.lockOK, m.shareAsked = nil, false, m.shared
	mc.startBroker(t)
}

// Share: the sandbox's outer mount namespace asks for the grant directory shared, once
func (mc *machine) Share(t *rapid.T) {
	pr, done := mc.w.peerOfPid(mc.w.sb.pid)
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
}

// ShareFromElsewhere: a process outside the sandbox's outer mount namespace asks for the share: refused (S9)
func (mc *machine) ShareFromElsewhere(t *rapid.T) {
	pr, done := mc.w.peerOfPid(mc.w.anonymous().pid)
	defer done()
	if res := mc.b.handleRequest(nil, pr, request{Op: "share"}); res.Error == "" {
		t.Fatal("Shared from another mount namespace")
	}
}

// Instances: the instances there are change (a VM started or shut down). One gone takes its console's connections
// along
func (mc *machine) Instances(t *rapid.T) {
	var names []string
	for _, n := range []string{"a", "b", "c"} {
		if rapid.Bool().Draw(t, "listed "+n) {
			names = append(names, n)
		}
	}
	mc.setListed(names)
	mc.hungUp(t, func(c *openConn) bool { return !mc.m.listed[c.name] })
}

// OtherLauncher: another launcher's daemon takes or lets go of an instance of the exclusive host commands (P13)
func (mc *machine) OtherLauncher(t *rapid.T) {
	n := rapid.SampledFrom([]string{"a", "b", "c"}).Draw(t, "instance")
	if mc.m.other[n] {
		mc.otherLocks[n]()
		delete(mc.otherLocks, n)
		delete(mc.m.other, n)
		return
	}
	unlock, err := mc.caps[capVM].exclusiveLock("other", json.RawMessage(params(map[string]any{"name": n})))
	free := mc.m.lockFree(capVM, params(map[string]any{"name": n})) && mc.m.listed[n]
	if free != (err == nil) {
		mc.fatalf(t, "The other launcher took %s: %v, want it free %v", n, err, free)
	}
	if err == nil {
		mc.otherLocks[n] = unlock
		mc.m.other[n] = true
	}
}

// AttackControl: the sandbox sends control.sock's operations (S6, P6): answering, revoking, ending holders
func (mc *machine) AttackControl(t *rapid.T) {
	req := request{Op: rapid.SampledFrom([]string{"answer", "revoke", "state", "end"}).Draw(t, "op"),
		Allow: true, Lease: "PT8H", Grant: mc.drawGrant(t), Grants: slices.Collect(maps.Keys(mc.m.grants))}
	if len(mc.m.pending) > 0 {
		req.Pending = mc.m.pending[0].id
	}
	pr, done := mc.w.peerOfPid(mc.w.anonymous().pid)
	defer done()
	if res := mc.b.handleControl(nil, pr, req); res.Error != "Only from the host" {
		mc.fatalf(t, "control.sock served the sandbox's %s: %+v", req.Op, res)
	}
}
