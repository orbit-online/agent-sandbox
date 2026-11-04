package main

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"pgregory.net/rapid"
)

// Check: after every action, the broker's state and the window's view against the reference, and
// the properties of models/README.md as invariants
func (mc *machine) Check(t *rapid.T) {
	m, b := mc.m, mc.b
	b.mu.Lock()
	type seen struct{ g grant }
	got := map[string]seen{}
	for id, g := range b.grants {
		got[id] = seen{*snapshot(g)}
	}
	lockOK := b.lockOK
	gates := map[string]gate{}
	for id, g := range b.gates {
		gates[id] = *g
	}
	pendingIDs := slices.Sorted(maps.Keys(b.pending))
	b.mu.Unlock()

	// P1, P4: the broker's grants are the reference's, with their leases and expiry
	if !slices.Equal(slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(m.grants))) {
		mc.fatalf(t, "Live grants %v, want %v", describeGrants(got, func(s seen) grant { return s.g }), describeRef(m.grants))
	}
	for id, r := range m.grants {
		s := got[id]
		if s.g.Capability != r.cap || canonical(objectOf(s.g.Params)) != r.params || s.g.Lease != r.lease ||
			!s.g.Expires.Equal(r.expires) {
			mc.fatalf(t, "Grant %s is %s %s %s until %v, want %s %s %s until %v", id, s.g.Capability, s.g.Params, s.g.Lease,
				s.g.Expires, r.cap, r.params, r.lease, r.expires)
		}
		// P1: only after an Allow, or a standing grant from the config the user hasn't ended
		if r.lease == "standing" && !m.isStanding(r.cap, r.params) ||
			r.lease != "standing" && !m.consented[storeKey{r.cap, r.params}] {
			mc.fatalf(t, "Grant %s (%s %s %s) without consent or a standing grant", id, r.cap, r.params, r.lease)
		}
		// P3: a folder beneath its ceiling
		if r.cap == capFolder && !strings.HasPrefix(s.g.Source, mc.w.root+"/") {
			mc.fatalf(t, "Folder grant %s of %s", id, s.g.Source)
		}
		// P9: no lock lease while the lock isn't watched
		if r.lease == "lock" && !lockOK {
			mc.fatalf(t, "Lock lease %s while the lock isn't watched", id)
		}
	}
	if lockOK != m.lockOK {
		mc.fatalf(t, "Lock watched: %v, want %v", lockOK, m.lockOK)
	}
	mc.checkDelivery(t)
	mc.checkProxy(t)
	mc.checkConns(t)
	mc.checkWindow(t)
	// P14: one question per capability, and the refusal block
	for _, c := range slices.Sorted(maps.Keys(mc.caps)) {
		g, r := gates[c], m.gate(c)
		if g.asking != r.asking || g.refused != r.refused || !g.blockedUntil.Equal(r.blockedUntil) {
			mc.fatalf(t, "Gate of %s: %+v, want %+v", c, g, *r)
		}
	}
	var wantPending []string
	for _, p := range m.pending {
		wantPending = append(wantPending, p.id)
	}
	if slices.Sort(wantPending); !slices.Equal(pendingIDs, wantPending) {
		mc.fatalf(t, "Pending %v, want %v", pendingIDs, wantPending)
	}
}

// checkDelivery: P4, P11, P13. Mounts and mountpoints for live folder grants only, exclusive locks for what's granted
// here or at the other launcher, and the consoles' addresses where the broker listens
func (mc *machine) checkDelivery(t *rapid.T) {
	var folders []string
	locks := map[string]string{}
	for id, g := range mc.m.grants {
		switch g.cap {
		case capVM:
			locks[g.vals["name"].(string)] = "test"
		case capFolder:
			folders = append(folders, id)
		}
	}
	for n := range mc.m.other {
		if locks[n] != "" {
			mc.fatalf(t, "Instance %s granted here and at the other launcher", n)
		}
		locks[n] = "other"
	}
	slices.Sort(folders)
	if mounted := slices.Sorted(maps.Keys(mc.w.mounted())); !slices.Equal(mounted, folders) {
		mc.fatalf(t, "Mounted in the sandbox %v, want %v", mounted, folders)
	}
	entries, _ := os.ReadDir(mc.w.cfg.GrantDir)
	var points []string
	for _, e := range entries {
		if e.Name() != "request.sock" && e.Name() != socketsDir {
			points = append(points, e.Name())
		}
	}
	if !slices.Equal(points, folders) {
		mc.fatalf(t, "Mountpoints %v, want %v", points, folders)
	}
	if held := lockHolders(mc.names); !maps.Equal(held, locks) {
		mc.fatalf(t, "Exclusive locks %v, want %v", held, locks)
	}
	if got := mc.w.listening(); !maps.Equal(got, mc.m.listening) {
		mc.fatalf(t, "Listening at the consoles of %v, want %v", got, mc.m.listening)
	}
}

// checkWindow: what control.sock's state shows the window, pending requests in arrival order
func (mc *machine) checkWindow(t *rapid.T) {
	res := mc.b.handleControl(nil, mc.w.host, wire.Request{Op: "state"})
	if res.Error != "" {
		mc.fatalf(t, "State: %s", res.Error)
	}
	var ids []string
	for _, g := range res.Grants {
		ids = append(ids, g.ID)
	}
	if slices.Sort(ids); !slices.Equal(ids, slices.Sorted(maps.Keys(mc.m.grants))) {
		mc.fatalf(t, "The window shows grants %v, want %v", ids, slices.Sorted(maps.Keys(mc.m.grants)))
	}
	if err := checkStandingView(mc.m, res.Standing); err != nil {
		mc.fatalf(t, "%v", err)
	}
	if len(res.Pending) != len(mc.m.pending) {
		mc.fatalf(t, "The window shows %d pending requests, want %d", len(res.Pending), len(mc.m.pending))
	}
	for i, p := range res.Pending {
		r := mc.m.pending[i]
		if p.ID != r.id || p.Capability != r.cap || canonical(objectOf(p.Params)) != r.params || p.Lease != r.lease || p.Options != r.options {
			mc.fatalf(t, "Pending %d: %s %s %s %s options %v, want %s %s %s %s options %v", i, p.ID, p.Capability, p.Params,
				p.Lease, p.Options, r.id, r.cap, r.params, r.lease, r.options)
		}
	}
}

// checkStandingView: the window's standing grants are the config's, each ended as the user ended it and with its live
// grant
func checkStandingView(m *model, views []standingGrant) error {
	if len(views) != len(m.standing) {
		return fmt.Errorf("The window shows %d standing grants, want %d", len(views), len(m.standing))
	}
	for i, v := range views {
		k := m.standing[i]
		live := ""
		if g := m.matching(k.cap, k.params); g != nil && g.lease == "standing" {
			live = g.id
		}
		if v.Capability != k.cap || canonical(objectOf(v.Params)) != k.params || v.Ended != m.ended[k] || v.Grant != live {
			return fmt.Errorf("The window shows standing grant %s %s ended %v live %q, want %v ended %v live %q",
				v.Capability, v.Params, v.Ended, v.Grant, k, m.ended[k], live)
		}
	}
	return nil
}

func describeGrants[V any](gs map[string]V, g func(V) grant) []string {
	var out []string
	for id, v := range gs {
		x := g(v)
		out = append(out, id+" "+x.Capability+" "+string(x.Params)+" "+x.Lease)
	}
	slices.Sort(out)
	return out
}

func describeRef(gs map[string]*refGrant) []string {
	var out []string
	for id, g := range gs {
		out = append(out, id+" "+g.cap+" "+g.params+" "+g.lease)
	}
	slices.Sort(out)
	return out
}
