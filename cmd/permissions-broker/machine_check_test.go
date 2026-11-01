package main

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"

	"pgregory.net/rapid"
)

// Check: after every action, the broker's state, its store file and the window's view against the reference, and
// the properties of models/README.md as invariants
func (mc *machine) Check(t *rapid.T) {
	m, b := mc.m, mc.b
	b.mu.Lock()
	type seen struct {
		g       grant
		anon    bool
		anchors []string
	}
	got := map[string]seen{}
	for id, g := range b.grants {
		got[id] = seen{*snapshot(g), g.anon, slices.Sorted(maps.Keys(g.sessions))}
	}
	lockOK := b.lockOK
	gates := map[string]gate{}
	for id, g := range b.gates {
		gates[id] = *g
	}
	pendingIDs := slices.Sorted(maps.Keys(b.pending))
	b.mu.Unlock()

	// P1, P4, release holds: the broker's grants are the reference's, with their holders, leases and expiry
	if !slices.Equal(slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(m.grants))) {
		mc.fatalf(t, "Live grants %v, want %v", describeGrants(got, func(s seen) grant { return s.g }), describeRef(m.grants))
	}
	for id, r := range m.grants {
		s := got[id]
		if s.g.Capability != r.cap || string(s.g.Params) != r.params || s.g.Lease != r.lease ||
			!s.g.Expires.Equal(r.expires) {
			mc.fatalf(t, "Grant %s is %s %s %s until %v, want %s %s %s until %v", id, s.g.Capability, s.g.Params, s.g.Lease,
				s.g.Expires, r.cap, r.params, r.lease, r.expires)
		}
		if !slices.Equal(s.g.Sessions, r.holders) || s.anon != r.anon ||
			!slices.Equal(s.anchors, slices.Sorted(maps.Keys(r.anchors))) {
			mc.fatalf(t, "Grant %s held by %v (anonymous %v, anchors %v), want %v (%v, %v)", id, s.g.Sessions, s.anon,
				s.anchors, r.holders, r.anon, slices.Sorted(maps.Keys(r.anchors)))
		}
		// P1: an always grant only while stored, any other only after an Allow
		if r.lease == "always" && !m.isAlways(r.cap, r.params) || r.lease != "always" && !m.consented[storeKey{r.cap, r.params}] {
			mc.fatalf(t, "Grant %s (%s %s %s) without consent or a stored always grant", id, r.cap, r.params, r.lease)
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
	mc.checkStore(t)
	mc.checkWindow(t)
	// P14: one question per capability, and the refusal block
	for _, c := range caps {
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

// checkDelivery: P4, P11, P13. Units up for live service grants only, mounts and mountpoints for live folder grants
// only, and exclusive locks for what's granted here or at the other launcher
func (mc *machine) checkDelivery(t *rapid.T) {
	var units, folders []string
	locks := map[string]string{}
	for id, g := range mc.m.grants {
		switch g.cap {
		case capVM:
			units = append(units, id)
			locks[decode(g.params)["name"].(string)] = "test"
		case capConsole:
			units = append(units, id)
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
	slices.Sort(units)
	slices.Sort(folders)
	if up := slices.Sorted(maps.Keys(mc.w.unitsUp())); !slices.Equal(up, units) {
		mc.fatalf(t, "Units up %v, want %v", up, units)
	}
	if mounted := slices.Sorted(maps.Keys(mc.w.mounted())); !slices.Equal(mounted, folders) {
		mc.fatalf(t, "Mounted in the sandbox %v, want %v", mounted, folders)
	}
	entries, _ := os.ReadDir(mc.w.cfg.GrantDir)
	var points []string
	for _, e := range entries {
		if e.Name() != "request.sock" {
			points = append(points, e.Name())
		}
	}
	if !slices.Equal(points, folders) {
		mc.fatalf(t, "Mountpoints %v, want %v", points, folders)
	}
	if held := lockHolders(); !maps.Equal(held, locks) {
		mc.fatalf(t, "Exclusive locks %v, want %v", held, locks)
	}
}

// checkStore: P2, P12 and revoke. The store file holds exactly the always grants, in order
func (mc *machine) checkStore(t *rapid.T) {
	var s storeData
	if data, err := os.ReadFile(mc.w.cfg.Store); err == nil {
		if err := json.Unmarshal(data, &s); err != nil {
			mc.fatalf(t, "Store: %v", err)
		}
	}
	if got := storeKeys(s.Always); !slices.Equal(got, mc.m.store) {
		mc.fatalf(t, "Store %v, want %v", got, mc.m.store)
	}
}

// checkWindow: what control.sock's state shows the window, pending requests in arrival order
func (mc *machine) checkWindow(t *rapid.T) {
	res := mc.b.handleControl(nil, mc.w.host, request{Op: "state"})
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
	if got := storeKeys(res.Always); !slices.Equal(got, mc.m.store) {
		mc.fatalf(t, "The window shows always grants %v, want %v", got, mc.m.store)
	}
	if len(res.Pending) != len(mc.m.pending) {
		mc.fatalf(t, "The window shows %d pending requests, want %d", len(res.Pending), len(mc.m.pending))
	}
	for i, p := range res.Pending {
		r := mc.m.pending[i]
		if p.ID != r.id || p.Capability != r.cap || string(p.Params) != r.params || p.Lease != r.lease || p.Options != r.options {
			mc.fatalf(t, "Pending %d: %s %s %s %s options %v, want %s %s %s %s options %v", i, p.ID, p.Capability, p.Params,
				p.Lease, p.Options, r.id, r.cap, r.params, r.lease, r.options)
		}
	}
}

func storeKeys(as []alwaysGrant) []storeKey {
	var ks []storeKey
	for _, a := range as {
		var p bytes.Buffer
		_ = json.Compact(&p, a.Params)
		ks = append(ks, storeKey{a.Capability, p.String()})
	}
	return ks
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
