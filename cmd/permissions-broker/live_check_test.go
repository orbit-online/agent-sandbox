package main

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"time"

	"pgregory.net/rapid"
)

// Check: after every action the live system matches the reference, waiting a while for what it does on its own.
// Pending requests near the daemon's two minutes are denied first
func (mc *liveMachine) Check(t *rapid.T) {
	for _, p := range slices.Clone(mc.m.pending) {
		if time.Since(p.asked) > 90*time.Second {
			mc.answer(t, p, request{Op: "answer", Pending: p.id})
		}
	}
	m := mc.m
	for id, r := range m.grants {
		// P1: only after an Allow, or a standing grant from the config the user hasn't ended
		if r.lease == "standing" && !m.isStanding(r.cap, r.params) ||
			r.lease != "standing" && !m.consented[storeKey{r.cap, r.params}] {
			mc.fatalf(t, "Grant %s (%s %s %s) without consent or a standing grant", id, r.cap, r.params, r.lease)
		}
	}
	mc.checkConns(t)
	var err error
	// Not liveSettle: a failure waits this long each time rapid replays it to shrink it
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		if err = mc.compare(t); err == nil {
			return
		}
		if time.Now().After(deadline) {
			mc.fatalf(t, "%v", err)
		}
	}
}

func (mc *liveMachine) compare(t *rapid.T) error {
	m, lv := mc.m, mc.lv
	st := lv.control(request{Op: "state"})
	if st.Error != "" {
		return fmt.Errorf("State: %s", st.Error)
	}
	// P1, P4: the window's grants are the reference's, with their leases
	got := map[string]*grant{}
	for _, g := range st.Grants {
		got[g.ID] = g
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(m.grants))) {
		return fmt.Errorf("Live grants %v, want %v", describeGrants(got, func(g *grant) grant { return *g }), describeRef(m.grants))
	}
	var folders []string
	for id, r := range m.grants {
		g := got[id]
		if g.Capability != r.cap || string(g.Params) != r.params || g.Lease != r.lease {
			return fmt.Errorf("Grant %s is %s %s %s, want %s %s %s", id, g.Capability, g.Params, g.Lease, r.cap, r.params, r.lease)
		}
		if d := g.Expires.Sub(r.expires); g.Expires.IsZero() != r.expires.IsZero() || d < -5*time.Second || d > 5*time.Second {
			return fmt.Errorf("Grant %s until %v, want %v", id, g.Expires, r.expires)
		}
		if r.cap == liveFolder {
			folders = append(folders, id)
			// P3: beneath its ceiling
			if g.Source != lv.root && !strings.HasPrefix(g.Source, lv.root+"/") {
				return fmt.Errorf("Folder grant %s of %s", id, g.Source)
			}
		}
	}
	slices.Sort(folders)
	if err := checkStandingView(m, st.Standing); err != nil {
		return err
	}
	if len(st.Pending) != len(m.pending) {
		return fmt.Errorf("The window shows %d pending requests, want %d", len(st.Pending), len(m.pending))
	}
	for i, p := range st.Pending {
		r := m.pending[i]
		if p.ID != r.id || p.Capability != r.cap || string(p.Params) != r.params || p.Lease != r.lease || p.Options {
			return fmt.Errorf("Pending %d: %s %s %s %s, want %s %s %s %s", i, p.ID, p.Capability, p.Params, p.Lease, r.id,
				r.cap, r.params, r.lease)
		}
	}
	return mc.compareDelivery(t, folders)
}

// compareDelivery: P4, P11. Mounts and mountpoints for live folder grants only, in the outer mount namespace and where
// the app runs, and the echo socket's address there from the daemon's start
func (mc *liveMachine) compareDelivery(t *rapid.T, folders []string) error {
	lv := mc.lv
	entries, _ := os.ReadDir(lv.cfg.GrantDir)
	var points []string
	for _, e := range entries {
		if name := e.Name(); name != "request.sock" && name != socketsDir {
			points = append(points, name)
		}
	}
	if !slices.Equal(points, folders) {
		return fmt.Errorf("The grant directory holds mountpoints %v, want %v", points, folders)
	}
	if fi, err := os.Stat(lv.cfg.GrantDir + "/" + socketsDir + "/" + liveSock); err != nil || fi.Mode().Type() != os.ModeSocket {
		return fmt.Errorf("No address for the echo socket: %v", err)
	}
	lines, err := lv.sb.mountinfo()
	if err != nil {
		return err
	}
	var outer []string
	for _, l := range lines {
		if name, ok := strings.CutPrefix(l.point, lv.cfg.SandboxGrantDir+"/"); ok {
			outer = append(outer, name)
		}
	}
	if slices.Sort(outer); !slices.Equal(outer, folders) {
		return fmt.Errorf("Mounted in the sandbox's outer mount namespace %v, want %v", outer, folders)
	}
	res := mc.anonymous(t).do(t, request{Op: "mounts"})
	var inner []string
	for _, p := range strings.Fields(res.Output) {
		inner = append(inner, strings.TrimPrefix(p, lv.cfg.SandboxGrantDir+"/"))
	}
	if slices.Sort(inner); res.Error != "" || !slices.Equal(inner, folders) {
		return fmt.Errorf("Mounted where the app runs %v (%s), want %v", inner, res.Error, folders)
	}
	return nil
}

// checkConns: the connections to the echo socket whose grant ended are closed (P4), the others still reach the host
func (mc *liveMachine) checkConns(t *rapid.T) {
	for key, id := range mc.conns {
		res := mc.anonymous(t).do(t, request{Op: "probe", Grant: key, Reason: "probe " + key})
		switch _, live := mc.m.grants[id]; {
		case !live && !strings.HasPrefix(res.Error, "closed: "):
			mc.fatalf(t, "A connection under %s, which ended, still open: %+v", id, res)
		case !live:
			delete(mc.conns, key)
		case res.Error != "" || res.Output != "probe "+key:
			mc.fatalf(t, "A connection under %s: %+v", id, res)
		}
	}
}
