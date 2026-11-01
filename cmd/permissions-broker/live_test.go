package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// The state machine tests (machine_test.go) live, in the VM test (nix/checks/vm.nix): a smaller set of the same
// actions against the work launcher's daemon under systemd, its real sandbox and plugins. Requests come from this
// binary run inside the sandbox through the launcher's re-entry (live_procs_test.go), as a session's agent below an
// anchor named claude, a forged session below one named node, or a caller without one; the user's answers, revoke and
// forget come through control.sock from the host. After every step the window's state, the store file, the service
// units, the grant directory and the mounts in the sandbox's outer mount namespace and where the app runs match the
// reference model (machine_model_test.go).
//
// Without LIVE_CONFIG it skips. The VM test sets: LIVE_CONFIG (the daemon's config), LIVE_LAUNCHER (the launcher,
// whose --exec runs a command in the sandbox), LIVE_BIN (a copy of this binary named claude where the sandbox sees it,
// with a copy named node next to it), LIVE_ROOT (a folder the ceiling allows, read-only, with a folder sub beneath),
// LIVE_OUTSIDE (one outside it) and LIVE_LOCK_SESSION (alice's graphical logind session, which the Lock action locks).
// It runs a few sequences with a fixed seed; more by hand, with -rapid.checks, -rapid.steps and -rapid.seed=0 (see
// CLAUDE.md)
func TestLiveMachine(t *testing.T) {
	if os.Getenv("LIVE_CONFIG") == "" {
		t.Skip("Runs in the VM test")
	}
	lv := newLiveEnv(t)
	rapidDefault(t, "rapid.checks", "15")
	rapidDefault(t, "rapid.steps", "100")
	// Each step takes the live system a while: rapid's 30 s don't shrink a failure far
	rapidDefault(t, "rapid.shrinktime", "3m")
	rapid.Check(t, func(rt *rapid.T) {
		actions := rapid.StateMachineActions(newLiveMachine(rt, lv))
		// Weights: Repeat picks actions evenly, and most requests wait for an answer or are refused
		for _, a := range []string{"Request", "Request", "Request", "Request", "WindowAnswer", "WindowAnswer",
			"WindowAnswer", "Restart"} {
			actions[a+strconv.Itoa(len(actions))] = actions[a]
		}
		if lv.lockSess == "" {
			delete(actions, "Lock")
		}
		rt.Repeat(actions)
	})
}

// How long the live system gets for what it does on its own
const liveSettle = 15 * time.Second

const (
	liveCmd    = "test/thing"
	liveSvc    = "test/echo"
	liveFolder = "folders/folder"
	// The command's ceiling
	liveMaxValidity = 8 * time.Hour
)

type liveEnv struct {
	cfg                 config
	launcher, bin, node string
	root, outside       string
	lockSess            string
	sb                  *sandbox
	desc                map[string]string // the capabilities' descriptions
}

func newLiveEnv(t *testing.T) *liveEnv {
	cfg, err := readConfig(os.Getenv("LIVE_CONFIG"))
	if err != nil {
		t.Fatal(err)
	}
	bin := os.Getenv("LIVE_BIN")
	lv := &liveEnv{cfg: cfg, launcher: os.Getenv("LIVE_LAUNCHER"), bin: bin,
		node: bin[:strings.LastIndex(bin, "/")+1] + "node", root: os.Getenv("LIVE_ROOT"),
		outside: os.Getenv("LIVE_OUTSIDE"), lockSess: os.Getenv("LIVE_LOCK_SESSION"), desc: map[string]string{}}
	if lv.sb, err = lookupSandbox(os.Getenv("XDG_RUNTIME_DIR"), cfg.AppID); err != nil {
		t.Fatal(err)
	}
	res := rawCall(cfg.ControlSocket, request{Op: "state"})
	if res.Error != "" {
		t.Fatal(res.Error)
	}
	for _, c := range res.Capabilities {
		lv.desc[c.ID] = c.Description
	}
	for _, c := range []string{liveCmd, liveSvc, liveFolder} {
		if lv.desc[c] == "" {
			t.Fatalf("No capability %s: %+v", c, res.Capabilities)
		}
	}
	return lv
}

// control sends an operation on control.sock, as the window does
func (lv *liveEnv) control(req request) response { return rawCall(lv.cfg.ControlSocket, req) }

func (lv *liveEnv) systemctl(args ...string) (string, error) {
	out, err := exec.Command(systemctl, append([]string{"--user"}, args...)...).CombinedOutput()
	return string(out), err
}

type liveMachine struct {
	lv           *liveEnv
	m            *model
	ev           *liveEvents
	anon, forged *liveProc
	sessions     map[string]*liveProc
	sessionsMade int
	procs        []*liveProc
	tags         int
}

// newLiveMachine starts an iteration from a clean daemon: nothing stored, the daemon restarted (no grants, gates or
// pending requests left from the last)
func newLiveMachine(t *rapid.T, lv *liveEnv) *liveMachine {
	mc := &liveMachine{lv: lv, sessions: map[string]*liveProc{}}
	t.Cleanup(func() {
		// Questions left are denied, so their callers end
		for _, p := range mc.pendingNow() {
			lv.control(request{Op: "answer", Pending: p.id})
		}
		for _, p := range mc.procs {
			p.kill()
		}
	})
	state := lv.control(request{Op: "state"})
	for _, a := range state.Always {
		if res := lv.control(request{Op: "forget", Capability: a.Capability, Params: a.Params}); res.Error != "" {
			t.Fatalf("Forget %s: %s", a.Capability, res.Error)
		}
	}
	mc.ev = lv.watch()
	t.Cleanup(func() { close(mc.ev.stop) })
	mc.restartDaemon(t)
	mc.m = newModel(time.Now())
	mc.m.shared, mc.m.shareAsked, mc.m.lockOK = true, true, lv.lockSess != ""
	mc.anonymous(t)
	return mc
}

func (mc *liveMachine) pendingNow() []*refPending {
	if mc.m == nil {
		return nil
	}
	return mc.m.pending
}

// restartDaemon restarts the daemon's unit and waits until it answers and its events are followed again
func (mc *liveMachine) restartDaemon(t *rapid.T) {
	mc.ev.mu.Lock()
	conns := mc.ev.conns
	mc.ev.mu.Unlock()
	// The unit's start limit counts restarts too: reset, or the fourth within ten minutes would end it
	if out, err := mc.lv.systemctl("reset-failed", mc.lv.cfg.Unit); err != nil {
		t.Fatalf("Reset the start limit: %v: %s", err, out)
	}
	if out, err := mc.lv.systemctl("restart", mc.lv.cfg.Unit); err != nil {
		t.Fatalf("Restart: %v: %s", err, out)
	}
	mc.waitFor(t, "the daemon's events", func() bool {
		mc.ev.mu.Lock()
		defer mc.ev.mu.Unlock()
		return mc.ev.conns > conns
	})
	// The daemon reads the watch request in a goroutine of its own: a moment for it to subscribe
	time.Sleep(200 * time.Millisecond)
}

func (mc *liveMachine) anonymous(t *rapid.T) *liveProc {
	if mc.anon == nil {
		mc.anon = mc.start(t, "anonymous", mc.lv.bin, "live-agent")
	}
	return mc.anon
}

func (mc *liveMachine) forgedSession(t *rapid.T) *liveProc {
	if mc.forged == nil {
		mc.forged = mc.start(t, "forged", mc.lv.node, "live-anchor", "s1")
	}
	return mc.forged
}

func (mc *liveMachine) session(t *rapid.T) *liveProc {
	mc.sessionsMade++
	id := "s" + strconv.Itoa(mc.sessionsMade)
	p := mc.start(t, id, mc.lv.bin, "live-anchor", id)
	p.sess = id
	mc.sessions[id] = p
	return p
}

func (mc *liveMachine) start(t *rapid.T, name, exe, mode string, args ...string) *liveProc {
	sock := mc.lv.cfg.SandboxGrantDir + "/request.sock"
	p := mc.lv.startProc(t, name, exe, append([]string{mode, sock}, args...)...)
	mc.procs = append(mc.procs, p)
	return p
}

// fatalf fails with the grants named by the order they were made, the broker's random ids left out, so rapid sees the
// same failure as it shrinks
func (mc *liveMachine) fatalf(t *rapid.T, format string, args ...any) {
	t.Helper()
	t.Fatal(hexID.ReplaceAllStringFunc(fmt.Sprintf(format, args...), func(id string) string {
		if g := mc.m.grants[id]; g != nil {
			return "g" + strconv.Itoa(g.seq)
		}
		return "<id>"
	}))
}

func (mc *liveMachine) waitFor(t *rapid.T, what string, cond func() bool) {
	for deadline := time.Now().Add(liveSettle); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			mc.fatalf(t, "Waited for %s", what)
		}
	}
}

func (mc *liveMachine) grantedCount() int {
	mc.ev.mu.Lock()
	defer mc.ev.mu.Unlock()
	return len(mc.ev.granted)
}

func (mc *liveMachine) grantedSince(n int) []string {
	mc.ev.mu.Lock()
	defer mc.ev.mu.Unlock()
	return slices.Clone(mc.ev.granted[n:])
}

func (mc *liveMachine) waitEnded(t *rapid.T, ids ...string) {
	for _, id := range ids {
		mc.waitFor(t, "the end of grant "+id, func() bool {
			mc.ev.mu.Lock()
			defer mc.ev.mu.Unlock()
			return mc.ev.ended[id]
		})
	}
}

func (mc *liveMachine) waitDone(t *rapid.T, p *refPending) response {
	select {
	case res := <-p.done:
		return res
	case <-time.After(liveSettle):
		mc.fatalf(t, "Request %s (%s %s) not answered", p.tag, p.cap, p.params)
		return response{}
	}
}

// Check: after every action the live system matches the reference, waiting a while for what it does on its own (an
// attach replay, a holder dropped). Pending requests near the daemon's two minutes are denied first
func (mc *liveMachine) Check(t *rapid.T) {
	for _, p := range slices.Clone(mc.m.pending) {
		if time.Since(p.asked) > 90*time.Second {
			mc.answer(t, p, request{Op: "answer", Pending: p.id})
		}
	}
	m := mc.m
	for id, r := range m.grants {
		// P1: an always grant only while stored, any other only after an Allow
		if r.lease == "always" && !m.isAlways(r.cap, r.params) || r.lease != "always" && !m.consented[storeKey{r.cap, r.params}] {
			mc.fatalf(t, "Grant %s (%s %s %s) without consent or a stored always grant", id, r.cap, r.params, r.lease)
		}
	}
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
	// P1, P4, release holds: the window's grants are the reference's, with their holders and leases
	got := map[string]*grant{}
	for _, g := range st.Grants {
		got[g.ID] = g
	}
	if !slices.Equal(slices.Sorted(maps.Keys(got)), slices.Sorted(maps.Keys(m.grants))) {
		return fmt.Errorf("Live grants %v, want %v", describeGrants(got, func(g *grant) grant { return *g }), describeRef(m.grants))
	}
	var services, folders []string
	for id, r := range m.grants {
		g := got[id]
		if g.Capability != r.cap || string(g.Params) != r.params || g.Lease != r.lease {
			return fmt.Errorf("Grant %s is %s %s %s, want %s %s %s", id, g.Capability, g.Params, g.Lease, r.cap, r.params, r.lease)
		}
		if d := g.Expires.Sub(r.expires); g.Expires.IsZero() != r.expires.IsZero() || d < -5*time.Second || d > 5*time.Second {
			return fmt.Errorf("Grant %s until %v, want %v", id, g.Expires, r.expires)
		}
		if !slices.Equal(g.Sessions, r.holders) {
			return fmt.Errorf("Grant %s held by %v, want %v", id, g.Sessions, r.holders)
		}
		switch r.cap {
		case liveSvc:
			services = append(services, id)
		case liveFolder:
			folders = append(folders, id)
			// P3: beneath its ceiling
			if g.Source != lv.root && !strings.HasPrefix(g.Source, lv.root+"/") {
				return fmt.Errorf("Folder grant %s of %s", id, g.Source)
			}
		}
	}
	slices.Sort(services)
	slices.Sort(folders)
	// P2, P12, revoke: the window's always grants and the store file are the reference's
	if ks := storeKeys(st.Always); !slices.Equal(ks, m.store) {
		return fmt.Errorf("The window shows always grants %v, want %v", ks, m.store)
	}
	var s storeData
	if data, err := os.ReadFile(lv.cfg.Store); err == nil {
		if err := json.Unmarshal(data, &s); err != nil {
			return fmt.Errorf("Store: %v", err)
		}
	}
	if ks := storeKeys(s.Always); !slices.Equal(ks, m.store) {
		return fmt.Errorf("Store %v, want %v", ks, m.store)
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
	return mc.compareDelivery(t, services, folders)
}

// compareDelivery: P4, P11. Socket units up and their sockets in the grant directory for live service grants only,
// mounts and mountpoints for live folder grants only, in the outer mount namespace and where the app runs
func (mc *liveMachine) compareDelivery(t *rapid.T, services, folders []string) error {
	lv := mc.lv
	prefix := unitPrefix(lv.cfg.Launcher)
	out, err := lv.systemctl("list-units", "--plain", "--no-legend", "--state=active", prefix+"*.socket")
	if err != nil {
		return fmt.Errorf("list-units: %v: %s", err, out)
	}
	var up []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if u, ok := strings.CutPrefix(strings.Fields(l + " x")[0], prefix); ok {
			up = append(up, strings.TrimSuffix(u, ".socket"))
		}
	}
	if slices.Sort(up); !slices.Equal(up, services) {
		return fmt.Errorf("Socket units up %v, want %v", up, services)
	}
	entries, _ := os.ReadDir(lv.cfg.GrantDir)
	var socks, points []string
	for _, e := range entries {
		switch name := e.Name(); {
		case name == "request.sock":
		case strings.HasSuffix(name, ".sock"):
			socks = append(socks, strings.TrimSuffix(name, ".sock"))
		default:
			points = append(points, name)
		}
	}
	if !slices.Equal(socks, services) || !slices.Equal(points, folders) {
		return fmt.Errorf("The grant directory holds sockets %v and mountpoints %v, want %v and %v", socks, points, services,
			folders)
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
