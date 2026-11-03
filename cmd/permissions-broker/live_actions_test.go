package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"pgregory.net/rapid"
)

// The live state machine's actions (live_test.go), as machine_requests_test.go, machine_answers_test.go and
// machine_actions_test.go have them, on the real sockets. Not live: notification clicks and Options (the VM's
// notification server is a fake that never answers), time passing (no fake clock: leases are long enough not to run
// out), list and other launchers (the test plugins have neither)

// Folders more often: more of their requests are refused
var liveCaps = []string{liveCmd, liveSvc, liveFolder, liveFolder}

var liveLeases = []string{"", "session", "lock", "PT1H", "standing"}

// A call's: once only there
var liveCallLeases = []string{"", "once", "once", "PT1H"}

func (mc *liveMachine) drawParams(t *rapid.T, c string) string {
	kv := map[string]any{}
	if c == liveFolder {
		kv["path"] = rapid.SampledFrom([]string{mc.lv.root, mc.lv.root, mc.lv.root, mc.lv.root + "/sub", mc.lv.outside}).Draw(t, "path")
		switch rapid.SampledFrom([]int{0, 0, 0, 1, 2}).Draw(t, "ro") {
		case 1:
			kv["ro"] = true
		case 2:
			kv["ro"] = false
		}
	}
	return params(kv)
}

// passes is the ceiling (P3): the root or beneath it, read-only
func (mc *liveMachine) passes(c, p string) bool {
	if c != liveFolder {
		return true
	}
	kv := decode(p)
	path, _ := kv["path"].(string)
	ro, set := kv["ro"].(bool)
	return (path == mc.lv.root || path == mc.lv.root+"/sub") && (!set || ro)
}

func (mc *liveMachine) drawCaller(t *rapid.T) *liveProc {
	choices := []string{"anonymous", "forged"}
	if len(mc.sessions) < 3 {
		choices = append(choices, "new")
	}
	// The sessions there are, more often: most leases need one
	for _, s := range slices.Sorted(maps.Keys(mc.sessions)) {
		choices = append(choices, s, s, s, s)
	}
	switch who := rapid.SampledFrom(choices).Draw(t, "caller"); who {
	case "anonymous":
		return mc.anonymous(t)
	case "forged":
		return mc.forgedSession(t)
	case "new":
		return mc.session(t)
	default:
		return mc.sessions[who]
	}
}

// Request: one request from inside, of any type and lease
func (mc *liveMachine) Request(t *rapid.T) {
	c := rapid.SampledFrom(liveCaps).Draw(t, "capability")
	p := mc.drawParams(t, c)
	lease := rapid.SampledFrom(liveLeases).Draw(t, "lease")
	mc.request(t, mc.drawCaller(t), c, p, lease, 1, false)
}

// Call: the host command's call, under a grant that covers it or asking for one
func (mc *liveMachine) Call(t *rapid.T) {
	lease := rapid.SampledFrom(liveCallLeases).Draw(t, "lease")
	mc.request(t, mc.drawCaller(t), liveCmd, "{}", lease, 1, true)
}

// Flood: the same request several times at once from one process (P14: one question)
func (mc *liveMachine) Flood(t *rapid.T) {
	c := rapid.SampledFrom(liveCaps).Draw(t, "capability")
	p := mc.drawParams(t, c)
	lease := rapid.SampledFrom(liveLeases).Draw(t, "lease")
	mc.request(t, mc.anonymous(t), c, p, lease, rapid.IntRange(2, 4).Draw(t, "copies"), false)
}

// Crafted: requests that never reach the user (P3, P7)
func (mc *liveMachine) Crafted(t *rapid.T) {
	r := rapid.SampledFrom([]request{
		{Capability: "test/other", Reason: "x"},
		{Capability: liveCmd, Params: json.RawMessage(`{"unit":"evil"}`), Reason: "x"},
		{Capability: liveFolder, Params: json.RawMessage(`{"path":5}`), Reason: "x"},
		{Capability: liveFolder, Params: json.RawMessage(`{"path":"` + mc.lv.root + `\nAllowed"}`), Reason: "x"},
		{Capability: liveCmd, Reason: " \n\x07\t "},
		{Capability: liveCmd, Reason: "x", Lease: "forever"},
		{Capability: liveCmd, Reason: "x", Lease: "once"},
		{Op: "call", Capability: liveCmd, Command: "other", Reason: "x"},
		{Op: "call", Capability: liveCmd, Command: "thing", Arguments: json.RawMessage(`{"x":1}`), Reason: "x"},
	}).Draw(t, "crafted")
	if r.Op == "" {
		r.Op = "request"
	}
	if res := mc.anonymous(t).do(t, r); res.Error == "" {
		mc.fatalf(t, "Crafted request %+v served: %+v", r, res.Grant)
	}
}

// ShareInside: the share asked from where the app runs: refused (S9)
func (mc *liveMachine) ShareInside(t *rapid.T) {
	if res := mc.anonymous(t).do(t, request{Op: "share"}); !strings.Contains(res.Error, "outer mount namespace") {
		mc.fatalf(t, "Share from inside: %+v", res)
	}
}

func (mc *liveMachine) predict(c, p, lease, sess string, call bool) (string, *refGrant) {
	m := mc.m
	lease = defaultLease(lease, call)
	if !m.leaseOK(lease, sess) || !mc.passes(c, p) || lease == "once" && !call {
		return "refused", nil
	}
	if g := m.matching(c, p); g != nil {
		return "live", g
	}
	if m.isStanding(c, p) {
		return "standing", nil
	}
	if g := m.gate(c); g.asking || m.now.Before(g.blockedUntil) {
		return "refused", nil
	}
	return "ask", nil
}

// clearOfBlocks waits until no capability's refusal block ends within two seconds, the time between the daemon's
// clock and ours
func (mc *liveMachine) clearOfBlocks() {
	for _, g := range mc.m.gates {
		if d := time.Until(g.blockedUntil); d > -2*time.Second && d < 2*time.Second {
			time.Sleep(d + 2*time.Second)
		}
	}
	mc.m.now = time.Now()
}

func (mc *liveMachine) request(t *rapid.T, who *liveProc, c, p, lease string, copies int, call bool) {
	mc.tags++
	req := request{Op: "request", Capability: c, Params: json.RawMessage(p), Lease: lease,
		Reason: fmt.Sprintf("why%d: to <b>read</b>\n\tthe notes", mc.tags)}
	if call {
		req.Op, req.Command, req.Arguments = "call", "thing", json.RawMessage(`{}`)
	}
	mc.clearOfBlocks()
	kind, live := mc.predict(c, p, lease, who.sess, call)
	dones := make([]chan response, copies)
	for i := range dones {
		dones[i] = who.send(req)
	}
	var asked *pending
	if kind == "ask" {
		mc.waitFor(t, "the question for "+c, func() bool {
			for _, q := range mc.lv.control(request{Op: "state"}).Pending {
				if q.Reason == cleanReason(req.Reason) {
					asked = q
				}
			}
			return asked != nil
		})
	}
	// The answers there are: all of them, or all but the one waiting for the user
	var results []response
	answered := make([]bool, copies)
	want := copies
	if kind == "ask" {
		want--
	}
	mc.waitFor(t, fmt.Sprintf("%d answers to %s %s %s (%s)", want, c, p, lease, kind), func() bool {
		for i, d := range dones {
			select {
			case res := <-d:
				answered[i] = true
				results = append(results, res)
			default:
			}
		}
		return len(results) >= want
	})
	if len(results) > want {
		mc.fatalf(t, "Request %s %s %s (%s): every copy answered", c, p, lease, kind)
	}
	switch kind {
	case "refused":
		for _, res := range results {
			if res.Error == "" {
				mc.fatalf(t, "Request %s %s %s served: %+v", c, p, lease, res.Grant)
			}
		}
	case "live":
		for _, res := range results {
			mc.m.hold(live, who.sess)
			mc.delivered(t, live, res, call)
		}
	case "standing":
		if results[0].Grant == nil {
			mc.fatalf(t, "Standing grant %s %s not granted: %s", c, p, results[0].Error)
		}
		g, _ := mc.m.grant(results[0].Grant.ID, c, p, "standing", "")
		for _, res := range results {
			mc.m.hold(g, who.sess)
			mc.delivered(t, g, res, call)
		}
	case "ask":
		for _, res := range results {
			if res.Error == "" {
				mc.fatalf(t, "A second request of %s %s served while the first waits", c, p)
			}
		}
		mc.asked(t, asked, req, who.sess, dones[slices.Index(answered, false)])
	}
}

// delivered checks a request's grant and, for a call, the validity the command was given (P10)
func (mc *liveMachine) delivered(t *rapid.T, g *refGrant, res response, call bool) {
	if res.Error != "" || res.Grant == nil || res.Grant.ID != g.id {
		mc.fatalf(t, "Grant %s %s not delivered: %s %+v", g.cap, g.params, res.Error, res.Grant)
	}
	if !call {
		return
	}
	want := liveMaxValidity
	if !g.expires.IsZero() && time.Until(g.expires) < want {
		want = time.Until(g.expires)
	}
	s, _ := strings.CutPrefix(strings.TrimSpace(res.Output), "issued-PT")
	n, err := strconv.Atoi(strings.TrimSuffix(s, "S"))
	if d := time.Duration(n)*time.Second - want; err != nil || d < -5*time.Second || d > time.Second {
		mc.fatalf(t, "Command run with %q, want about %s", res.Output, formatDuration(want))
	}
}

// asked checks the question as the window shows it (P7: the daemon's summary, the reason cleaned) and notes it pending
func (mc *liveMachine) asked(t *rapid.T, q *pending, req request, sess string, done chan response) {
	lease := defaultLease(req.Lease, req.Op == "call")
	tag, _, _ := strings.Cut(req.Reason, " ")
	if !strings.HasPrefix(q.Summary, mc.lv.desc[req.Capability]) || strings.Contains(q.Summary, tag) ||
		q.Lease != lease || q.Capability != req.Capability || string(q.Params) != string(req.Params) {
		mc.fatalf(t, "Asked %+v for %+v", q, req)
	}
	mc.m.pending = append(mc.m.pending, &refPending{tag: tag, cap: req.Capability, params: string(req.Params),
		lease: lease, sess: sess, asked: time.Now(), done: done, id: q.ID, isCall: req.Op == "call"})
	mc.m.gate(req.Capability).asking = true
}

func (mc *liveMachine) drawGrant(t *rapid.T) string {
	ids := []string{"0123456789abcdef"}
	for _, g := range mc.m.ordered() {
		ids = append(ids, g.id)
	}
	return ids[rapid.IntRange(0, len(ids)-1).Draw(t, "grant")]
}

// Release: release from inside; it drops only the caller's hold, and the grant ends once nobody holds it
func (mc *liveMachine) Release(t *rapid.T) {
	id := mc.drawGrant(t)
	who := mc.drawCaller(t)
	res := who.do(t, request{Op: "release", Grant: id})
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
		mc.m.endedByUser(g)
		mc.waitEnded(t, id)
	}
}

// NewSession: a Claude Code session starts in the sandbox
func (mc *liveMachine) NewSession(t *rapid.T) {
	if len(mc.sessions) >= 3 {
		t.Skip("Sessions enough")
	}
	mc.session(t)
}

// EndSession: a session's anchor exits, dropping its holds; the session leases it was the last holder of end (P8)
func (mc *liveMachine) EndSession(t *rapid.T) {
	if len(mc.sessions) == 0 {
		t.Skip("No session")
	}
	id := rapid.SampledFrom(slices.Sorted(maps.Keys(mc.sessions))).Draw(t, "session")
	mc.sessions[id].end()
	delete(mc.sessions, id)
	mc.waitEnded(t, mc.m.sessionEnd(id)...)
	mc.waitFor(t, "the session's holds dropped", func() bool {
		for _, g := range mc.lv.control(request{Op: "state"}).Grants {
			if slices.Contains(g.Sessions, id) {
				return false
			}
		}
		return true
	})
}

// Lock: logind locks alice's graphical session; lock leases end (P9)
func (mc *liveMachine) Lock(t *rapid.T) {
	if out, err := exec.Command("loginctl", "lock-session", mc.lv.lockSess).CombinedOutput(); err != nil {
		mc.fatalf(t, "Lock: %v: %s", err, out)
	}
	mc.waitEnded(t, mc.m.endWhere(func(g *refGrant) bool { return g.lease == "lock" })...)
}

// Revoke: the user revokes a grant in the window; a standing grant stays ended until a restart
func (mc *liveMachine) Revoke(t *rapid.T) {
	id := mc.drawGrant(t)
	res := mc.lv.control(request{Op: "revoke", Grant: id})
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

// Restart: systemctl restarts the daemon. Its grants end with it (ExecStopPost, units bound to it), its questions go
// unanswered; the new one starts from its standing grants alone, the ended ones too (P12)
func (mc *liveMachine) Restart(t *rapid.T) {
	m := mc.m
	pending := m.pending
	mc.restartDaemon(t)
	for _, p := range pending {
		if res := mc.waitDone(t, p); res.Error == "" {
			mc.fatalf(t, "Request %s %s granted across a restart", p.cap, p.params)
		}
	}
	clear(m.grants)
	clear(m.gates)
	clear(m.ended)
	m.pending = nil
	mc.started(t)
}
