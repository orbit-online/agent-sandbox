package main

import (
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/duration"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"pgregory.net/rapid"
)

// The live state machine's actions (live_test.go), as machine_requests_test.go, machine_answers_test.go and
// machine_actions_test.go have them, on the real sockets. Not live: notification clicks and Options (the VM's
// notification server is a fake that never answers), time passing (no fake clock: leases are long enough not to run
// out), instances and other launchers (the test capabilities have neither)

// shape is what the live machine's requests are drawn from: the declarations the daemon lists, folders more often
// (more of their requests are refused), beneath the ceiling and around it
func (mc *liveMachine) shape() requestShape {
	return requestShape{caps: mc.lv.caps, ids: []string{liveCmd, liveSock, liveFolder, liveFolder},
		callIDs: []string{liveCmd, liveCmd, liveSock}, hint: mc.hint}
}

func (mc *liveMachine) hint(t *rapid.T, id, arg string) (string, bool) {
	if id != liveFolder || arg != "path" {
		return "", false
	}
	lv := mc.lv
	return encodeString(t, drawPath(t, []string{lv.root, lv.root, lv.root + "/sub", lv.outside, "/srv/mounted"})), true
}

// drawLiveLease draws a lease as drawLease does, but no duration shorter than an hour: nothing runs out here
func drawLiveLease(t *rapid.T) string {
	return rapid.Custom(drawLease).Filter(func(l string) bool {
		d, ok := oracleDuration(l)
		return !ok || d >= time.Hour
	}).Draw(t, "live lease")
}

// draw draws a request or call, with no lease that could run out while the machine runs
func (mc *liveMachine) draw(t *rapid.T, call bool) wire.Request {
	mc.tags++
	req := mc.shape().draw(t, call, fmt.Sprintf("why%d", mc.tags))
	if d, ok := oracleDuration(req.Lease); ok && d < time.Hour {
		req.Lease = drawLiveLease(t)
	}
	return req
}

// Request: one request from inside, of any type and lease
func (mc *liveMachine) Request(t *rapid.T) {
	mc.request(t, mc.anonymous(t), mc.draw(t, false), 1)
}

// Call: the host command's call, under a grant that covers it or asking for one
func (mc *liveMachine) Call(t *rapid.T) {
	mc.request(t, mc.anonymous(t), mc.draw(t, true), 1)
}

// Flood: the same request several times at once from one process (P14: one question)
func (mc *liveMachine) Flood(t *rapid.T) {
	mc.request(t, mc.anonymous(t), mc.draw(t, rapid.Bool().Draw(t, "call")), rapid.IntRange(2, 4).Draw(t, "copies"))
}

// ShareInside: the share asked from where the app runs: refused (S9)
func (mc *liveMachine) ShareInside(t *rapid.T) {
	if res := mc.anonymous(t).do(t, wire.Request{Op: "share"}); !strings.Contains(res.Error, "outer mount namespace") {
		mc.fatalf(t, "Share from inside: %+v", res)
	}
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

func (mc *liveMachine) request(t *rapid.T, who *liveProc, req wire.Request, copies int) {
	call := req.Op == "call"
	mc.clearOfBlocks()
	v := mc.m.judge(call, req.Capability, req.Command, req.Params, req.Arguments, req.Reason, req.Lease)
	about := fmt.Sprintf("%s %q %s %s %q", req.Op, req.Capability, req.Params, req.Arguments, req.Lease)
	known := map[string]bool{}
	for _, p := range mc.m.pending {
		known[p.id] = true
	}
	dones := make([]chan response, copies)
	for i := range dones {
		dones[i] = who.send(req)
	}
	var asked *pending
	if v.kind == "ask" {
		mc.waitFor(t, "the question for "+about, func() bool {
			for _, q := range mc.lv.control(wire.Request{Op: "state"}).Pending {
				if !known[q.ID] {
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
	if v.kind == "ask" {
		want--
	}
	mc.waitFor(t, fmt.Sprintf("%d answers to %s (%s %v)", want, about, v.kind, v.broken), func() bool {
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
		mc.fatalf(t, "%s (%s): every copy answered", about, v.kind)
	}
	switch {
	case v.refused():
		for _, res := range results {
			if !refusedAs(res, v) {
				mc.fatalf(t, "%s: %q (%s), want refused as one of %v", about, res.Error, res.Refused, v.broken)
			}
		}
	case v.kind == "live":
		for _, res := range results {
			mc.delivered(t, v.grant, res, call)
		}
	case v.kind == "standing":
		if results[0].Grant == nil {
			mc.fatalf(t, "Standing grant %s %s not granted: %s", req.Capability, v.params, results[0].Error)
		}
		g, _ := mc.m.grant(results[0].Grant.ID, req.Capability, v.params, "standing")
		for _, res := range results {
			mc.delivered(t, g, res, call)
		}
	case v.kind == "ask":
		for _, res := range results {
			if res.Refused != refAsking {
				mc.fatalf(t, "A second %s served while the first waits: %+v", about, res)
			}
		}
		mc.asked(t, asked, req, v, dones[slices.Index(answered, false)])
	}
}

// delivered checks a request's grant and, for a call, the validity the command was given (P10)
func (mc *liveMachine) delivered(t *rapid.T, g *refGrant, res response, call bool) {
	if res.Error != "" || res.Grant == nil || res.Grant.ID != g.id {
		mc.fatalf(t, "Grant %s %s not delivered: %s %+v", g.cap, g.params, res.Error, res.Grant)
	}
	if !call {
		if want := mc.lv.cfg.SandboxGrantDir + "/" + socketsDir + "/" + liveSock; g.cap == liveSock && res.Grant.Socket != want {
			mc.fatalf(t, "Host socket grant at %q, want %q", res.Grant.Socket, want)
		}
		return
	}
	want := liveMaxValidity
	if !g.expires.IsZero() && time.Until(g.expires) < want {
		want = time.Until(g.expires)
	}
	s, _ := strings.CutPrefix(strings.TrimSpace(res.Output), "issued-PT")
	n, err := strconv.Atoi(strings.TrimSuffix(s, "S"))
	if d := time.Duration(n)*time.Second - want; err != nil || d < -5*time.Second || d > time.Second {
		mc.fatalf(t, "Command run with %q, want about %s", res.Output, duration.Format(want))
	}
}

// asked checks the question as the window shows it (P7: the daemon's summary, the reason folded) and notes it pending
func (mc *liveMachine) asked(t *rapid.T, q *pending, req wire.Request, v verdict, done chan response) {
	tag, _, _ := strings.Cut(req.Reason, ":")
	leaked := strings.HasPrefix(tag, "why") && strings.Contains(q.Summary, tag) ||
		strings.ContainsFunc(q.Summary+q.Bounds, invisible)
	if !strings.HasPrefix(q.Summary, mc.lv.desc[req.Capability]) || leaked || q.Lease != v.lease ||
		q.Capability != req.Capability || canonical(objectOf(q.Params)) != v.params || q.Reason != oracleReason(req.Reason) {
		mc.fatalf(t, "Asked %+v for %+v", q, req)
	}
	mc.m.pending = append(mc.m.pending, &refPending{tag: tag, cap: req.Capability, params: v.params, vals: v.vals,
		lease: v.lease, asked: time.Now(), done: done, id: q.ID, isCall: req.Op == "call", args: req.Arguments})
	mc.m.gate(req.Capability).asking = true
}

// drawGrant picks a live grant's id, one that ended, or garbage
func (mc *liveMachine) drawGrant(t *rapid.T) string {
	var live []string
	for _, g := range mc.m.ordered() {
		live = append(live, g.id)
	}
	return drawGrantID(t, live, mc.m.stale)
}

// Release: release from inside, which ends the grant
func (mc *liveMachine) Release(t *rapid.T) {
	id := mc.drawGrant(t)
	res := mc.anonymous(t).do(t, wire.Request{Op: "release", Grant: id})
	g := mc.m.grants[id]
	if g == nil {
		if res.Refused != refNoGrant {
			mc.fatalf(t, "Released %q, which isn't granted: %+v", id, res)
		}
		return
	}
	if res.Error != "" {
		mc.fatalf(t, "Release %s: %s", id, res.Error)
	}
	mc.m.endedByUser(g)
	mc.waitEnded(t, mc.m.endWhere(func(o *refGrant) bool { return o == g })...)
}

// Connect: the sandbox connects to the echo socket's address. Under a live grant what it sends comes back from the
// host, and the connection stays open (checked after every step); without one it's closed at once
func (mc *liveMachine) Connect(t *rapid.T) {
	mc.tags++
	key := "c" + strconv.Itoa(mc.tags)
	res := mc.anonymous(t).do(t, wire.Request{Op: "connect", Capability: socketsDir + "/" + liveSock, Grant: key,
		Reason: "ping " + key})
	g := mc.m.matching(liveSock, "{}")
	switch {
	case g == nil && !strings.HasPrefix(res.Error, "closed: "):
		mc.fatalf(t, "Connected to the echo socket without a grant: %+v", res)
	case g != nil && (res.Error != "" || res.Output != "ping "+key):
		mc.fatalf(t, "The echo socket under %s: %+v", g.id, res)
	case g != nil:
		mc.conns[key] = g.id
	}
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
	res := mc.lv.control(wire.Request{Op: "revoke", Grant: id})
	g := mc.m.grants[id]
	if g == nil {
		if res.Refused != refNoGrant {
			mc.fatalf(t, "Revoked %q, which isn't granted: %+v", id, res)
		}
		return
	}
	if res.Error != "" {
		mc.fatalf(t, "Revoke %s: %s", id, res.Error)
	}
	mc.m.endedByUser(g)
	mc.waitEnded(t, mc.m.endWhere(func(o *refGrant) bool { return o == g })...)
}

// Restart: systemctl restarts the daemon. Its grants end with it (ExecStopPost, call units bound to it, its
// connections), its questions go unanswered; the new one starts from its standing grants alone, the ended ones too (P12)
func (mc *liveMachine) Restart(t *rapid.T) {
	m := mc.m
	pending := m.pending
	mc.restartDaemon(t)
	for _, p := range pending {
		if res := mc.waitDone(t, p); res.Error == "" {
			mc.fatalf(t, "Request %s %s granted across a restart", p.cap, p.params)
		}
	}
	m.endWhere(func(*refGrant) bool { return true })
	clear(m.gates)
	clear(m.ended)
	m.pending = nil
	mc.started(t)
}
