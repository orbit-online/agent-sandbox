package main

import (
	"encoding/json"
	"slices"
	"time"

	"pgregory.net/rapid"
)

// The user's answers in the live state machine (live_test.go), as machine_answers_test.go has them: in the window,
// through control.sock

// WindowAnswer: the user answers a pending request in the window: deny, or allow with any lease, the parameters
// narrowed or not
func (mc *liveMachine) WindowAnswer(t *rapid.T) {
	if len(mc.m.pending) == 0 {
		t.Skip("Nothing pending")
	}
	p := mc.m.pending[rapid.IntRange(0, len(mc.m.pending)-1).Draw(t, "pending")]
	ans := request{Op: "answer", Pending: p.id, Allow: rapid.Bool().Draw(t, "allow")}
	if ans.Allow {
		ans.Lease = rapid.SampledFrom(liveLeases).Draw(t, "lease")
		if rapid.Bool().Draw(t, "narrow") {
			ans.Params = json.RawMessage(mc.drawParams(t, p.cap))
		}
	}
	mc.answer(t, p, ans)
}

func (mc *liveMachine) answer(t *rapid.T, p *refPending, ans request) {
	before := mc.grantedCount()
	if res := mc.lv.control(ans); res.Error != "" {
		mc.fatalf(t, "Answer to %s: %s", p.tag, res.Error)
	}
	res := mc.waitDone(t, p)
	mc.m.now = time.Now()
	if !ans.Allow {
		mc.m.dropPending(p)
		mc.m.closeGate(p.cap, false)
		if res.Error == "" {
			mc.fatalf(t, "Request %s %s granted on a refusal", p.cap, p.params)
		}
		return
	}
	lease, params := ans.Lease, p.params
	if lease == "" {
		lease = p.lease
	}
	if len(ans.Params) > 0 {
		params = string(ans.Params)
	}
	mc.allowed(t, p, lease, params, res, before)
}

// allowed: the user allowed p with a lease and parameters, checked again (P3, P9) before the grant
func (mc *liveMachine) allowed(t *rapid.T, p *refPending, lease, params string, res response, before int) {
	m := mc.m
	m.dropPending(p)
	m.closeGate(p.cap, true)
	if !m.leaseOK(lease, p.sess) || !mc.passes(p.cap, params) {
		if res.Error == "" {
			mc.fatalf(t, "Allowed %s %s %s served: %+v", p.cap, params, lease, res.Grant)
		}
		return
	}
	// A session gone while the user was asked: what it's given is let go of at once (P8)
	_, alive := mc.sessions[p.sess]
	gone := p.sess != "" && !alive
	g := m.matching(p.cap, params)
	if g != nil {
		m.consented[storeKey{p.cap, params}] = true
		m.hold(g, p.sess)
		mc.delivered(t, g, res)
	} else {
		// The event comes on a connection of its own, and may come after the answer
		mc.waitFor(t, "the grant's event", func() bool { return len(mc.grantedSince(before)) > 0 })
		made := mc.grantedSince(before)
		if len(made) != 1 || res.Grant != nil && res.Grant.ID != made[0] {
			mc.fatalf(t, "Allowed %s %s %s made grants %v: %s", p.cap, params, lease, made, res.Error)
		}
		m.consented[storeKey{p.cap, params}] = true
		g, _ = m.grant(made[0], p.cap, params, lease, p.sess)
		if lease != "session" {
			m.hold(g, p.sess)
		}
		if !gone || lease != "session" {
			mc.delivered(t, g, res)
		}
	}
	if gone {
		mc.waitFor(t, "the gone session's hold dropped", func() bool { return !mc.holds(g.id, p.sess) })
		mc.waitEnded(t, m.sessionEnd(p.sess)...)
	}
}

// holds reports whether the window shows sess holding grant id
func (mc *liveMachine) holds(id, sess string) bool {
	for _, g := range mc.lv.control(request{Op: "state"}).Grants {
		if g.ID == id && slices.Contains(g.Sessions, sess) {
			return true
		}
	}
	return false
}
