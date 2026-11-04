package main

import (
	"encoding/json"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
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
	ans := wire.Request{Op: "answer", Pending: p.id, Allow: rapid.Bool().Draw(t, "allow")}
	if ans.Allow {
		ans.Lease = drawLiveLease(t)
		if rapid.Bool().Draw(t, "narrow") {
			h := func(t *rapid.T, arg string) (string, bool) { return mc.hint(t, p.cap, arg) }
			ans.Params = drawObject(t, mc.m.caps[p.cap].params, oracleMaxParam, false, often(t, 7, "valid"), h)
		}
	}
	mc.answer(t, p, ans)
}

func (mc *liveMachine) answer(t *rapid.T, p *refPending, ans wire.Request) {
	before := mc.grantedCount()
	if res := mc.lv.control(ans); res.Error != "" {
		mc.fatalf(t, "Answer to %s: %s", p.tag, res.Error)
	}
	res := mc.waitDone(t, p)
	mc.m.now = time.Now()
	if !ans.Allow {
		mc.m.dropPending(p)
		mc.m.closeGate(p.cap, false)
		if res.Refused != refDenied {
			mc.fatalf(t, "Request %s %s on a refusal: %+v", p.cap, p.params, res)
		}
		return
	}
	mc.allowed(t, p, ans.Lease, ans.Params, res, before)
}

// allowed: the user allowed p with a lease and parameters (none: the request's), checked again (P3, P9) before the
// grant
func (mc *liveMachine) allowed(t *rapid.T, p *refPending, lease string, params json.RawMessage, res response, before int) {
	m := mc.m
	v := m.answered(p, lease, params)
	m.dropPending(p)
	m.closeGate(p.cap, true)
	if v.refused() {
		if !refusedAs(res, v) {
			mc.fatalf(t, "Allowed %s %s %q %s: %q (%s), want refused as one of %v", p.cap, p.params, lease, params,
				res.Error, res.Refused, v.broken)
		}
		return
	}
	m.consented[storeKey{p.cap, v.params}] = true
	if v.kind == "live" {
		mc.delivered(t, v.grant, res, p.isCall)
		return
	}
	// The event comes on a connection of its own, and may come after the answer
	mc.waitFor(t, "the grant's event", func() bool { return len(mc.grantedSince(before)) > 0 })
	made := mc.grantedSince(before)
	if len(made) != 1 || res.Grant != nil && res.Grant.ID != made[0] {
		mc.fatalf(t, "Allowed %s %s %s made grants %v: %s", p.cap, v.params, v.lease, made, res.Error)
	}
	g, _ := m.grant(made[0], p.cap, v.params, v.lease)
	mc.delivered(t, g, res, p.isCall)
	if v.lease == "once" {
		// Made for the call, ended once it's answered
		mc.waitEnded(t, m.endWhere(func(o *refGrant) bool { return o == g })...)
	}
}
