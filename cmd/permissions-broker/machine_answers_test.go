package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/notify"
	"github.com/orbit-online/agent-sandbox/cmd/permissions-broker/internal/wire"
	"pgregory.net/rapid"
)

// The user's answers to pending requests: on the notification (notifAllow, refuse, options) and in the window
// (windowAllow, refuse), protocol_events.als; and the notification server the test answers for the user

// drawPending picks a pending request; with notification, one whose notification is still up
func (mc *machine) drawPending(t *rapid.T, notification bool) *refPending {
	var ps []*refPending
	for _, p := range mc.m.pending {
		if !notification || !p.options {
			ps = append(ps, p)
		}
	}
	if len(ps) == 0 {
		t.Skip("Nothing pending")
	}
	p := ps[rapid.IntRange(0, len(ps)-1).Draw(t, "pending")]
	t.Logf("Pending %s: %s %s for %s", p.tag, p.cap, p.params, p.lease)
	return p
}

// NotifyAllow: Allow on the notification, with the lease it offered
func (mc *machine) NotifyAllow(t *rapid.T) {
	p := mc.drawPending(t, true)
	before := mc.grantedCount()
	p.call.answer <- "allow"
	mc.allowed(t, p, "", nil, mc.waitDone(t, p), before)
}

// NotifyDeny: Deny on the notification
func (mc *machine) NotifyDeny(t *rapid.T) {
	p := mc.drawPending(t, true)
	p.call.answer <- "deny"
	mc.refused(t, p, mc.waitDone(t, p))
}

// NotifyOptions: Options on the notification hands the request to the window, which waits 10 minutes at most
func (mc *machine) NotifyOptions(t *rapid.T) {
	p := mc.drawPending(t, true)
	timers := mc.clk.asked(wire.OptionsTimeout)
	p.call.answer <- "options"
	// Its timer starts now
	for deadline := time.Now().Add(settle); mc.clk.asked(wire.OptionsTimeout) == timers; {
		if time.Now().After(deadline) {
			mc.fatalf(t, "Options on %s: the window's wait didn't start", p.tag)
		}
		time.Sleep(time.Millisecond)
	}
	p.options, p.optionsAt = true, mc.m.now
}

// WindowAnswer: an answer in the window, while the notification is up or after Options: deny, or allow with any lease,
// the parameters narrowed or not (drawn as a request's are: the window is the host's, but its answer is checked again)
func (mc *machine) WindowAnswer(t *rapid.T) {
	p := mc.drawPending(t, false)
	ans := wire.Request{Op: "answer", Pending: p.id, Allow: rapid.Bool().Draw(t, "allow")}
	if ans.Allow {
		ans.Lease = drawLease(t)
		if rapid.Bool().Draw(t, "narrow") {
			h := func(t *rapid.T, arg string) (string, bool) { return mc.hint(t, p.cap, arg) }
			ans.Params = drawObject(t, mc.m.caps[p.cap].params, oracleMaxParam, false, often(t, 7, "valid"), h)
		}
	}
	before := mc.grantedCount()
	if res := mc.b.handleControl(nil, mc.w.host, ans); res.Error != "" {
		mc.fatalf(t, "Answer to %s: %s", p.tag, res.Error)
	}
	res := mc.waitDone(t, p)
	if !ans.Allow {
		mc.refused(t, p, res)
		return
	}
	mc.allowed(t, p, ans.Lease, ans.Params, res, before)
}

// refused: a request denied, or not answered in time. The third in a row blocks the capability (P14)
func (mc *machine) refused(t *rapid.T, p *refPending, res response) {
	mc.m.dropPending(p)
	mc.m.closeGate(p.cap, false)
	if res.Refused != refDenied {
		mc.fatalf(t, "Request %s %s on a refusal: %+v", p.cap, p.params, res)
	}
}

// allowed: the user allowed p with a lease and parameters (none: the request's), checked again (P3, P9) before the
// grant. before is how many grants were made before the answer
func (mc *machine) allowed(t *rapid.T, p *refPending, lease string, params json.RawMessage, res response, before int) {
	m := mc.m
	v := m.answered(p, lease, params)
	m.dropPending(p)
	m.closeGate(p.cap, true)
	made := mc.grantedSince(before)
	if v.refused() {
		if !refusedAs(res, v) || len(made) > 0 {
			mc.fatalf(t, "Allowed %s %s %q %s: %q (%s), grants %v; want refused as one of %v", p.cap, p.params, lease,
				params, res.Error, res.Refused, made, v.broken)
		}
		return
	}
	m.consented[storeKey{p.cap, v.params}] = true
	if v.kind == "live" {
		mc.delivered(t, v.grant, res, p.isCall, p.args)
		return
	}
	if len(made) != 1 {
		mc.fatalf(t, "Allowed %s %s %s made grants %v: %s", p.cap, v.params, v.lease, made, res.Error)
	}
	g, _ := m.grant(made[0], p.cap, v.params, v.lease)
	mc.delivered(t, g, res, p.isCall, p.args)
	if v.lease == "once" {
		// Made for the call, ended once it's answered
		mc.waitEnded(t, m.endWhere(func(o *refGrant) bool { return o == g })...)
	}
}

// The user's notification server: each question waits for the test's answer, or for the broker to take it down
type askCall struct {
	p      notify.Prompt
	answer chan string
}

type notifier struct{ calls chan *askCall }

func (n *notifier) ask(ctx context.Context, p notify.Prompt) (string, error) {
	c := &askCall{p: p, answer: make(chan string, 1)}
	select {
	case n.calls <- c:
	case <-ctx.Done():
		return "", nil
	}
	select {
	case a := <-c.answer:
		return a, nil
	case <-ctx.Done():
		// As awaitAction: taken down, or no answer in time
		return "", nil
	}
}
