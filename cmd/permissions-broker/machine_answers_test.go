package main

import (
	"context"
	"encoding/json"
	"time"

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
	t.Logf("Pending %s: %s %s for %s, %s", p.tag, p.cap, p.params, p.lease, p.sess)
	return p
}

// NotifyAllow: Allow on the notification, with the lease it offered
func (mc *machine) NotifyAllow(t *rapid.T) {
	p := mc.drawPending(t, true)
	before := mc.grantedCount()
	p.call.answer <- "allow"
	mc.allowed(t, p, p.lease, p.params, mc.waitDone(t, p), before)
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
	timers := mc.clk.asked(optionsTimeout)
	p.call.answer <- "options"
	// Its timer starts now
	for deadline := time.Now().Add(settle); mc.clk.asked(optionsTimeout) == timers; {
		if time.Now().After(deadline) {
			mc.fatalf(t, "Options on %s: the window's wait didn't start", p.tag)
		}
		time.Sleep(time.Millisecond)
	}
	p.options, p.optionsAt = true, mc.m.now
}

// WindowAnswer: an answer in the window, while the notification is up or after Options: deny, or allow with any lease,
// the parameters narrowed or not
func (mc *machine) WindowAnswer(t *rapid.T) {
	p := mc.drawPending(t, false)
	ans := request{Op: "answer", Pending: p.id, Allow: rapid.Bool().Draw(t, "allow")}
	if ans.Allow {
		ans.Lease = rapid.SampledFrom(leases).Draw(t, "lease")
		if rapid.Bool().Draw(t, "narrow") {
			ans.Params = json.RawMessage(mc.drawParams(t, p.cap))
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
	lease, params := ans.Lease, p.params
	if lease == "" {
		lease = p.lease
	}
	if len(ans.Params) > 0 {
		params = string(ans.Params)
	}
	mc.allowed(t, p, lease, params, res, before)
}

// refused: a request denied, or not answered in time. The third in a row blocks the capability (P14)
func (mc *machine) refused(t *rapid.T, p *refPending, res response) {
	mc.m.dropPending(p)
	mc.m.closeGate(p.cap, false)
	if res.Error == "" {
		mc.fatalf(t, "Request %s %s granted on a refusal", p.cap, p.params)
	}
}

// allowed: the user allowed p with a lease and parameters, checked again (P3, P9) before the grant. before is how many
// grants were made before the answer
func (mc *machine) allowed(t *rapid.T, p *refPending, lease, params string, res response, before int) {
	m := mc.m
	m.dropPending(p)
	m.closeGate(p.cap, true)
	refuse := func(why string) {
		if res.Error == "" {
			mc.fatalf(t, "Allowed %s %s %s served (%s): %+v", p.cap, params, lease, why, res.Grant)
		}
	}
	switch {
	case !m.leaseOK(lease, p.sess):
		refuse("no such lease now")
		return
	case !m.passes(p.cap, params, mc.w.root):
		refuse("above the ceiling")
		return
	}
	// A session gone while the user was asked: what it's given is let go of at once (P8)
	_, alive := mc.w.sessions[p.sess]
	gone := p.sess != "" && !alive
	g := m.matching(p.cap, params)
	if g != nil {
		m.consented[storeKey{p.cap, params}] = true
		m.hold(g, p.sess)
		mc.delivered(t, g, res)
	} else {
		made := mc.grantedSince(before)
		if !m.lockFree(p.cap, params) {
			refuse("its instance is granted")
			if len(made) > 0 {
				mc.fatalf(t, "Allowed %s %s granted with its instance granted", p.cap, params)
			}
			return
		}
		if len(made) != 1 {
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
		mc.waitFor(t, "the gone session's hold dropped", func() bool {
			mc.b.mu.Lock()
			defer mc.b.mu.Unlock()
			return mc.b.grants[g.id] == nil || mc.b.grants[g.id].sessions[p.sess] == nil
		})
		mc.waitEnded(t, m.sessionEnd(p.sess)...)
	}
}

// The user's notification server: each question waits for the test's answer, or for the broker to take it down
type askCall struct {
	p      prompt
	answer chan string
}

type notifier struct{ calls chan *askCall }

func (n *notifier) ask(ctx context.Context, p prompt) (string, error) {
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
