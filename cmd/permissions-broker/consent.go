package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/unix"
)

// request asks the user for a grant, or finds one already there that covers it, and delivers it
func (b *broker) request(p peer, req request) (*grant, string, error) {
	c, ok := b.caps[req.Capability]
	if !ok {
		return nil, "", fmt.Errorf("No capability %q: see list", req.Capability)
	}
	params, err := c.validate(req.Params)
	if err != nil {
		return nil, "", err
	}
	reason := strings.Join(strings.FieldsFunc(req.Reason, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if reason == "" {
		return nil, "", errors.New("Say why you need it: the user sees the reason")
	}
	if r := []rune(reason); len(r) > maxReason {
		reason = string(r[:maxReason]) + "…"
	}
	if c.Type == "attach" {
		b.mu.Lock()
		shared := b.shared
		b.mu.Unlock()
		if !shared {
			return nil, "", errors.New("Folder and device grants need the sandbox's grant directory shared, which " +
				"failed when it started: restart the app")
		}
	}
	sess, err := b.sb.sessionOf(p.pid)
	if err != nil {
		return nil, "", err
	}
	keepSess := false
	defer func() {
		if sess != nil && !keepSess {
			unix.Close(sess.pidfd)
		}
	}()
	// The session was read by pid: it's the caller's only if the caller still runs
	if p.gone() {
		return nil, "", errors.New("The caller is gone")
	}
	lease := req.Lease
	if lease == "" {
		lease = "session"
	}
	if err := b.checkLease(lease, sess); err != nil {
		return nil, "", err
	}
	summary := c.describe(params)
	if c.Type == "attach" {
		// Checked before asking: what's outside the ceiling is refused without bothering the user. What's mounted is
		// what's at the path then, checked again
		src, err := b.resolveAttach(c, params)
		if err != nil {
			return nil, "", err
		}
		summary = describeAttach(summary, src)
	} else if err := c.inList(context.Background(), params); err != nil {
		return nil, "", err
	}

	// Already granted: always grants and, for a command, a live grant decide whether to ask again. One request per
	// capability at a time here, so concurrent requests find the grant the first made instead of each making one
	c.covered.Lock()
	g := b.matching(c, params)
	if g != nil {
		// Another session wants it too: it holds it now, and a session lease lasts until the last of them ends
		keepSess = b.hold(g, sess)
	}
	if g == nil && b.isAlways(c, params) {
		if g, err = b.grant(c, params, summary, "always", nil); err != nil {
			c.covered.Unlock()
			return nil, "", err
		}
		b.hold(g, sess)
	}
	c.covered.Unlock()
	if g != nil {
		return b.deliver(c, g)
	}

	unlockGate, err := b.openGate(c.id())
	if err != nil {
		return nil, "", err
	}
	// always is picked in the window only: the notification offers the session, or an hour without one
	asked := lease
	if lease == "always" {
		asked = "PT1H"
		if sess != nil {
			asked = "session"
		}
	}
	answer, err := b.consent(c, params, summary, reason, asked)
	unlockGate(answer.Allow)
	if err != nil {
		return nil, "", fmt.Errorf("Asking the user: %w", err)
	}
	if !answer.Allow {
		b.logDecision(summary, reason, "denied")
		return nil, "", errors.New("The user didn't allow it")
	}
	// Again, whether or not the answer changed the lease: the screen lock may have stopped being watched while the
	// user was asked
	if err := b.checkLease(answer.Lease, sess); err != nil {
		return nil, "", err
	}
	lease = answer.Lease
	if len(answer.Params) > 0 {
		if params, err = c.validate(answer.Params); err != nil {
			return nil, "", err
		}
		summary = c.describe(params)
		if c.Type == "attach" {
			src, err := b.resolveAttach(c, params)
			if err != nil {
				return nil, "", err
			}
			summary = describeAttach(summary, src)
		}
	}
	// What list prints may have changed while the user was asked (a VM shut down): checked at grant time. An attach
	// grant's source is checked again when it's mounted
	if err := c.inList(context.Background(), params); err != nil {
		return nil, "", err
	}
	// A grant of the same may have appeared while the user was asked (a replay, the window narrowing to what's
	// granted): that one serves, rather than a second of the same
	c.covered.Lock()
	if g = b.matching(c, params); g != nil {
		keepSess = b.hold(g, sess)
	} else if g, err = b.grant(c, params, summary, lease, sess); err != nil {
		c.covered.Unlock()
		return nil, "", err
	} else if keepSess = lease == "session"; !keepSess {
		// A session lease took the session's pidfd, which its watch closes, already if the anchor is gone
		b.hold(g, sess)
	}
	c.covered.Unlock()
	b.logDecision(summary, reason, "allowed ("+lease+")")
	if lease == "always" {
		b.addAlways(c, params)
	}
	return b.deliver(c, g)
}

// deliver returns a grant's delivery: for a command what its run command prints, run for the grant's validity. The
// grant must still be live when the plugin runs and when the output is handed out: a request may wait for a plugin
// slot while the grant is revoked or runs out
func (b *broker) deliver(c *capability, g *grant) (*grant, string, error) {
	if c.Type != "command" {
		return g, "", nil
	}
	cred, err := c.runCommand(context.Background(), g.Params, func() (time.Duration, error) {
		if !b.isLive(g) {
			return 0, errors.New("The grant ended: ask again")
		}
		v := b.validity(c, g)
		if v <= 0 {
			return 0, errors.New("The grant just ran out: ask again")
		}
		return v, nil
	})
	if err != nil {
		return nil, "", err
	}
	if !b.isLive(g) {
		return nil, "", errors.New("The grant ended: ask again")
	}
	return g, cred, nil
}

// isLive reports whether g is still granted
func (b *broker) isLive(g *grant) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.grants[g.ID] == g
}

func (b *broker) matching(c *capability, params json.RawMessage) *grant {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, g := range b.grants {
		if g.cap == c && string(g.Params) == string(params) {
			return g
		}
	}
	return nil
}

// openGate allows one open request per capability, and none for a while after maxRefusals in a row. The returned
// function closes it with the user's decision
func (b *broker) openGate(id string) (func(allowed bool), error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	g := b.gates[id]
	if g == nil {
		g = &gate{}
		b.gates[id] = g
	}
	switch {
	case g.asking:
		return nil, errors.New("The user hasn't answered your last request for this yet")
	case b.now().Before(g.blockedUntil):
		return nil, fmt.Errorf("The user turned down %d requests in a row: ask again after %s", maxRefusals,
			g.blockedUntil.Format(time.TimeOnly))
	}
	g.asking = true
	return func(allowed bool) {
		b.mu.Lock()
		defer b.mu.Unlock()
		g.asking = false
		if allowed {
			g.refused = 0
			return
		}
		if g.refused++; g.refused >= maxRefusals {
			g.refused = 0
			g.blockedUntil = b.now().Add(blockFor)
		}
	}, nil
}

type decision struct {
	Allow  bool
	Lease  string
	Params json.RawMessage
}

// consent asks with a notification. Options hands the request to the window, which answers through control.sock
func (b *broker) consent(c *capability, params json.RawMessage, summary, reason, lease string) (decision, error) {
	p := &pending{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Reason: reason, Lease: lease,
		answer: make(chan request, 1)}
	b.mu.Lock()
	b.pendingSeq++
	p.seq = b.pendingSeq
	b.pending[p.ID] = p
	b.mu.Unlock()
	b.event("pending", p.ID)
	defer func() {
		b.mu.Lock()
		delete(b.pending, p.ID)
		b.mu.Unlock()
		b.event("answered", p.ID)
	}()

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	timeout := b.clock.after(askTimeout)
	go func() {
		select {
		case <-timeout:
			cancel(context.DeadlineExceeded)
		case <-ctx.Done():
		}
	}()
	type result struct {
		action string
		err    error
	}
	asked := make(chan result, 1)
	go func() {
		action, err := b.ask(ctx, prompt{Summary: summary, Reason: reason, Lease: lease, Options: len(b.cfg.Window) > 0})
		asked <- result{action, err}
	}()
	select {
	case r := <-asked:
		switch {
		case r.err != nil:
			return decision{}, r.err
		case r.action == "allow":
			return decision{Allow: true, Lease: lease}, nil
		case r.action != "options":
			return decision{}, nil
		}
		_ = b.markOptions(p.ID)
		if err := b.openWindow(); err != nil {
			slog.Warn("Open the window", "err", err)
		}
	case a := <-p.answer:
		// Answered in the window while the notification was up
		cancel(errAnswered)
		return windowDecision(a, lease), nil
	}
	select {
	case a := <-p.answer:
		return windowDecision(a, lease), nil
	case <-b.clock.after(optionsTimeout):
		return decision{}, nil
	}
}

// Why a notification is taken down early: the user answered in the window
var errAnswered = errors.New("answered in the window")

func windowDecision(a request, lease string) decision {
	if a.Lease == "" {
		a.Lease = lease
	}
	return decision{Allow: a.Allow, Lease: a.Lease, Params: a.Params}
}

func (b *broker) markOptions(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	p, ok := b.pending[id]
	if !ok {
		return fmt.Errorf("No pending request %q", id)
	}
	p.Options = true
	return nil
}

func (b *broker) answer(req request) error {
	b.mu.Lock()
	p, ok := b.pending[req.Pending]
	b.mu.Unlock()
	if !ok {
		return fmt.Errorf("No pending request %q", req.Pending)
	}
	select {
	case p.answer <- req:
		return nil
	default:
		return errors.New("Already answered")
	}
}
