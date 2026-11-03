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
)

// request asks the user for a grant, or finds one already there that covers it
func (b *broker) request(p peer, req request) (*grant, error) {
	c, ok := b.caps[req.Capability]
	if !ok {
		return nil, fmt.Errorf("No capability %q: see list", req.Capability)
	}
	params, err := c.validate(req.Params)
	if err != nil {
		return nil, err
	}
	reason, err := foldReason(req.Reason)
	if err != nil {
		return nil, err
	}
	return b.obtain(p, c, params, reason, req.Lease, nil)
}

// A request or a call that names no lease proposes this one
const defaultLease = "PT1H"

// foldReason folds whitespace and control characters to single spaces and cuts the reason to maxReason
func foldReason(r string) (string, error) {
	reason := strings.Join(strings.FieldsFunc(r, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }), " ")
	if reason == "" {
		return "", errors.New("Say why you need it: the user sees the reason")
	}
	if r := []rune(reason); len(r) > maxReason {
		reason = string(r[:maxReason]) + "…"
	}
	return reason, nil
}

// The call that asks for a grant, which the window shows: its command and free arguments
type askingCall struct {
	Command   string
	Arguments json.RawMessage
}

// obtain finds a grant covering c with params, or asks the user for one. A once lease, which only a call may ask for,
// makes a grant nothing else finds. call is the call asking, nil for a request
func (b *broker) obtain(p peer, c *capability, params json.RawMessage, reason, lease string, call *askingCall) (*grant, error) {
	if lease == "once" && call == nil {
		return nil, errors.New("A once lease is for host command calls: ask for a duration")
	}
	if c.Type == "attach" {
		b.mu.Lock()
		shared := b.shared
		b.mu.Unlock()
		if !shared {
			return nil, errors.New("Folder and device grants need the sandbox's grant directory shared, which " +
				"failed when it started: restart the app")
		}
	}
	if p.gone() {
		return nil, errors.New("The caller is gone")
	}
	if lease == "" {
		lease = defaultLease
	}
	if err := b.checkLease(lease); err != nil {
		return nil, err
	}
	summary := c.describe(params)
	if c.Type == "attach" {
		// Checked before asking: what's outside the ceiling is refused without bothering the user. What's mounted is
		// what's at the path then, checked again
		src, err := b.resolveAttach(c, params)
		if err != nil {
			return nil, err
		}
		summary = describeAttach(summary, src)
	} else if err := c.inList(params); err != nil {
		return nil, err
	}

	// Already granted: a live grant, or a standing grant from the config with exactly these parameters, serves without
	// asking. One request per capability at a time here, so concurrent requests find the grant the first made instead
	// of each making one
	c.covered.Lock()
	g := b.matching(c, params)
	var err error
	if g == nil && b.isStanding(c, params) {
		if g, err = b.grant(c, params, summary, "", "standing"); err != nil {
			c.covered.Unlock()
			return nil, err
		}
	}
	c.covered.Unlock()
	if g != nil {
		return g, nil
	}

	unlockGate, err := b.openGate(c.id())
	if err != nil {
		return nil, err
	}
	answer, err := b.consent(c, params, summary, reason, lease, call)
	unlockGate(answer.Allow)
	if err != nil {
		return nil, fmt.Errorf("Asking the user: %w", err)
	}
	if !answer.Allow {
		b.logDecision(summary, reason, "denied")
		return nil, errors.New("The user didn't allow it")
	}
	// Again, whether or not the answer changed the lease: the screen lock may have stopped being watched while the
	// user was asked
	if answer.Lease == "once" && call == nil {
		return nil, errors.New("A once lease is for host command calls")
	}
	if err := b.checkLease(answer.Lease); err != nil {
		return nil, err
	}
	lease = answer.Lease
	if len(answer.Params) > 0 && c.Type == "command" {
		// The call needs these bounding values; the window may change only the lease
		if p, err := c.validate(answer.Params); err != nil || string(p) != string(params) {
			return nil, errors.New("A host command grant's parameters can't be changed: only its lease")
		}
	} else if len(answer.Params) > 0 {
		if params, err = c.validate(answer.Params); err != nil {
			return nil, err
		}
		summary = c.describe(params)
		if c.Type == "attach" {
			src, err := b.resolveAttach(c, params)
			if err != nil {
				return nil, err
			}
			summary = describeAttach(summary, src)
		}
	}
	// The instances may have changed while the user was asked (a VM shut down): checked at grant time. An attach
	// grant's source is checked again when it's mounted
	if err := c.inList(params); err != nil {
		return nil, err
	}
	// A grant of the same may have appeared while the user was asked (the window narrowing to what's granted): that
	// one serves, rather than a second of the same
	c.covered.Lock()
	if g = b.matching(c, params); g == nil {
		if g, err = b.grant(c, params, summary, reason, lease); err != nil {
			c.covered.Unlock()
			return nil, err
		}
	}
	c.covered.Unlock()
	b.logDecision(summary, reason, "allowed ("+lease+")")
	return g, nil
}

// logDecision records the user's answer for the window, the last maxLog of them
func (b *broker) logDecision(summary, reason, decision string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log = append(b.log, logEntry{Time: b.now(), Summary: summary, Reason: reason, Decision: decision})
	if n := len(b.log); n > maxLog {
		b.log = b.log[n-maxLog:]
	}
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
		// A once grant covers the call it was made for only
		if g.cap == c && string(g.Params) == string(params) && g.Lease != "once" {
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
func (b *broker) consent(c *capability, params json.RawMessage, summary, reason, lease string, call *askingCall) (decision, error) {
	p := &pending{ID: randomID(), Capability: c.id(), Params: params, Summary: summary, Reason: reason, Lease: lease,
		answer: make(chan request, 1)}
	bounds := ""
	if c.Type == "command" {
		p.Scope, bounds = c.scope(), c.bounds(params)
	}
	if call != nil {
		p.Command, p.Arguments = call.Command, call.Arguments
	}
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
		action, err := b.ask(ctx, prompt{Summary: summary, Reason: reason, Lease: lease, Scope: p.Scope, Bounds: bounds,
			Options: len(b.cfg.Window) > 0})
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
