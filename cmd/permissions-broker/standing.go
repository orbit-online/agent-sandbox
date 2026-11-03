package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
)

// Standing grants: what the launcher's Nix config grants for as long as the daemon runs (permissions.grants), of host
// command and host socket capabilities only. The daemon grants them when it starts, and again without asking on a request with
// exactly their parameters, until the user ends one (revoke, or a release that ends it): then it's asked for like any
// other until the daemon starts again. What should always be there is declared and reviewed in Nix, not granted with
// one click in a dialog the sandbox brought up

// A standing grant as the config names it
type standingConfig struct {
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
}

// A standing grant as the window shows it: its live grant if there is one, and whether the user ended it
type standingGrant struct {
	Capability string          `json:"capability"`
	Params     json.RawMessage `json:"params"`
	Summary    string          `json:"summary"`
	Grant      string          `json:"grant,omitempty"`
	Ended      bool            `json:"ended,omitempty"` // under broker.mu
	cap        *capability
}

// checkStanding checks the config's standing grants against the capabilities: one there, not of the attach type, its
// parameters valid, none twice. Their instances and exclusive lock are checked when they're granted
func checkStanding(grants []standingConfig, caps map[string]*capability) ([]*standingGrant, error) {
	var out []*standingGrant
	for _, s := range grants {
		c, ok := caps[s.Capability]
		if !ok {
			return nil, fmt.Errorf("Standing grant of %s: no such capability", s.Capability)
		}
		if c.Type == "attach" {
			return nil, fmt.Errorf("Standing grant of %s: folders get none, bind what should always be there",
				s.Capability)
		}
		params, err := c.validate(s.Params)
		if err != nil {
			return nil, fmt.Errorf("Standing grant of %s: %w", s.Capability, err)
		}
		for _, o := range out {
			if o.cap == c && string(o.Params) == string(params) {
				return nil, fmt.Errorf("Standing grant of %s %s: listed twice", s.Capability, params)
			}
		}
		out = append(out, &standingGrant{Capability: c.id(), Params: params, Summary: c.describe(params), cap: c})
	}
	return out, nil
}

// grantStanding grants the standing grants at start. One whose instance isn't there, or another launcher holds, is
// left out: a request for it once it's there gets it without asking
func (b *broker) grantStanding() {
	for _, s := range b.standing {
		if err := s.cap.inList(s.Params); err != nil {
			slog.Warn("Standing grant", "capability", s.Capability, "err", err)
			continue
		}
		s.cap.covered.Lock()
		if b.matching(s.cap, s.Params) == nil {
			if _, err := b.grant(s.cap, s.Params, s.Summary, "", "standing"); err != nil {
				slog.Warn("Standing grant", "capability", s.Capability, "err", err)
			}
		}
		s.cap.covered.Unlock()
	}
}

// isStanding reports whether c with exactly these parameters is a standing grant the user hasn't ended
func (b *broker) isStanding(c *capability, params json.RawMessage) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.standing {
		if s.cap == c && string(s.Params) == string(params) && !s.Ended {
			return true
		}
	}
	return false
}

// endStanding records that the user ended g, if it's a standing grant: not granted again until the daemon starts again
func (b *broker) endStanding(g *grant) {
	if g.Lease != "standing" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, s := range b.standing {
		if s.cap == g.cap && string(s.Params) == string(g.Params) {
			s.Ended = true
		}
	}
}

// standingViews is the standing grants for the window, each with its live grant
func (b *broker) standingViews() []standingGrant {
	b.mu.Lock()
	defer b.mu.Unlock()
	views := make([]standingGrant, len(b.standing))
	for i, s := range b.standing {
		views[i] = *s
		for _, g := range b.grants {
			if g.cap == s.cap && g.Lease == "standing" && string(g.Params) == string(s.Params) {
				views[i].Grant = g.ID
			}
		}
	}
	return views
}
