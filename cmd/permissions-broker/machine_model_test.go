package main

import (
	"encoding/json"
	"maps"
	"slices"
	"time"
)

// The reference the state machine tests check the broker against: a small model of its grants, leases, gates, standing
// grants, pending requests and the host sockets' addresses, following models/protocol_state.als and
// protocol_events.als

type refGrant struct {
	// params as the model keys them (canonical), vals their values
	id, cap, params, lease string
	vals                   map[string]any
	expires                time.Time
	// Its place in the order grants were made, which draws go by: ids are random
	seq int
}

type refPending struct {
	tag, cap, params string
	vals             map[string]any
	// The lease the notification offers
	lease string
	// A host command's call, not a request
	isCall    bool
	asked     time.Time
	options   bool
	optionsAt time.Time
	call      *askCall
	done      chan response
	// A call's arguments as sent
	args json.RawMessage
	id   string // the broker's
}

type refGate struct {
	asking       bool
	refused      int
	blockedUntil time.Time
}

type storeKey struct{ cap, params string }

type model struct {
	// The capabilities as declared, and the folders' ceiling
	caps    map[string]*oracleCap
	ceiling *ceiling
	now     time.Time
	grants  map[string]*refGrant
	gates   map[string]*refGate
	// The config's standing grants, and those the user ended in this daemon's life
	standing []storeKey
	ended    map[storeKey]bool
	pending  []*refPending
	// The grant directory shared in the sandbox; share asked once
	shared, shareAsked bool
	lockOK             bool
	// The instances there are, and those the other launcher holds
	listed, other map[string]bool
	// The instances whose console the broker listens at: those there were at its start or when a console grant was
	// last made
	listening map[string]bool
	// What the user allowed, by capability and parameters (P1)
	consented map[storeKey]bool
	made      int
	// Grants that ended, whose ids release and revoke may still name
	stale []string
}

func newModel(now time.Time, caps map[string]*oracleCap, ceil *ceiling, standing []standingConfig) *model {
	m := &model{caps: caps, ceiling: ceil, now: now, grants: map[string]*refGrant{}, gates: map[string]*refGate{}, listed: map[string]bool{},
		other: map[string]bool{}, consented: map[storeKey]bool{}, ended: map[storeKey]bool{}, listening: map[string]bool{}}
	for _, s := range standing {
		m.standing = append(m.standing, storeKey{s.Capability, canonical(objectOf(s.Params))})
	}
	return m
}

// isStanding: a standing grant with exactly these parameters, which the user hasn't ended
func (m *model) isStanding(cap, p string) bool {
	k := storeKey{cap, p}
	return slices.Contains(m.standing, k) && !m.ended[k]
}

// endedByUser records a standing grant the user ended (revoke, or release)
func (m *model) endedByUser(g *refGrant) {
	if g.lease == "standing" {
		m.ended[storeKey{g.cap, g.params}] = true
	}
}

func (m *model) gate(c string) *refGate {
	if m.gates[c] == nil {
		m.gates[c] = &refGate{}
	}
	return m.gates[c]
}

// params is the model's key of parameters kv: canonical
func params(kv map[string]any) string { return canonical(kv) }

// decode reads a key's values back
func decode(p string) map[string]any { return objectOf(json.RawMessage(p)) }

func (m *model) matching(cap, p string) *refGrant {
	for _, g := range m.grants {
		if g.cap == cap && g.params == p {
			return g
		}
	}
	return nil
}

// ordered is the live grants in the order they were made
func (m *model) ordered() []*refGrant {
	gs := slices.Collect(maps.Values(m.grants))
	slices.SortFunc(gs, func(a, b *refGrant) int { return a.seq - b.seq })
	return gs
}

// lockFree is the exclusive lock (P13): no grant of the instance here or at the other launcher
func (m *model) lockFree(cap string, vals map[string]any) bool {
	c := m.caps[cap]
	if c == nil || !c.exclusive {
		return true
	}
	name := vals[c.instanceArg]
	for _, g := range m.grants {
		if g.cap == cap && g.vals[c.instanceArg] == name {
			return false
		}
	}
	n, _ := name.(string)
	return !m.other[n]
}

// grant makes a grant live, as the broker's grant: false when the lock is held. A console grant listens at the
// instances' consoles there are
func (m *model) grant(id, cap, p, lease string) (*refGrant, bool) {
	vals := decode(p)
	if !m.lockFree(cap, vals) || lease == "lock" && !m.lockOK {
		return nil, false
	}
	if cap == capConsole {
		m.listen()
	}
	m.made++
	g := &refGrant{id: id, cap: cap, params: p, vals: vals, lease: lease, seq: m.made}
	if d, ok := oracleDuration(lease); ok {
		g.expires = m.now.Add(d)
	}
	m.grants[id] = g
	return g, true
}

// listen: the broker listens at the console of every instance there is, and no other
func (m *model) listen() {
	clear(m.listening)
	for n := range m.listed {
		if m.isInstance(capConsole, map[string]any{"name": n}) {
			m.listening[n] = true
		}
	}
}

// endWhere ends the grants f picks, and returns them
func (m *model) endWhere(f func(*refGrant) bool) []string {
	var ended []string
	for id, g := range m.grants {
		if f(g) {
			delete(m.grants, id)
			m.stale = append(m.stale, id)
			ended = append(ended, id)
		}
	}
	return ended
}

// closeGate is the gate's unlock with the user's decision (P14)
func (m *model) closeGate(cap string, allowed bool) {
	g := m.gate(cap)
	g.asking = false
	if allowed {
		g.refused = 0
		return
	}
	if g.refused++; g.refused >= maxRefusals {
		g.refused = 0
		g.blockedUntil = m.now.Add(blockFor)
	}
}

func (m *model) dropPending(p *refPending) {
	m.pending = slices.DeleteFunc(m.pending, func(q *refPending) bool { return q == p })
}

// validity is what a host command's call is given (P10): its maxValidity, or what's left of a duration lease if less;
// none without either
func (m *model) validity(g *refGrant) time.Duration {
	v := m.caps[g.cap].maxValidity
	if left := g.expires.Sub(m.now); !g.expires.IsZero() && (v == 0 || left < v) {
		v = left
	}
	return v
}
