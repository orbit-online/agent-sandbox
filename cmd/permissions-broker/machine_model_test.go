package main

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"
	"unicode"
)

// The reference the state machine tests check the broker against: a small model of its grants, leases, gates, standing
// grants, pending requests and the host sockets' addresses, following models/protocol_state.als and
// protocol_events.als

type refGrant struct {
	id, cap, params, lease string
	expires                time.Time
	// Its place in the order grants were made, which draws go by: ids are random
	seq int
}

type refPending struct {
	tag, cap, params string
	// The lease the notification offers
	lease string
	// A host command's call, not a request
	isCall    bool
	asked     time.Time
	options   bool
	optionsAt time.Time
	call      *askCall
	done      chan response
	id        string // the broker's
}

type refGate struct {
	asking       bool
	refused      int
	blockedUntil time.Time
}

type storeKey struct{ cap, params string }

type model struct {
	now    time.Time
	grants map[string]*refGrant
	gates  map[string]*refGate
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
}

func newModel(now time.Time, standing []standingConfig) *model {
	m := &model{now: now, grants: map[string]*refGrant{}, gates: map[string]*refGate{}, listed: map[string]bool{},
		other: map[string]bool{}, consented: map[storeKey]bool{}, ended: map[storeKey]bool{}, listening: map[string]bool{}}
	for _, s := range standing {
		m.standing = append(m.standing, storeKey{s.Capability, string(s.Params)})
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

// params builds parameters as validate encodes them: an object with sorted keys
func params(kv map[string]any) string {
	data, _ := json.Marshal(kv)
	return string(data)
}

func decode(p string) map[string]any {
	var m map[string]any
	_ = json.Unmarshal([]byte(p), &m)
	return m
}

// passes is the ceiling (P3): the instance there, the folder beneath the ceiling root, read-write only
// beneath its rw root
func (m *model) passes(cap, p, root string) bool {
	kv := decode(p)
	switch cap {
	case capVM, capConsole:
		name, _ := kv["name"].(string)
		return m.listed[name]
	case capFolder:
		path, _ := kv["path"].(string)
		ro, set := kv["ro"].(bool)
		if path != root+"/x" && path != root+"/w" {
			return false
		}
		return !set || ro || path == root+"/w"
	}
	return true
}

func validLease(lease string) bool {
	if lease == "lock" || lease == "once" {
		return true
	}
	_, err := parseDuration(lease)
	return err == nil
}

// leaseOK is checkLease: a lock lease needs the lock watched
func (m *model) leaseOK(lease string) bool {
	if lease == "lock" {
		return m.lockOK
	}
	return validLease(lease)
}

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
func (m *model) lockFree(cap, p string) bool {
	if cap != capVM {
		return true
	}
	name := decode(p)["name"]
	for _, g := range m.grants {
		if g.cap == capVM && decode(g.params)["name"] == name {
			return false
		}
	}
	n, _ := name.(string)
	return !m.other[n]
}

// grant makes a grant live, as the broker's grant: false when the lock is held. A console grant listens at the
// instances' consoles there are
func (m *model) grant(id, cap, p, lease string) (*refGrant, bool) {
	if !m.lockFree(cap, p) || lease == "lock" && !m.lockOK {
		return nil, false
	}
	if cap == capConsole {
		m.listen()
	}
	m.made++
	g := &refGrant{id: id, cap: cap, params: p, lease: lease, seq: m.made}
	if d, err := parseDuration(lease); err == nil {
		g.expires = m.now.Add(d)
	}
	m.grants[id] = g
	return g, true
}

// listen: the broker listens at the console of every instance there is, and no other
func (m *model) listen() {
	clear(m.listening)
	for n := range m.listed {
		m.listening[n] = true
	}
}

// endWhere ends the grants f picks, and returns them
func (m *model) endWhere(f func(*refGrant) bool) []string {
	var ended []string
	for id, g := range m.grants {
		if f(g) {
			delete(m.grants, id)
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

// validity is what a host command's call is given (P10): its maxValidity, or what's left of a duration lease if less
func (m *model) validity(g *refGrant) time.Duration {
	if !g.expires.IsZero() && g.expires.Sub(m.now) < maxValidity {
		return g.expires.Sub(m.now)
	}
	return maxValidity
}

// cleanReason is the reason as the notification shows it (P7): whitespace and control characters collapsed, at most
// maxReason characters
func cleanReason(r string) string {
	r = strings.Join(strings.FieldsFunc(r, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }), " ")
	if rs := []rune(r); len(rs) > maxReason {
		r = string(rs[:maxReason]) + "…"
	}
	return r
}
