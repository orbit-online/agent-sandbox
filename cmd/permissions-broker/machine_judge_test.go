package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
)

// The oracle's verdict on a request, a call and the user's answer in the window (machine_oracle_test.go has the rules
// on values): refused, and by which rules, or what happens: served by a live grant, granted as a standing grant, or
// asked. A refusal may name any of the rules the request breaks; the docs give no order among them

type verdict struct {
	// The rules broken: the refusal's category must be one of them. None: served or asked
	broken []refusal
	kind   string // live, standing or ask
	grant  *refGrant
	// The parameters as the model keys them, and their values
	params string
	vals   map[string]any
	lease  string
}

func (v verdict) refused() bool { return len(v.broken) > 0 }

// folderSource is a source of the ceiling: a folder, and whether beneath it may be read-write
type folderSource struct {
	path string
	rw   bool
}

// ceiling is the folders' ceiling as the docs have it (Source ceiling and resolving paths): an absolute path, read
// lexically; never at, beneath or above a denied folder; beneath a source, the longest that covers it deciding
// whether read-write is allowed. Mounting then needs a folder there, reached without links
type ceiling struct {
	sources []folderSource
	denied  []string
	// What's there beneath the sources, cleaned: the folders the mount can reach
	folders map[string]bool
}

func beneath(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// allows: whether path passes the ceiling, and whether its mount would then work
func (c *ceiling) allows(path string, ro bool) (passes, mountable bool) {
	if !filepath.IsAbs(path) {
		return false, false
	}
	p := filepath.Clean(path)
	for _, d := range c.denied {
		if beneath(p, d) || beneath(d, p) {
			return false, false
		}
	}
	var best *folderSource
	for i, s := range c.sources {
		if beneath(p, s.path) && (best == nil || len(s.path) > len(best.path)) {
			best = &c.sources[i]
		}
	}
	if best == nil || !ro && !best.rw {
		return false, false
	}
	return true, c.folders[p]
}

// folderOf reads a folder request's values: its path, read-only unless ro is false
func folderValues(vals map[string]any) (string, bool) {
	path, _ := vals["path"].(string)
	ro, set := vals["ro"].(bool)
	return path, !set || ro
}

// judge: a request (call false) or a call of capability id, with what it carries
func (m *model) judge(call bool, id, command string, params, args json.RawMessage, reason, lease string) verdict {
	c := m.caps[id]
	if c == nil || call && c.typ != "command" || call && c.commands[command] == nil {
		return verdict{broken: []refusal{refUnknown}}
	}
	var v verdict
	if paramsOK(c.params, params) {
		v.vals = objectOf(params)
		v.params = canonical(v.vals)
	} else {
		v.broken = append(v.broken, refParams)
	}
	if call && !argumentsOK(c.commands[command], args) {
		v.broken = append(v.broken, refArguments)
	}
	if oracleReason(reason) == "" {
		v.broken = append(v.broken, refReason)
	}
	v.lease = leaseOf(lease)
	if !m.leaseOK(v.lease, call) {
		v.broken = append(v.broken, refLease)
	}
	if v.vals != nil {
		v.broken = append(v.broken, m.reach(id, v.vals)...)
	}
	if v.refused() {
		return v
	}
	if g := m.matching(id, v.params); g != nil {
		v.kind, v.grant = "live", g
		return v
	}
	if m.isStanding(id, v.params) {
		v.kind = "standing"
		return v
	}
	if g := m.gate(id); g.asking {
		v.broken = []refusal{refAsking}
	} else if m.now.Before(g.blockedUntil) {
		v.broken = []refusal{refBlocked}
	} else {
		v.kind = "ask"
	}
	return v
}

// leaseOK: a lease (Leases and triggers): lock while the lock is watched, a positive duration, once for a call only
func (m *model) leaseOK(lease string, call bool) bool {
	l, ok := leaseKind(lease)
	return ok && (l != "lock" || m.lockOK) && (l != "once" || call)
}

// reach: what refuses valid parameters before asking: folders before the share, a folder past the ceiling, no
// instance with these values
func (m *model) reach(id string, vals map[string]any) []refusal {
	c := m.caps[id]
	var broken []refusal
	if c.typ == "attach" {
		if !m.shared {
			broken = append(broken, refUnshared)
		}
		if passes, _ := m.ceiling.allows(folderValues(vals)); !passes {
			broken = append(broken, refCeiling)
		}
	}
	if c.instanceArg != "" && !m.isInstance(id, vals) {
		broken = append(broken, refInstance)
	}
	return broken
}

// isInstance: the instance named is there, and is one the declaration allows. A bounding argument with instances
// must be given. A host socket's instance names its address in the grant directory (Host sockets), a file name of 80
// bytes at most
func (m *model) isInstance(id string, vals map[string]any) bool {
	c := m.caps[id]
	name, ok := vals[c.instanceArg].(string)
	return ok && m.listed[name] && c.params[c.instanceArg].accepts(name, oracleMaxParam) &&
		(c.typ != "socket" || len(name) <= 80)
}

// answered is the oracle's verdict on an Allow in the window with lease and params (none: the request's own), for
// pending p: refused by which rules, or the grant made or found (kind "live" or "grant")
func (m *model) answered(p *refPending, lease string, params json.RawMessage) verdict {
	v := verdict{params: p.params, vals: p.vals, lease: lease}
	if lease == "" {
		v.lease = p.lease
	}
	if !m.leaseOK(v.lease, p.isCall) {
		v.broken = append(v.broken, refLease)
	}
	c := m.caps[p.cap]
	if len(params) > 0 {
		switch {
		case !paramsOK(c.params, params):
			v.broken = append(v.broken, refParams)
		case c.typ == "command" && canonical(objectOf(params)) != p.params:
			// A host command grant's bounding values are what the call needs: only its lease changes
			v.broken = append(v.broken, refParams)
		default:
			v.vals = objectOf(params)
			v.params = canonical(v.vals)
		}
	}
	if !slices.Contains(v.broken, refParams) {
		for _, r := range m.reach(p.cap, v.vals) {
			if r != refUnshared {
				v.broken = append(v.broken, r)
			}
		}
	}
	if v.refused() {
		return v
	}
	if g := m.matching(p.cap, v.params); g != nil {
		v.kind, v.grant = "live", g
		return v
	}
	if !m.lockFree(p.cap, v.vals) {
		v.broken = []refusal{refHeld}
		return v
	}
	if c.typ == "attach" {
		if _, mountable := m.ceiling.allows(folderValues(v.vals)); !mountable {
			v.broken = []refusal{refFailed}
			return v
		}
	}
	v.kind = "grant"
	return v
}

// leaseOf is the lease a request or call proposes
func leaseOf(lease string) string {
	if lease == "" {
		return defaultLease
	}
	return lease
}

// refusedAs checks a refusal's category against the rules a verdict says were broken
func refusedAs(res response, v verdict) bool {
	return res.Error != "" && slices.Contains(v.broken, res.Refused)
}
