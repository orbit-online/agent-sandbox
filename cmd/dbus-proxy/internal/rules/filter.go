// Package rules is the proxy's rules: the static rule set read from its JSON config, the rules looked up by name, and
// xdg-dbus-proxy's matching
package rules

import "strings"

// The policy levels of xdg-dbus-proxy, each implying the ones before it
type Policy int

const (
	None Policy = iota
	See
	Talk
	Own
)

// What a filter from a call or broadcast rule applies to; one from a policy applies to both
type Kind uint8

const (
	Call Kind = 1 << iota
	Broadcast
	All = Call | Broadcast
)

// One rule for a name: a policy, and for a call or broadcast rule what a message must match (empty matches anything)
type Filter struct {
	policy      Policy
	types       Kind
	hasPath     bool
	path        string
	pathSubtree bool // The path ended in "/*"; "@/*" leaves path empty and covers every path
	iface       string
	member      string
}

var matchAll = map[Policy]*Filter{
	See:  {policy: See, types: All},
	Talk: {policy: Talk, types: All},
	Own:  {policy: Own, types: All},
}

// A rule's path, interface and member against a message's, as xdg-dbus-proxy's filter_matches
func (f *Filter) Matches(t Kind, path, iface, member string) bool {
	if f.policy < Talk || f.types&t == 0 {
		return false
	}
	if f.hasPath {
		if path == "" {
			return false
		}
		if f.pathSubtree {
			if !strings.HasPrefix(path, f.path) || (len(path) > len(f.path) && path[len(f.path)] != '/') {
				return false
			}
		} else if path != f.path {
			return false
		}
	}
	if f.iface != "" && f.iface != iface {
		return false
	}
	if f.member != "" && f.member != member {
		return false
	}
	return true
}

func AnyMatches(fs []*Filter, t Kind, path, iface, member string) bool {
	for _, f := range fs {
		if f.Matches(t, path, iface, member) {
			return true
		}
	}
	return false
}

// MatchAll is the filter a unique name gets from its own policy p, xdg-dbus-proxy's match_all
func MatchAll(p Policy) *Filter { return matchAll[p] }

// Whether a broadcast from a sender with these filters reaches the client: a policy filter of TALK or OWN, or a
// broadcast rule that matches, as xdg-dbus-proxy 0.1.9 (CVE-2026-93676). A call rule's filter passes none
func BroadcastPasses(fs []*Filter, path, iface, member string) bool {
	return AnyMatches(fs, Broadcast, path, iface, member)
}
