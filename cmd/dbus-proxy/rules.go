package main

import (
	"fmt"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The policy levels of xdg-dbus-proxy, each implying the ones before it
type policy int

const (
	policyNone policy = iota
	policySee
	policyTalk
	policyOwn
)

// What a filter from --call or --broadcast applies to; one from --see, --talk or --own applies to both
type filterType uint8

const (
	filterCall filterType = 1 << iota
	filterBroadcast
	filterAll = filterCall | filterBroadcast
)

// One rule for a name: a policy, and for --call and --broadcast what a message must match (empty matches anything)
type filter struct {
	policy      policy
	subtree     bool // The name ended in ".*": it covers the names below it too
	types       filterType
	hasPath     bool
	path        string
	pathSubtree bool // The path ended in "/*"; "@/*" leaves path empty and covers every path
	iface       string
	member      string
}

// The filters a unique name gets from its own policy, xdg-dbus-proxy's match_all
var matchAll = map[policy]*filter{
	policySee:  {policy: policySee, types: filterAll},
	policyTalk: {policy: policyTalk, types: filterAll},
	policyOwn:  {policy: policyOwn, types: filterAll},
}

// A rule's path, interface and member against a message's, as xdg-dbus-proxy's filter_matches
func (f *filter) matches(t filterType, path, iface, member string) bool {
	if f.policy < policyTalk || f.types&t == 0 {
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

func anyMatches(fs []*filter, t filterType, path, iface, member string) bool {
	for _, f := range fs {
		if f.matches(t, path, iface, member) {
			return true
		}
	}
	return false
}

// The filters of one source by name: the command line now, a grant's rule set once the broker sends them
type RuleSet struct {
	byName map[string][]*filter
}

func NewRuleSet() *RuleSet {
	return &RuleSet{byName: map[string][]*filter{}}
}

// Splits "org.foo.*" into the name and whether it covers the names below it, and checks the name
func parseName(arg string) (string, bool, error) {
	name, subtree := strings.CutSuffix(arg, ".*")
	if strings.HasPrefix(name, ":") || !isBusName(name) {
		return "", false, fmt.Errorf("Not a valid well-known bus name: %q", arg)
	}
	return name, subtree, nil
}

// A well-known bus name as the D-Bus specification has it: two or more dot-separated elements of [A-Za-z0-9_-], none
// empty or starting with a digit, at most 255 bytes
func isBusName(name string) bool {
	if len(name) == 0 || len(name) > 255 {
		return false
	}
	elems := strings.Split(name, ".")
	if len(elems) < 2 {
		return false
	}
	for _, e := range elems {
		if e == "" || (e[0] >= '0' && e[0] <= '9') {
			return false
		}
		for _, c := range e {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// --see, --talk or --own for NAME
func (rs *RuleSet) AddPolicy(arg string, p policy) error {
	name, subtree, err := parseName(arg)
	if err != nil {
		return err
	}
	rs.byName[name] = append(rs.byName[name], &filter{policy: p, subtree: subtree, types: filterAll})
	return nil
}

// --call or --broadcast with NAME=RULE. A rule is [METHOD][@PATH], parsed as xdg-dbus-proxy's filter_new_from_rule
// does: METHOD "*" matches anything, otherwise it splits at its last dot into interface and member, a member of "*"
// matching any (so "org.foo.Bar" is member Bar of interface org.foo, as there); PATH may end in "/*" for a subtree
func (rs *RuleSet) AddRule(arg string, t filterType) error {
	nameArg, rule, ok := strings.Cut(arg, "=")
	if !ok {
		return fmt.Errorf("Not a NAME=RULE: %q", arg)
	}
	name, subtree, err := parseName(nameArg)
	if err != nil {
		return err
	}
	f := &filter{policy: policyTalk, subtree: subtree, types: t}
	method := rule
	if at := strings.IndexByte(rule, '@'); at >= 0 {
		method = rule[:at]
		if path := rule[at+1:]; path != "" {
			f.hasPath = true
			f.path, f.pathSubtree = strings.CutSuffix(path, "/*")
			if !(f.pathSubtree && f.path == "") && !dbus.ObjectPath(f.path).IsValid() {
				return fmt.Errorf("Not a valid object path in rule %q", arg)
			}
		}
	}
	if method != "" && method[0] != '*' {
		f.iface = method
		if dot := strings.LastIndexByte(method, '.'); dot >= 0 {
			f.iface = method[:dot]
			if m := method[dot+1:]; m != "*" {
				f.member = m
			}
		}
	}
	rs.byName[name] = append(rs.byName[name], f)
	return nil
}

// The rule sets a proxy applies, looked up together. Static for now: the command line's and the bus's own
type Rules struct {
	sets []*RuleSet
}

// Every client may talk to the bus itself
func NewRules(sets ...*RuleSet) *Rules {
	bus := NewRuleSet()
	bus.byName[busName] = []*filter{{policy: policyTalk, types: filterAll}}
	return &Rules{sets: append([]*RuleSet{bus}, sets...)}
}

// The highest policy and the filters that apply to a well-known name: the name's own, then those of its dot-prefixes
// that cover the names below them, as xdg-dbus-proxy's flatpak_proxy_client_get_max_policy_and_matched
func (r *Rules) lookup(name string) (policy, []*filter) {
	max := policyNone
	var matched []*filter
	exact := true
	for {
		for _, rs := range r.sets {
			for _, f := range rs.byName[name] {
				if exact || f.subtree {
					if f.policy > max {
						max = f.policy
					}
					matched = append(matched, f)
				}
			}
		}
		exact = false
		dot := strings.LastIndexByte(name, '.')
		if dot < 0 {
			return max, matched
		}
		name = name[:dot]
	}
}

// The names the rules mention other than the bus, each with whether a filter covers the names below it
func (r *Rules) names() map[string]bool {
	out := map[string]bool{}
	for _, rs := range r.sets {
		for name, fs := range rs.byName {
			if name == busName {
				continue
			}
			for _, f := range fs {
				out[name] = out[name] || f.subtree
			}
		}
	}
	return out
}
