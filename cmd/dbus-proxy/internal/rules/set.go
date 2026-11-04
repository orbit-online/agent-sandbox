package rules

import (
	"fmt"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The filters of one source by name: the command line's or the bus's own
type Set struct {
	byName map[string][]*Filter
}

func newSet() *Set {
	return &Set{byName: map[string][]*Filter{}}
}

// The names the set mentions, sorted
func (rs *Set) Names() []string {
	out := make([]string, 0, len(rs.byName))
	for name := range rs.byName {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// Checks a rule's name: a well-known name, exact (no ".*" wildcards, which xdg-dbus-proxy takes)
func checkName(name string) error {
	if !isBusName(name) {
		return fmt.Errorf("Not a valid well-known bus name: %q", name)
	}
	return nil
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
func (rs *Set) addPolicy(name string, p Policy) error {
	if err := checkName(name); err != nil {
		return err
	}
	rs.byName[name] = append(rs.byName[name], &Filter{policy: p, types: All})
	return nil
}

// --call or --broadcast with NAME=RULE. A rule is [METHOD][@PATH], parsed as xdg-dbus-proxy's filter_new_from_rule
// does: METHOD "*" matches anything, otherwise it splits at its last dot into interface and member, a member of "*"
// matching any (so "org.foo.Bar" is member Bar of interface org.foo, as there); PATH may end in "/*" for a subtree
func (rs *Set) addRule(arg string, t Kind) error {
	name, rule, ok := strings.Cut(arg, "=")
	if !ok {
		return fmt.Errorf("Not a NAME=RULE: %q", arg)
	}
	if err := checkName(name); err != nil {
		return err
	}
	f := &Filter{policy: Talk, types: t}
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

// Args are a set's rules in xdg-dbus-proxy's syntax: names for --see, --talk and --own, NAME=RULE for --call and
// --broadcast
type Args struct {
	See, Talk, Own, Call, Broadcast []string
}

// Parse parses the command line's rules
func Parse(a Args) (*Set, error) {
	rs := newSet()
	return rs, rs.add(a)
}

func (rs *Set) add(a Args) error {
	for _, o := range []struct {
		flag string
		args []string
		add  func(string) error
	}{
		{"see", a.See, func(n string) error { return rs.addPolicy(n, See) }},
		{"talk", a.Talk, func(n string) error { return rs.addPolicy(n, Talk) }},
		{"own", a.Own, func(n string) error { return rs.addPolicy(n, Own) }},
		{"call", a.Call, func(r string) error { return rs.addRule(r, Call) }},
		{"broadcast", a.Broadcast, func(r string) error { return rs.addRule(r, Broadcast) }},
	} {
		for _, arg := range o.args {
			if err := o.add(arg); err != nil {
				return fmt.Errorf("--%s: %w", o.flag, err)
			}
		}
	}
	return nil
}
