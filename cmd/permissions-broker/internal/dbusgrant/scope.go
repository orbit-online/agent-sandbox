package dbusgrant

import (
	"fmt"
	"sort"
	"strings"

	"github.com/orbit-online/agent-sandbox/internal/dbuspolicy"
)

// Scope says plainly what a grant covers, for the consent: "On the system bus: call org.freedesktop.timedate1's
// methods and get its signals (talk). ..."
func (d *Config) Scope() string {
	named := func(arg string) string {
		if name, ok := strings.CutSuffix(arg, ".*"); ok {
			return name + " and the names below it"
		}
		return arg
	}
	// On the system bus polkit judges the proxy's calls as the user's graphical session (docs/permissions.md, D-Bus)
	talk, calls := "call any method of %s and get its signals (talk); the service may be started on demand and may "+
		"ask polkit", "call %s: %s"
	if d.Bus == "system" {
		talk = "call any method of %s and get its signals (talk); the service may be started on demand (" + desktopPolkit + ")"
		calls = "call %s: %s (" + desktopPolkit + ")"
	}
	var parts []string
	for _, p := range []struct {
		names []string
		what  string
	}{
		{d.See, "see %s (no calls)"},
		{d.Talk, talk},
		{d.Own, "own %s, and anything talk gives (own): host programs will send it what they mean for that name"},
	} {
		for _, n := range p.names {
			parts = append(parts, fmt.Sprintf(p.what, named(n)))
		}
	}
	for _, r := range []struct {
		rules map[string][]string
		what  string
	}{
		{d.Call, calls},
		{d.Broadcast, "get the signals of %s: %s"},
	} {
		keys := make([]string, 0, len(r.rules))
		for k := range r.rules {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			rules := make([]string, len(r.rules[k]))
			for i, rule := range r.rules[k] {
				rules[i] = describeRule(rule)
			}
			parts = append(parts, fmt.Sprintf(r.what, named(k), strings.Join(rules, ", ")))
		}
	}
	return "On the " + d.Bus + " bus: " + strings.Join(parts, "; ") + "."
}

// What a system-bus grant's calls get from polkit, which takes the proxy, a process of the user's outside any session,
// for the user's graphical session
const desktopPolkit = "polkit treats these calls as yours at the desktop: actions an active session may take run without asking"

// describeRule says what a call or broadcast rule matches, as the proxy reads it: "any method", "any method of
// org.foo.Iface", "org.foo.Iface.Get", with its path. A METHOD starting with * matches every method, whatever follows
func describeRule(rule string) string {
	iface, member := dbuspolicy.Method(rule)
	out := iface + "." + member
	switch {
	case iface == "":
		out = "any method"
	case member == "":
		out = "any method of " + iface
	}
	if _, path, ok := strings.Cut(rule, "@"); ok && path != "" {
		switch sub, ok := strings.CutSuffix(path, "/*"); {
		case ok && sub == "":
			out += " on any object"
		case ok:
			out += " on " + sub + " and the objects below it"
		default:
			out += " on " + path
		}
	}
	return out
}
