// Package dbusgrant is the D-Bus capabilities (docs/permissions.md, D-Bus): a rule set for the session-bus proxy or
// the system-bus one, granted whole. A grant adds it to its bus's proxy under the grant's id through the proxy's
// control socket, and its end removes it, which closes the client connections that used it. The proxy drops every set
// when the broker's connection closes, so a daemon that ends takes its D-Bus grants with it
package dbusgrant

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/orbit-online/agent-sandbox/internal/dbuspolicy"
)

// Config is a D-Bus capability as the config declares it, with the proxy's syntax: names that may end in ".*", call and
// broadcast rules by name, each [METHOD][@PATH]
type Config struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Bus         string              `json:"bus"`
	See         []string            `json:"see,omitempty"`
	Talk        []string            `json:"talk,omitempty"`
	Own         []string            `json:"own,omitempty"`
	Call        map[string][]string `json:"call,omitempty"`
	Broadcast   map[string][]string `json:"broadcast,omitempty"`
	// The sandbox's app ID, which owned names must lie below
	appID string
}

// MaxRules is how many rules the proxy takes in a set at most
const MaxRules = 64

var (
	wellKnown = regexp.MustCompile(`^[A-Za-z_-][A-Za-z0-9_-]*(\.[A-Za-z_-][A-Za-z0-9_-]*)+$`)
	busRule   = regexp.MustCompile(`^(\*|[A-Za-z0-9_.*-]*)(@(/\*|(/[A-Za-z0-9_]+)+(/\*)?|/))?$`)
	dbusBuss  = []string{"session", "system"}
)

// For is the capability for the sandbox of app ID appID, which owned names must lie below
func (d Config) For(appID string) *Config {
	d.appID = appID
	return &d
}

// Check checks a D-Bus capability's rule set: a bus, rules the proxy takes, and nothing the bus's
// policy refuses (internal/dbuspolicy: a guard against known footguns, not a guarantee)
func (d *Config) Check() error {
	if !slices.Contains(dbusBuss, d.Bus) {
		return fmt.Errorf("bus %q: session or system", d.Bus)
	}
	n := len(d.See) + len(d.Talk) + len(d.Own)
	var names []string
	names = append(append(append(names, d.See...), d.Talk...), d.Own...)
	for _, rules := range []map[string][]string{d.Call, d.Broadcast} {
		for name, rs := range rules {
			names = append(names, name)
			n += len(rs)
			for _, r := range rs {
				if !busRule.MatchString(r) {
					return fmt.Errorf("rule %q for %s: [METHOD][@PATH], as the proxy takes it", r, name)
				}
			}
			if len(rs) == 0 {
				return fmt.Errorf("%s: no rules", name)
			}
		}
	}
	if n == 0 || n > MaxRules {
		return fmt.Errorf("%d rules: from 1 to %d", n, MaxRules)
	}
	for _, arg := range names {
		name, _ := strings.CutSuffix(arg, ".*")
		if !wellKnown.MatchString(name) || len(name) > 255 {
			return fmt.Errorf("%q isn't a well-known bus name", arg)
		}
	}
	return dbuspolicy.Check(d.Bus, d.appID, dbuspolicy.Set{See: d.See, Talk: d.Talk, Own: d.Own, Call: d.Call,
		Broadcast: d.Broadcast})
}
