// Package dbuspolicy says what a D-Bus rule set the permissions broker grants may not hold, for the broker, which
// checks the config's declarations, and for the D-Bus proxy, which checks every set the broker adds. The lists are in
// policy.json, which the Home Manager module reads too for its assertions.
//
// The lists guard the config's author against known footguns: names that hand the sandbox more than their own
// service (code run on the host, the user's secrets, input and screen), names it could take over from host programs,
// and wildcards over a vendor's whole namespace. They are not a guarantee: what any other name gives is the config's
// responsibility, and every grant is the user's to consent to (docs/permissions.md, D-Bus)
package dbuspolicy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// One bus's policy
type Policy struct {
	// Names refused with the names below them and any wildcard covering them. A trailing * matches any rest of the
	// last element (org.kde.klauncher*)
	Refused []string `json:"refused"`
	// No wildcard at or below these, nor covering them
	NoWildcard []string `json:"noWildcard"`
	// By name, interfaces no call rule may reach. Neither talk nor own of the name, and every call rule names an
	// interface, none of these
	Methods map[string][]string `json:"methods"`
	// Names only call rules with an interface and a member reach: no talk or own
	ExplicitCalls []string `json:"explicitCalls"`
	// Whether names may end in .*, and whether a set may own names (below the sandbox's app ID only)
	Wildcards bool `json:"wildcards"`
	Own       bool `json:"own"`
}

//go:embed policy.json
var policyJSON []byte

// The policy of each bus, session and system
var Buses = func() map[string]Policy {
	var b map[string]Policy
	if err := json.Unmarshal(policyJSON, &b); err != nil {
		panic(err)
	}
	return b
}()

// A rule set as declared: names, and call and broadcast rules ([METHOD][@PATH]) by name
type Set struct {
	See, Talk, Own  []string
	Call, Broadcast map[string][]string
}

// The tray's names, which the static config owns too: org.freedesktop.StatusNotifierItem-<pid>-<n>
var trayName = regexp.MustCompile(`^org\.freedesktop\.StatusNotifierItem-[0-9]+-[0-9]+$`)

// A launcher's app ID is the default one's with an element of [a-z][a-z0-9-]* added, so names below an app ID whose
// next element starts with a lowercase letter may be another launcher's
var launcherElement = regexp.MustCompile(`^[a-z]`)

// Method is a rule's interface and member: "" for any. A rule's METHOD starting with * matches every method, as in
// xdg-dbus-proxy, whatever follows the *
func Method(rule string) (iface, member string) {
	method, _, _ := strings.Cut(rule, "@")
	if method == "" || method[0] == '*' {
		return "", ""
	}
	dot := strings.LastIndexByte(method, '.')
	if dot < 0 {
		return method, ""
	}
	if m := method[dot+1:]; m != "*" {
		member = m
	}
	return method[:dot], member
}

// Check refuses what bus's policy refuses in s; appID is the sandbox's, which owned names must lie below
func Check(bus, appID string, s Set) error {
	p, ok := Buses[bus]
	if !ok {
		return fmt.Errorf("bus %q: session or system", bus)
	}
	for _, n := range s.Own {
		if err := p.checkOwn(appID, n); err != nil {
			return err
		}
	}
	type use struct {
		name string
		talk bool // talk or own: every method
	}
	var uses []use
	for _, n := range s.See {
		uses = append(uses, use{n, false})
	}
	for _, n := range append(append([]string{}, s.Talk...), s.Own...) {
		uses = append(uses, use{n, true})
	}
	for _, rules := range []map[string][]string{s.Call, s.Broadcast} {
		for n, rs := range rules {
			uses = append(uses, use{n, false})
			for _, r := range rs {
				if method, _, _ := strings.Cut(r, "@"); strings.HasPrefix(method, "*") && method != "*" {
					return fmt.Errorf("rule %q for %s: a METHOD starting with * matches every method; write * or name the interface", r, n)
				}
			}
		}
	}
	for _, u := range uses {
		if err := p.checkName(u.name, u.talk); err != nil {
			return err
		}
	}
	for n, rs := range s.Call {
		bare := strings.TrimSuffix(n, ".*")
		for _, r := range rs {
			iface, member := Method(r)
			if denied, ok := p.Methods[bare]; ok {
				if iface == "" {
					return fmt.Errorf("rule %q for %s: name the interface, the name's %s are refused", r, n, strings.Join(denied, " and "))
				}
				for _, d := range denied {
					if iface == d {
						return fmt.Errorf("rule %q for %s: %s is refused", r, n, d)
					}
				}
			}
			if contains(p.ExplicitCalls, bare) && (iface == "" || member == "") {
				return fmt.Errorf("rule %q for %s: only calls naming an interface and a member", r, n)
			}
		}
	}
	return nil
}

// checkName refuses a name or wildcard the policy refuses; talk is for talk and own, which reach every method
func (p Policy) checkName(arg string, talk bool) error {
	bare, wildcard := strings.CutSuffix(arg, ".*")
	if wildcard {
		if !p.Wildcards {
			return fmt.Errorf("%s: no wildcards on this bus", arg)
		}
		if strings.Count(bare, ".") < 2 {
			return fmt.Errorf("%s: a wildcard needs three name elements before .*", arg)
		}
		for _, n := range p.NoWildcard {
			if bare == n || strings.HasPrefix(bare, n+".") || strings.HasPrefix(n, bare+".") {
				return fmt.Errorf("%s: no wildcard over %s", arg, n)
			}
		}
	}
	for _, r := range p.Refused {
		if covers(r, bare) || wildcard && strings.HasPrefix(strings.TrimSuffix(r, "*"), bare+".") {
			return fmt.Errorf("%s is refused: it reaches %s", arg, r)
		}
	}
	guarded := append([]string{}, p.ExplicitCalls...)
	for n := range p.Methods {
		guarded = append(guarded, n)
	}
	for _, n := range guarded {
		if wildcard && (covers(bare, n) || strings.HasPrefix(n, bare+".")) {
			return fmt.Errorf("%s: no wildcard over %s", arg, n)
		}
		if talk && bare == n {
			return fmt.Errorf("%s: no talk or own, only call rules", arg)
		}
	}
	return nil
}

// covers reports whether the refused pattern r covers the name n: n is r or below it, or r ends in * and n starts with
// the rest
func covers(r, n string) bool {
	if lit, ok := strings.CutSuffix(r, "*"); ok {
		return strings.HasPrefix(n, lit)
	}
	return n == r || strings.HasPrefix(n, r+".")
}

// checkOwn: owning a name makes host programs send it what they mean for the service that would own it, so only the
// sandbox's own names: its app ID and the names below it (but not the ones another launcher's app ID could start),
// and the tray's
func (p Policy) checkOwn(appID, arg string) error {
	if !p.Own {
		return fmt.Errorf("own %s: no own on this bus", arg)
	}
	bare, wildcard := strings.CutSuffix(arg, ".*")
	if !wildcard && trayName.MatchString(bare) {
		return nil
	}
	if appID != "" {
		if !wildcard && bare == appID {
			return nil
		}
		if rest, ok := strings.CutPrefix(bare, appID+"."); ok && !launcherElement.MatchString(rest) {
			return nil
		}
	}
	return fmt.Errorf("own %s: only %s, names below it whose next element doesn't start with a lowercase letter, "+
		"and org.freedesktop.StatusNotifierItem-<pid>-<n>", arg, appID)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
