package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The caps on a config: its size, its names, and the rules in one name's call or broadcast list
const (
	MaxConfig = 64 << 10
	MaxNames  = 64
	MaxRules  = 64
)

// The filters of one source by name: the config's or the bus's own
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

// Load reads the config at path (Decode)
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		var rs *Set
		if rs, err = Decode(data); err == nil {
			return rs, nil
		}
	}
	return nil, fmt.Errorf("Config %s: %w", path, err)
}

// Decode reads a config: a JSON object with an entry per well-known name, exact and not the bus driver's, each an
// object with a "policy" ("see", "talk" or "own"), "call" and "broadcast" lists of rules, or both:
//
//	{"org.freedesktop.portal.Desktop": {"call": ["org.freedesktop.portal.OpenURI.OpenURI@/org/freedesktop/portal/desktop"]},
//	 "org.freedesktop.StatusNotifierItem-100-1": {"policy": "own"}}
//
// Exactly that: a key twice, a field unknown (encoding/json would take "Policy" for "policy"), a null, data after the
// object, a config past the caps are refused
func Decode(data []byte) (*Set, error) {
	if len(data) > MaxConfig {
		return nil, fmt.Errorf("Over %d bytes", MaxConfig)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	rs := newSet()
	err := object(dec, func(name string) error {
		if len(rs.byName) == MaxNames {
			return fmt.Errorf("More than %d names", MaxNames)
		}
		fs, err := decodeName(dec, name)
		if err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		rs.byName[name] = fs
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("Data after the config")
	}
	return rs, nil
}

// object reads a JSON object, calling field with each key and the decoder at its value
func object(dec *json.Decoder, field func(string) error) error {
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return fmt.Errorf("Not a JSON object: %v %v", t, err)
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		key := t.(string)
		if seen[key] {
			return fmt.Errorf("%q twice", key)
		}
		seen[key] = true
		if err := field(key); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

// value reads a JSON value into out, refusing null
func value[T any](dec *json.Decoder, out *T) error {
	var p *T
	if err := dec.Decode(&p); err != nil {
		return err
	}
	if p == nil {
		return errors.New("null")
	}
	*out = *p
	return nil
}

var policies = map[string]Policy{"see": See, "talk": Talk, "own": Own}

// One name's entry
func decodeName(dec *json.Decoder, name string) ([]*Filter, error) {
	if !isBusName(name) || name == BusName {
		return nil, errors.New("Not a well-known bus name other than the bus driver's")
	}
	var fs []*Filter
	err := object(dec, func(field string) error {
		switch field {
		case "policy":
			var s string
			if err := value(dec, &s); err != nil {
				return err
			}
			p, ok := policies[s]
			if !ok {
				return fmt.Errorf("Not a policy: %q", s)
			}
			fs = append(fs, &Filter{policy: p, types: All})
		case "call", "broadcast":
			var list []string
			if err := value(dec, &list); err != nil {
				return fmt.Errorf("%s: %w", field, err)
			}
			if len(list) > MaxRules {
				return fmt.Errorf("%s: more than %d rules", field, MaxRules)
			}
			kind := map[string]Kind{"call": Call, "broadcast": Broadcast}[field]
			for _, r := range list {
				f, err := parseRule(r, kind)
				if err != nil {
					return fmt.Errorf("%s: %w", field, err)
				}
				fs = append(fs, f)
			}
		default:
			return fmt.Errorf("Unknown field %q", field)
		}
		return nil
	})
	if err == nil && len(fs) == 0 {
		err = errors.New("No policy and no rules")
	}
	return fs, err
}

// A rule, [METHOD][@PATH], not empty: METHOD "*" matches any call, "IFACE.*" any of the interface's, "IFACE.MEMBER"
// one (split at the last dot as xdg-dbus-proxy does, so "org.foo.Bar" is member Bar of org.foo); PATH is an object
// path, or one ending in "/*" for it and its subtree, "/*" for any
func parseRule(rule string, t Kind) (*Filter, error) {
	f := &Filter{policy: Talk, types: t}
	method, path, hasPath := strings.Cut(rule, "@")
	if hasPath {
		f.hasPath = true
		f.path, f.pathSubtree = strings.CutSuffix(path, "/*")
		anyPath := f.pathSubtree && f.path == ""
		if !anyPath && (!dbus.ObjectPath(f.path).IsValid() || f.pathSubtree && f.path == "/") {
			return nil, fmt.Errorf("Not a valid path in rule %q", rule)
		}
	}
	if method == "*" || method == "" && hasPath {
		return f, nil
	}
	dot := strings.LastIndexByte(method, '.')
	if dot < 0 || !isDotted(method[:dot], false) || method[dot+1:] != "*" && !isMember(method[dot+1:]) {
		return nil, fmt.Errorf("Not a valid method in rule %q", rule)
	}
	f.iface = method[:dot]
	if m := method[dot+1:]; m != "*" {
		f.member = m
	}
	return f, nil
}

// A well-known bus name: two or more dot-separated elements of [A-Za-z0-9_-], none empty or starting with a digit,
// at most 255 bytes
func isBusName(name string) bool { return isDotted(name, true) }

// isDotted is a well-known bus name with hyphen, an interface name without
func isDotted(name string, hyphen bool) bool {
	if len(name) > 255 {
		return false
	}
	elems := strings.Split(name, ".")
	if len(elems) < 2 {
		return false
	}
	for _, e := range elems {
		if !isElement(e, hyphen) {
			return false
		}
	}
	return true
}

// A member name: one element of [A-Za-z0-9_], at most 255 bytes
func isMember(name string) bool { return len(name) <= 255 && isElement(name, false) }

func isElement(e string, hyphen bool) bool {
	if e == "" || e[0] >= '0' && e[0] <= '9' {
		return false
	}
	for _, c := range e {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || hyphen && c == '-') {
			return false
		}
	}
	return true
}
