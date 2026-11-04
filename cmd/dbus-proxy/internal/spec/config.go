package spec

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// The proxy's static rules as docs/permissions.md (D-Bus) describes their config: a JSON object of well-known names
// (exact, not the bus driver's), each an object of a "policy" ("see", "talk" or "own") and "call" and "broadcast"
// lists of rules, at least one rule or a policy; a rule is [METHOD][@PATH], METHOD "*", "IFACE.*" or "IFACE.MEMBER",
// PATH an object path, one ending in "/*" for it and its subtree, or "/*" for any. No key twice, no other field, no
// null, nothing after the object; at most 64 KiB, 64 names and 64 rules a list. Read here as a tree of the JSON
// first, then checked, without the proxy's decoder

const (
	ConfigMaxBytes = 64 << 10
	ConfigMaxNames = 64
	ConfigMaxRules = 64
)

// A JSON value as read: an object's members in order, duplicates kept
type jsonValue struct {
	tok     json.Token
	members []jsonMember
	items   []jsonValue
}

type jsonMember struct {
	key string
	val jsonValue
}

func readJSON(dec *json.Decoder) (jsonValue, error) {
	t, err := dec.Token()
	if err != nil {
		return jsonValue{}, err
	}
	v := jsonValue{tok: t}
	switch t {
	case json.Delim('{'):
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return v, err
			}
			val, err := readJSON(dec)
			if err != nil {
				return v, err
			}
			v.members = append(v.members, jsonMember{k.(string), val})
		}
		_, err = dec.Token()
	case json.Delim('['):
		for dec.More() {
			item, err := readJSON(dec)
			if err != nil {
				return v, err
			}
			v.items = append(v.items, item)
		}
		_, err = dec.Token()
	}
	return v, err
}

// One name's rules
type configRule struct {
	iface, member string // "" for any
	hasPath       bool   // a message without a path matches no rule with one
	path          string // "" for any
	subtree       bool
}

type configName struct {
	policy Level
	calls  []configRule
	ruled  bool // any call or broadcast rule
}

// Config is a config the proxy takes
type Config struct {
	names map[string]*configName
}

// ParseConfig reads a config, or says why the proxy refuses it
func ParseConfig(data []byte) (*Config, error) {
	if len(data) > ConfigMaxBytes {
		return nil, errors.New("too big")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	top, err := readJSON(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("data after the object")
	}
	if top.tok != json.Delim('{') || len(top.members) > ConfigMaxNames || dupKeys(top) {
		return nil, errors.New("not an object of at most 64 distinct names")
	}
	c := &Config{names: map[string]*configName{}}
	for _, m := range top.members {
		if !WellKnownName(m.key) || m.key == DriverName || m.val.tok != json.Delim('{') || dupKeys(m.val) {
			return nil, fmt.Errorf("%q: not a name with an object of its own", m.key)
		}
		n := &configName{}
		for _, f := range m.val.members {
			switch f.key {
			case "policy":
				s, _ := f.val.tok.(string)
				n.policy = map[string]Level{"see": See, "talk": Talk, "own": Own}[s]
				if n.policy == None {
					return nil, fmt.Errorf("%q: policy %v", m.key, f.val.tok)
				}
			case "call", "broadcast":
				if f.val.tok != json.Delim('[') || len(f.val.items) > ConfigMaxRules {
					return nil, fmt.Errorf("%q: %s not a list of at most 64", m.key, f.key)
				}
				for _, item := range f.val.items {
					s, ok := item.tok.(string)
					r, valid := configRuleOf(s)
					if !ok || !valid {
						return nil, fmt.Errorf("%q: rule %v", m.key, item.tok)
					}
					n.ruled = true
					if f.key == "call" {
						n.calls = append(n.calls, r)
					}
				}
			default:
				return nil, fmt.Errorf("%q: field %q", m.key, f.key)
			}
		}
		if n.policy == None && !n.ruled {
			return nil, fmt.Errorf("%q: nothing given", m.key)
		}
		c.names[m.key] = n
	}
	return c, nil
}

func dupKeys(v jsonValue) bool {
	seen := map[string]bool{}
	for _, m := range v.members {
		if seen[m.key] {
			return true
		}
		seen[m.key] = true
	}
	return false
}

func configRuleOf(s string) (configRule, bool) {
	var r configRule
	method, path, hasPath := strings.Cut(s, "@")
	if hasPath {
		r.hasPath = true
		switch {
		case path == "/*":
		case strings.HasSuffix(path, "/*"):
			r.path, r.subtree = strings.TrimSuffix(path, "/*"), true
			if r.path == "/" || !Path(r.path) {
				return r, false
			}
		case Path(path):
			r.path = path
		default:
			return r, false
		}
	}
	if method == "*" || method == "" && hasPath {
		return r, true
	}
	i := strings.LastIndex(method, ".")
	if i < 0 || !Interface(method[:i]) || method[i+1:] != "*" && !Member(method[i+1:]) {
		return r, false
	}
	r.iface = method[:i]
	if method[i+1:] != "*" {
		r.member = method[i+1:]
	}
	return r, true
}

// Names: the names the config gives rules, sorted
func (c *Config) Names() []string {
	var out []string
	for n := range c.names {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// Level is a well-known name's policy: its own, or TALK for any rule (xdg-dbus-proxy's), and TALK for the bus driver
func (c *Config) Level(name string) Level {
	if name == DriverName {
		return Talk
	}
	n := c.names[name]
	switch {
	case n == nil:
		return None
	case n.ruled:
		return max(n.policy, Talk)
	}
	return n.policy
}

// Calls is whether the config lets a client call member of iface at path on a well-known name: talk or own, or a
// call rule that matches
func (c *Config) Calls(name, path, iface, member string) bool {
	if name == DriverName {
		return true
	}
	n := c.names[name]
	if n == nil {
		return false
	}
	if n.policy >= Talk {
		return true
	}
	for _, r := range n.calls {
		pathOK := !(r.hasPath && path == "") && !r.subtree && (r.path == "" || path == r.path) ||
			r.subtree && (path == r.path || strings.HasPrefix(path, r.path+"/"))
		if pathOK && (r.iface == "" || r.iface == iface) && (r.member == "" || r.member == member) {
			return true
		}
	}
	return false
}

// Broadcasts is whether a name's broadcasts reach a client that asked: every one of a name at TALK or above, rules or
// not (docs/permissions.md: any rule gives its name TALK, and TALK passes all its broadcasts)
func (c *Config) Broadcasts(name string) bool { return c.Level(name) >= Talk }
