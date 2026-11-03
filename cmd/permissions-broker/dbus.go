package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/orbit-online/agent-sandbox/internal/dbuspolicy"
)

// D-Bus capabilities (docs/permissions.md, D-Bus): a rule set for the session-bus proxy or the system-bus one, granted
// whole. A grant adds it to its bus's proxy under the grant's id through the proxy's control socket, and its end
// removes it, which closes the client connections that used it. The proxy drops every set when the broker's
// connection closes, so a daemon that ends takes its D-Bus grants with it

// A D-Bus capability as the config declares it, with the proxy's syntax: names that may end in ".*", call and
// broadcast rules by name, each [METHOD][@PATH]
type dbusConfig struct {
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

// The proxy takes 64 rules in a set at most
const maxDBusRules = 64

var (
	wellKnown = regexp.MustCompile(`^[A-Za-z_-][A-Za-z0-9_-]*(\.[A-Za-z_-][A-Za-z0-9_-]*)+$`)
	busRule   = regexp.MustCompile(`^(\*|[A-Za-z0-9_.*-]*)(@(/\*|(/[A-Za-z0-9_]+)+(/\*)?|/))?$`)
	dbusBuss  = []string{"session", "system"}
)

// loadDBus makes the config's D-Bus capabilities, each under its own name, for the sandbox of app ID appID
func loadDBus(cfgs []dbusConfig, caps map[string]*capability, appID string) error {
	for i := range cfgs {
		dc := cfgs[i]
		dc.appID = appID
		c := &capability{Name: dc.Name, Type: "dbus", Description: dc.Description, DBus: &dc}
		if err := c.check(); err != nil {
			return fmt.Errorf("D-Bus capability %s: %w", dc.Name, err)
		}
		if _, dup := caps[c.id()]; dup {
			return fmt.Errorf("Capability %s declared twice", c.id())
		}
		caps[c.id()] = c
	}
	return nil
}

// checkDBus checks a D-Bus capability: a name, a description, a bus, rules the proxy takes, and nothing the bus's
// policy refuses (internal/dbuspolicy: a guard against known footguns, not a guarantee)
func (c *capability) checkDBus() error {
	d := c.DBus
	switch {
	case !commandName.MatchString(c.Name):
		return fmt.Errorf("name %q: letters, digits and -", c.Name)
	case c.Description == "":
		return errors.New("no description: the consent names it")
	case len(c.Params) > 0:
		return errors.New("no bounding arguments: a D-Bus capability is granted whole")
	case !slices.Contains(dbusBuss, d.Bus):
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
	if n == 0 || n > maxDBusRules {
		return fmt.Errorf("%d rules: from 1 to %d", n, maxDBusRules)
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

// dbusScope says plainly what a grant covers, for the consent: "On the system bus: call org.freedesktop.timedate1's
// methods and get its signals (talk). ..."
func (c *capability) dbusScope() string {
	d := c.DBus
	named := func(arg string) string {
		if name, ok := strings.CutSuffix(arg, ".*"); ok {
			return name + " and the names below it"
		}
		return arg
	}
	var parts []string
	for _, p := range []struct {
		names []string
		what  string
	}{
		{d.See, "see %s (no calls)"},
		{d.Talk, "call any method of %s and get its signals (talk); the service may be started on demand and may " +
			"ask polkit"},
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
		{d.Call, "call %s: %s"},
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

// The rule set as the proxy's control socket takes it
type dbusSet struct {
	Op        string   `json:"op"`
	ID        string   `json:"id"`
	See       []string `json:"see,omitempty"`
	Talk      []string `json:"talk,omitempty"`
	Own       []string `json:"own,omitempty"`
	Call      []string `json:"call,omitempty"`
	Broadcast []string `json:"broadcast,omitempty"`
}

func (c *capability) dbusSet(id string) dbusSet {
	d := c.DBus
	s := dbusSet{Op: "add", ID: id, See: d.See, Talk: d.Talk, Own: d.Own}
	for name, rules := range d.Call {
		for _, r := range rules {
			s.Call = append(s.Call, name+"="+r)
		}
	}
	for name, rules := range d.Broadcast {
		for _, r := range rules {
			s.Broadcast = append(s.Broadcast, name+"="+r)
		}
	}
	return s
}

// The connection to one bus's proxy, made at the first grant and again after it broke
type dbusProxy struct {
	path string
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

// How long the proxy has to answer
var dbusTimeout = 10 * time.Second

// do sends one request and reads its answer. A broken connection is closed, reported as lost: the proxy dropped
// every set of the broker's with it. dial false doesn't connect anew: a removal has nothing to remove then
func (p *dbusProxy) do(req dbusSet, dial bool) (lost bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		if !dial {
			return false, nil
		}
		conn, err := net.DialTimeout("unix", p.path, dbusTimeout)
		if err != nil {
			return false, fmt.Errorf("Reach the D-Bus proxy: %w", err)
		}
		p.conn, p.r = conn, bufio.NewReader(conn)
	}
	data, _ := json.Marshal(req)
	_ = p.conn.SetDeadline(time.Now().Add(dbusTimeout))
	var res struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	line := []byte{}
	_, err = p.conn.Write(append(data, '\n'))
	if err == nil {
		line, err = p.r.ReadBytes('\n')
	}
	if err == nil {
		err = json.Unmarshal(line, &res)
	}
	if err != nil {
		p.conn.Close()
		p.conn = nil
		return true, fmt.Errorf("The D-Bus proxy's connection broke: %w", err)
	}
	if !res.OK {
		return false, fmt.Errorf("The D-Bus proxy refused the rules: %s", res.Error)
	}
	return false, nil
}

// proxyFor is the connection to bus's proxy
func (b *broker) proxyFor(bus string) (*dbusProxy, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	path := b.cfg.DBusControl[bus]
	if path == "" {
		return nil, fmt.Errorf("No D-Bus proxy for the %s bus", bus)
	}
	if b.proxies == nil {
		b.proxies = map[string]*dbusProxy{}
	}
	if b.proxies[bus] == nil {
		b.proxies[bus] = &dbusProxy{path: path}
	}
	return b.proxies[bus], nil
}

// dbusAdd adds g's rule set to its bus's proxy
func (b *broker) dbusAdd(g *grant) error {
	p, err := b.proxyFor(g.cap.DBus.Bus)
	if err != nil {
		return err
	}
	lost, err := p.do(g.cap.dbusSet(g.ID), true)
	if lost {
		go b.dbusLost(g.cap.DBus.Bus)
	}
	return err
}

// dbusRemove removes g's rule set from its bus's proxy
func (b *broker) dbusRemove(g *grant) {
	p, err := b.proxyFor(g.cap.DBus.Bus)
	if err != nil {
		return
	}
	lost, err := p.do(dbusSet{Op: "remove", ID: g.ID}, false)
	if err != nil {
		slog.Warn("Remove the D-Bus rules", "grant", g.ID, "err", err)
	}
	if lost {
		go b.dbusLost(g.cap.DBus.Bus)
	}
}

// dbusLost ends the grants on bus: its proxy dropped their rules with the broker's connection
func (b *broker) dbusLost(bus string) {
	for _, g := range b.liveGrants() {
		if g.cap.Type == "dbus" && g.cap.DBus.Bus == bus {
			g.end("the D-Bus proxy's connection broke")
		}
	}
}

// closeProxies closes the connections to the proxies, which drop the broker's rule sets
func (b *broker) closeProxies() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, p := range b.proxies {
		p.mu.Lock()
		if p.conn != nil {
			p.conn.Close()
			p.conn = nil
		}
		p.mu.Unlock()
	}
}
