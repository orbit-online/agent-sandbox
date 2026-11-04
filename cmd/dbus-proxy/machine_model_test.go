package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"pgregory.net/rapid"
)

// The state machine's reference model (machine_test.go): what each client may see and send under the rules,
// models/proxy.als's state. Unique names are the parties' roles (svc0, c1), well-known names have dots. The rule
// matching itself is internal/rules', which its tests check against internal/spec's model of the config; the model
// owns everything that changes over time: the names each client's proxy learned, pending calls both ways, the bus's
// owners and match rules.

const (
	lazyName  = "org.test.Lazy"
	sigIface  = "org.test.Sig"
	sigMatch  = "type='signal',interface='org.test.Sig'"
	pingMatch = "type='signal',interface='org.test.Sig',member='Ping'"
)

// The proxy's configs in the machine's world, from internal/gen: the world's names, paths, interfaces and members
var configNames = gen.ConfigNames{Name: rapid.SampledFrom(allNames),
	Path: rapid.SampledFrom([]string{"/org/test", "/org", "/"}), Iface: rapid.SampledFrom([]string{svcIface, sigIface,
		"org.test"}), Member: rapid.SampledFrom([]string{"Echo", "Other", "Ping", "Iface"})}

// Names services take, names clients ask for, and every name a call may go to
var (
	svcNames    = []string{"org.test.Talk", "org.test.Call", "org.test.See", "org.test.Hidden", lazyName}
	clientNames = []string{"org.test.Own", "org.test.Talk", "org.test.Hidden"}
	allNames    = append(append([]string{}, svcNames...), "org.test.Own")
)

// What one client's proxy knows of a unique name: its own policy and the names it was seen owning (names.go)
type refID struct {
	policy rules.Policy
	owned  []string
}

type busKey struct {
	caller string
	serial uint32
	callee string
}

type peerKey struct {
	caller string
	serial uint32
}

// A call let through awaiting its reply: the callee's role ("bus" for the bus) and the call's token
type refCall struct {
	to, tok string
}

type refClient struct {
	role            string
	helloed, closed bool
	table           map[string]*refID
	pending         map[uint32]refCall // its calls let through awaiting a reply, by serial
	peer            map[peerKey]bool   // calls to it awaiting its reply
	sent            []uint32           // serials it used
	matches         map[string]int     // its own match rules
}

// A call to a service awaiting the service's reply
type refIncoming struct {
	from   string
	serial uint32
	tok    string
}

type refSvc struct {
	role string
	in   []refIncoming      // calls to it, unanswered
	out  map[uint32]refCall // its calls to clients, by serial
}

type model struct {
	rules   *rules.Rules
	static  *rules.Set
	owners  map[string]string // well-known name -> role
	clients map[string]*refClient
	svcs    map[string]*refSvc
	lazy    []peerKey // StartServiceByName calls waiting for org.test.Lazy's owner: the caller and serial
	// The calls between connections the bus awaits a reply to: it refuses another with the same caller, serial and
	// callee, and forgets one when the callee answers or either leaves
	busPending map[busKey]bool
	// What each party should receive in this step, as rec() writes it
	want map[string][]string
}

// The model of a proxy with the config cfg
func newModel(cfg []byte) *model {
	rs, err := rules.Decode(cfg)
	if err != nil {
		panic(err)
	}
	return &model{rules: rules.New(rs), static: rs, owners: map[string]string{}, clients: map[string]*refClient{}, svcs: map[string]*refSvc{},
		want: map[string][]string{}, busPending: map[busKey]bool{}}
}

func (m *model) newClient(role string) *refClient {
	c := &refClient{role: role, table: map[string]*refID{},
		pending: map[uint32]refCall{}, peer: map[peerKey]bool{}, matches: map[string]int{}}
	m.clients[role] = c
	return c
}

func (c *refClient) id(role string) *refID {
	e := c.table[role]
	if e == nil {
		e = &refID{}
		c.table[role] = e
	}
	return e
}

func (c *refClient) raise(role string, p rules.Policy) {
	if e := c.id(role); p > e.policy {
		e.policy = p
	}
}

func (c *refClient) addOwned(role, name string) {
	if role == "" || role == busName {
		return
	}
	if e := c.id(role); !slices.Contains(e.owned, name) {
		e.owned = append(e.owned, name)
	}
}

// The policy and filters of a name for client c, as its proxy's lookup has them
func (m *model) lookup(c *refClient, name string) (rules.Policy, []*rules.Filter) {
	var p rules.Policy
	var fs []*rules.Filter
	switch {
	case name == "":
		return rules.Talk, []*rules.Filter{rules.MatchAll(rules.Talk)}
	case strings.Contains(name, "."):
		p, fs = m.rules.Lookup(name)
	default:
		e := c.table[name]
		if e == nil {
			return rules.None, nil
		}
		p = e.policy
		if p > rules.None {
			fs = append(fs, rules.MatchAll(p))
		}
		for _, o := range e.owned {
			op, ofs := m.rules.Lookup(o)
			p = max(p, op)
			fs = append(fs, ofs...)
		}
	}
	return p, fs
}

// Whether the proxy's match rules cover a NameOwnerChanged of name: the rules' names
func (m *model) watches(name string) bool {
	return slices.Contains(m.rules.Names(), name)
}

// lookupNames is what the proxy does when it starts watching names (lookupNames): the owner of each
func (m *model) lookupNames(c *refClient, names []string) {
	for _, n := range names {
		c.addOwned(m.owners[n], n)
	}
}

// The clients connected and registered, in role order
func (m *model) registered() []*refClient {
	var out []*refClient
	for _, r := range mapsKeys(m.clients) {
		if c := m.clients[r]; c.helloed && !c.closed {
			out = append(out, c)
		}
	}
	return out
}

// The keys of a map, sorted
func mapsKeys[V any](mp map[string]V) []string {
	out := make([]string, 0, len(mp))
	for k := range mp {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rec records what a party should receive in this step:
//
//	R <tok> <sender> <body>   a method return to its call
//	E <tok> <sender> <error>  an error reply
//	C <member> <tok> <sender> -> <dest>
//	S <member> <sender> -> <dest or *> <body>
func (m *model) rec(role string, format string, args ...any) {
	m.want[role] = append(m.want[role], fmt.Sprintf(format, args...))
}

// The names the bus lists: its own, the well-known names owned and every registered connection's unique name
func (m *model) busNames() []string {
	out := []string{busName, "obs"}
	// The test binary the bus started for org.test.Lazy never connects
	for r := range m.svcs {
		out = append(out, r)
	}
	for _, c := range m.registered() {
		out = append(out, c.role)
	}
	for n := range m.owners {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
