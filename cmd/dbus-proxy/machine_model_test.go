package main

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// The state machine's reference model (machine_test.go): what each client may see and send under the static rules
// and the live sets in force, models/proxy.als's state. Unique names are the parties' roles (svc0, c1), well-known
// names have dots. The rule matching itself is rules.go's, which rules_test.go checks against xdg-dbus-proxy's
// semantics; the model owns everything that changes over time: the sets in force, the names each client's proxy
// learned, pending calls both ways, which sets a client used, the bus's owners and match rules.

const (
	lazyName  = "org.test.Lazy"
	sigIface  = "org.test.Sig"
	sigMatch  = "type='signal',interface='org.test.Sig'"
	pingMatch = "type='signal',interface='org.test.Sig',member='Ping'"
)

// The proxy's command line in the machine's world
var staticArgs = []string{"--talk=org.test.Talk", "--call=org.test.Call=org.test.Iface.Echo@/org/test",
	"--see=org.test.See", "--talk=" + lazyName, "--own=org.test.Own"}

// The live sets the broker adds, each valid under the session bus's policy
var setCatalog = []map[string][]string{
	{"talk": {"org.test.Live"}},
	{"call": {"org.test.Live=org.test.Iface.Echo"}, "broadcast": {"org.test.Live=org.test.Sig.Ping"}},
	{"talk": {"org.test.W.A"}},
	{"own": {testApp + ".Live"}},
	{"see": {"org.test.Hidden"}},
}

// Names services take, names clients ask for, and every name a call may go to
var (
	svcNames    = []string{"org.test.Talk", "org.test.Call", "org.test.See", "org.test.Hidden", "org.test.Live", "org.test.W.A", lazyName}
	clientNames = []string{"org.test.Own", testApp + ".Live", "org.test.Talk", "org.test.Hidden"}
	allNames    = append(append([]string{}, svcNames...), "org.test.Own", testApp+".Live")
)

// A live set in force: its id, catalog entry and the RuleSet the model looks names up in
type refSet struct {
	id  string
	idx int
	rs  *RuleSet
}

// What one client's proxy knows of a unique name: its own policy and the names it was seen owning (names.go)
type refID struct {
	policy policy
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
	watched         map[*refSet]bool   // live sets whose names the proxy watches for it
	used            map[*refSet]bool   // live sets a message it sent or got was judged under
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
	static  *RuleSet
	live    []*refSet
	owners  map[string]string // well-known name -> role
	clients map[string]*refClient
	svcs    map[string]*refSvc
	lazy    []peerKey // StartServiceByName calls waiting for org.test.Lazy's owner: the caller and serial
	// The calls between connections the bus awaits a reply to: it refuses another with the same caller, serial and
	// callee, and forgets one when the callee answers or either leaves
	busPending map[busKey]bool
	setSeq     int
	// What each party should receive in this step, as rec() writes it
	want map[string][]string
}

func newModel() *model {
	rs := NewRuleSet()
	for _, a := range staticArgs {
		flag, arg, _ := strings.Cut(a, "=")
		var err error
		switch flag {
		case "--talk":
			err = rs.AddPolicy(arg, policyTalk)
		case "--see":
			err = rs.AddPolicy(arg, policySee)
		case "--own":
			err = rs.AddPolicy(arg, policyOwn)
		case "--call":
			err = rs.AddRule(arg, filterCall)
		}
		if err != nil {
			panic(err)
		}
	}
	return &model{static: rs, owners: map[string]string{}, clients: map[string]*refClient{}, svcs: map[string]*refSvc{},
		want: map[string][]string{}, busPending: map[busKey]bool{}}
}

func (m *model) newClient(role string) *refClient {
	c := &refClient{role: role, table: map[string]*refID{}, watched: map[*refSet]bool{}, used: map[*refSet]bool{},
		pending: map[uint32]refCall{}, peer: map[peerKey]bool{}, matches: map[string]int{}}
	m.clients[role] = c
	return c
}

// The rules in force
func (m *model) rules() *Rules {
	sets := []*RuleSet{m.static}
	for _, s := range m.live {
		sets = append(sets, s.rs)
	}
	return NewRules(sets...)
}

func (m *model) setOf(rs *RuleSet) *refSet {
	for _, s := range m.live {
		if s.rs == rs {
			return s
		}
	}
	return nil
}

func (c *refClient) id(role string) *refID {
	e := c.table[role]
	if e == nil {
		e = &refID{}
		c.table[role] = e
	}
	return e
}

func (c *refClient) raise(role string, p policy) {
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

// The policy and filters of a name for client c, as its proxy's lookup has them, marking the live sets it touches
// as used
func (m *model) lookup(c *refClient, name string) (policy, []*filter) {
	var p policy
	var fs []*filter
	switch {
	case name == "":
		return policyTalk, []*filter{matchAll[policyTalk]}
	case strings.Contains(name, "."):
		p, fs = m.rules().lookup(name)
	default:
		e := c.table[name]
		if e == nil {
			return policyNone, nil
		}
		p = e.policy
		if p > policyNone {
			fs = append(fs, matchAll[p])
		}
		for _, o := range e.owned {
			op, ofs := m.rules().lookup(o)
			p = max(p, op)
			fs = append(fs, ofs...)
		}
	}
	for _, f := range fs {
		if s := m.setOf(f.set); s != nil {
			c.used[s] = true
		}
	}
	return p, fs
}

// Whether the proxy's match rules for c cover a NameOwnerChanged of name: the static rules' names, and those of the
// live sets it watches
func (m *model) watches(c *refClient, name string) bool {
	if slices.Contains(NewRules(m.static).names(), name) {
		return true
	}
	for s := range c.watched {
		if slices.Contains(s.rs.names(), name) {
			return true
		}
	}
	return false
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
