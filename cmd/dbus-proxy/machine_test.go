package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"pgregory.net/rapid"
)

// Stateful property tests: rapid runs random sequences of models/proxy.als's actions against the proxy between a real
// dbus-daemon and clients speaking the wire (machine_world_test.go), and after every step compares what arrived at
// each end, which connections closed and who owns each name with the reference model (machine_model_test.go,
// machine_bus_test.go). Each step runs to quiescence first. The actions: clients (machine_clients_test.go), the bus's
// calls (machine_buscalls_test.go) and services (machine_peers_test.go).
//
// The package build runs 50 sequences of about 30 steps; more with -rapid.checks=1000 -rapid.steps=100 (or
// RAPID_CHECKS and RAPID_STEPS), a failure again with -rapid.seed or -rapid.failfile as rapid prints them.
func TestProxyMachine(t *testing.T) {
	rapidDefault(t, "rapid.checks", "50")
	rapid.Check(t, func(rt *rapid.T) {
		all := rapid.StateMachineActions(newMachine(rt))
		// rapid sorts the actions by name and draws earlier ones more often: named by this order, the attacker's
		// sequencing moves come first
		actions := map[string]func(*rapid.T){"": all[""]}
		for i, a := range []string{"Call", "Generated", "BusCall", "ForgeReply", "Start", "Hello", "Connect",
			"Acquire", "CallClient", "Reply", "ServiceReply", "Broadcast", "Release", "Disconnect"} {
			actions[fmt.Sprintf("%02d%s", i, a)] = all[a]
		}
		rt.Repeat(actions)
	})
}

// rapidDefault sets a rapid flag for this test unless the command line or the environment did
func rapidDefault(t *testing.T, name, value string) {
	set := os.Getenv(strings.ToUpper(strings.ReplaceAll(name, ".", "_"))) != ""
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	if set {
		return
	}
	old := flag.Lookup(name).Value.String()
	_ = flag.Set(name, value)
	t.Cleanup(func() { _ = flag.Set(name, old) })
}

type machine struct {
	w       *world
	m       *model
	clients map[string]*party
	nclient int
	tok     int
}

func newMachine(t *rapid.T) *machine {
	// A config of the world's names, which the specification's model of the config takes
	cfg := gen.Config(configNames, false).Draw(t, "config")
	if _, err := spec.ParseConfig(cfg); err != nil {
		t.Fatalf("Config %s: %v", cfg, err)
	}
	w := newWorld(t, cfg)
	mc := &machine{w: w, m: newModel(cfg), clients: map[string]*party{}}
	for _, s := range w.svcs {
		mc.m.svcs[s.role] = &refSvc{role: s.role, out: map[uint32]refCall{}}
		s.drain()
	}
	w.obs.drain()
	// A client registered and one connected to start with
	mc.hello(t, mc.connect())
	mc.connect()
	mc.Check(t)
	return mc
}

func (mc *machine) token() string {
	mc.tok++
	return "t" + strconv.Itoa(mc.tok)
}

// party of a role: a client's or a service's
func (mc *machine) party(role string) *party {
	if p := mc.clients[role]; p != nil {
		return p
	}
	for _, s := range mc.w.svcs {
		if s.role == role {
			return s
		}
	}
	return nil
}

// Check compares the world with the model after a step settled: what each party received, which clients are
// closed, and the bus's owner of every name
func (mc *machine) Check(t *rapid.T) {
	mc.settle(t)
	for _, role := range mapsKeys(mc.m.clients) {
		c := mc.m.clients[role]
		if closed := mc.clients[role].isClosed(false); closed != c.closed {
			t.Fatalf("%s closed %v, want %v", role, closed, c.closed)
		}
	}
	roles := append(mapsKeys(mc.m.clients), "svc0", "svc1")
	for _, role := range roles {
		got := mc.received(mc.party(role))
		want := mc.m.want[role]
		slices.Sort(want)
		if !sameMessages(got, want) {
			t.Fatalf("%s received\n  %s\nwant\n  %s", role, strings.Join(got, "\n  "), strings.Join(want, "\n  "))
		}
	}
	clear(mc.m.want)
	for _, name := range allNames {
		if got, want := mc.w.owner(name), mc.m.owners[name]; got != want {
			t.Fatalf("Owner of %s: %q, want %q", name, got, want)
		}
	}
}

// settle runs the step to quiescence: the connections that end have ended and the bus dropped them, then each party
// has what the bus sent it, services first (a client's message reaches a service through the bus), then clients
// (what services sent reaches them through the proxy), then services again (clients' replies)
func (mc *machine) settle(t *rapid.T) {
	for _, role := range mapsKeys(mc.m.clients) {
		c, p := mc.m.clients[role], mc.clients[role]
		if c.closed && !p.isClosed(true) {
			t.Fatalf("%s isn't closed", role)
		}
		if c.closed && p.unique != "" {
			mc.w.waitGone(p.unique)
		}
	}
	barrier := func(p *party) {
		if !p.barrier() {
			t.Fatalf("%s closed, or no answer to its barrier", p.role)
		}
	}
	for _, s := range mc.w.svcs {
		barrier(s)
	}
	for _, c := range mc.m.registered() {
		barrier(mc.clients[c.role])
	}
	for _, s := range mc.w.svcs {
		barrier(s)
	}
}

// received is what a party got since the last check, each message as the model's rec writes it, sorted
func (mc *machine) received(p *party) []string {
	var out []string
	for _, m := range p.drain() {
		out = append(out, mc.normal(p, m))
	}
	slices.Sort(out)
	return out
}

func (mc *machine) normal(p *party, m *inMsg) string {
	sender := mc.w.role(m.sender)
	switch m.sender {
	case "":
		sender = "proxy"
	case busName:
		sender = "bus"
	}
	tok := func(serial uint32) string {
		if tok, ok := p.tokens[serial]; ok {
			return tok
		}
		return "?" + strconv.FormatUint(uint64(serial), 10)
	}
	switch m.typ {
	case dbus.TypeMethodReply:
		return fmt.Sprintf("R %s %s %s", tok(m.replySerial), sender, mc.body(m.body))
	case dbus.TypeError:
		return fmt.Sprintf("E %s %s %s", tok(m.replySerial), sender, m.errName)
	case dbus.TypeMethodCall:
		// The machine's own calls carry their token first; a generated one's is by its sender and serial
		t, _ := firstString(m.body)
		if tok, ok := mc.w.callTok(m.sender, m.serial); ok && !isToken(t) {
			t = tok
		}
		return fmt.Sprintf("C %s %s %s -> %s", m.member, t, sender, mc.w.role(m.dest))
	}
	dest := "*"
	if m.dest != "" {
		dest = mc.w.role(m.dest)
	}
	return fmt.Sprintf("S %s %s -> %s %s", m.member, sender, dest, mc.body(m.body))
}

func firstString(body []any) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	s, ok := body[0].(string)
	return s, ok
}

// A body with unique names as roles and string lists sorted
func (mc *machine) body(body []any) string {
	out := make([]any, len(body))
	for i, v := range body {
		switch v := v.(type) {
		case string:
			out[i] = mc.w.role(v)
		case []string:
			l := make([]string, len(v))
			for j, s := range v {
				l[j] = mc.w.role(s)
			}
			slices.Sort(l)
			out[i] = l
		default:
			out[i] = v
		}
	}
	return fmt.Sprint(out)
}
