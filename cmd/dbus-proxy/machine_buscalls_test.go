package main

import (
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
	"pgregory.net/rapid"
)

// The state machine's calls to the bus: owners asked, names listed, owned, released and started, match rules added
// (eavesdropping ones among them) and removed, BecomeMonitor and a second Hello. fromclient.go's bus verdicts

type matchRule struct {
	rule      string
	eavesdrop bool
}

var matchCatalog = []matchRule{
	{"type='method_call',eavesdrop=true", true},
	{sigMatch, false},
	{"type='signal',eavesdrop='false'", true},
	{pingMatch, false},
}

// BusCall: a registered client calls the bus, with a drawn serial
func (mc *machine) BusCall(t *rapid.T) {
	role := pick(t, mc.registered(), "client")
	c, p := mc.m.clients[role], mc.clients[role]
	// rapid draws earlier entries more often
	member := rapid.SampledFrom([]string{"StartServiceByName", "AddMatch", "GetNameOwner", "RequestName", "ListNames",
		"NameHasOwner", "ReleaseName", "RemoveMatch", "BecomeMonitor"}).Draw(t, "member")
	var arg string
	switch member {
	case "GetNameOwner", "NameHasOwner":
		arg = rapid.SampledFrom(mc.destinations()).Draw(t, "name")
	case "RequestName", "ReleaseName":
		arg = rapid.SampledFrom(clientNames).Draw(t, "name")
	case "StartServiceByName":
		arg = rapid.SampledFrom([]string{lazyName, lazyName, "org.test.Hidden", "org.test.See", "org.test.Live"}).Draw(t, "name")
	case "AddMatch":
		arg = rapid.SampledFrom(matchCatalog).Draw(t, "rule").rule
	case "RemoveMatch":
		arg = rapid.SampledFrom([]string{sigMatch, pingMatch}).Draw(t, "rule")
	}
	mc.busCall(t, c, p, mc.drawSerial(t, c, p), member, arg)
}

// Start: a registered client asks the bus to start org.test.Lazy, which stays pending until someone takes the name:
// a call to the bus awaiting its reply, for forged replies to aim at
func (mc *machine) Start(t *rapid.T) {
	role := pick(t, mc.registered(), "client")
	c, p := mc.m.clients[role], mc.clients[role]
	mc.busCall(t, c, p, mc.drawSerial(t, c, p), "StartServiceByName", lazyName)
}

// busCall sends a call to the bus and works out its outcome in the model
func (mc *machine) busCall(t *rapid.T, c *refClient, p *party, serial uint32, member, arg string) {
	var args []any
	switch member {
	case "GetNameOwner", "NameHasOwner", "ReleaseName", "AddMatch", "RemoveMatch":
		args = []any{mc.busNameOf(arg)}
	case "RequestName":
		args = []any{arg, uint32(dbus.NameFlagDoNotQueue)}
	case "StartServiceByName":
		args = []any{arg, uint32(0)}
	case "BecomeMonitor":
		args = []any{[]string{}, uint32(0)}
	}
	msg := busCall(member, args...)
	msg.Flags = dbus.FlagNoAutoStart
	if member == "BecomeMonitor" {
		msg.Headers[dbus.FieldInterface] = dbus.MakeVariant("org.freedesktop.DBus.Monitoring")
	}
	tok := mc.token()
	p.tokens[serial] = tok
	_ = p.sendAs(serial, msg)
	mc.m.busCall(c, serial, tok, member, arg)
}

// busCall: the proxy's verdict on a call to the bus and the bus's answer
func (m *model) busCall(c *refClient, serial uint32, tok, member, arg string) {
	refuse, ok := m.guard(c, serial, tok)
	if !ok {
		return
	}
	role := c.role
	reply := func(format string, args ...any) {
		m.rec(role, "R "+tok+" bus "+format, args...)
	}
	// Guards before any rule: monitoring and eavesdropping, a second Hello (readsOthersTraffic, judgeClient)
	switch {
	case member == "BecomeMonitor", member == "Hello":
		refuse(errAccessDenied)
		return
	case member == "AddMatch" && slices.ContainsFunc(matchCatalog, func(r matchRule) bool { return r.rule == arg && r.eavesdrop }):
		refuse(errAccessDenied)
		return
	}
	// The name in the first argument and the policy the call needs of it (verdict, arg0Policy)
	need := map[string]policy{"GetNameOwner": policySee, "NameHasOwner": policySee, "RequestName": policyOwn,
		"ReleaseName": policyOwn, "StartServiceByName": policyTalk}[member]
	if need != policyNone {
		pol, _ := m.lookup(c, arg)
		switch {
		case pol < policySee && member == "NameHasOwner":
			if m.letThrough(c, serial) {
				m.rec(role, "R %s proxy [false]", tok)
			}
			return
		case pol < policySee:
			refuse(errNameHasNoOwner)
			return
		case pol < need:
			refuse(errAccessDenied)
			return
		}
	}
	if !m.letThrough(c, serial) {
		return
	}
	owner := m.owner(arg)
	switch member {
	case "GetNameOwner":
		if owner == "" {
			m.rec(role, "E %s bus %s", tok, errNameHasNoOwner)
		} else {
			reply("[%s]", owner)
		}
	case "NameHasOwner":
		reply("[%v]", owner != "")
	case "ListNames":
		var seen []string
		for _, n := range m.busNames() {
			if pol, _ := m.lookup(c, n); pol >= policySee {
				seen = append(seen, n)
			}
		}
		slices.Sort(seen)
		reply("[[%s]]", strings.Join(seen, " "))
	case "RequestName":
		switch owner {
		case "":
			reply("[1]")
			m.acquired(arg, role)
		case role:
			reply("[4]")
		default:
			reply("[3]")
		}
	case "ReleaseName":
		switch owner {
		case role:
			reply("[1]")
			m.released(arg, role, true)
		case "":
			reply("[2]")
		default:
			reply("[3]")
		}
	case "StartServiceByName":
		// The bus looks for the name's service file first
		switch {
		case arg != lazyName:
			m.rec(role, "E %s bus %s", tok, errServiceUnknown)
		case owner != "":
			reply("[2]")
		default:
			c.pending[serial] = refCall{"bus", tok}
			m.lazy = append(m.lazy, peerKey{role, serial})
		}
	case "AddMatch":
		c.matches[arg]++
		reply("[]")
	case "RemoveMatch":
		if c.matches[arg] == 0 {
			m.rec(role, "E %s bus org.freedesktop.DBus.Error.MatchRuleNotFound", tok)
			return
		}
		c.matches[arg]--
		reply("[]")
	}
}
