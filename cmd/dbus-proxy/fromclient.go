package main

import (
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// What a message from the client gets, after xdg-dbus-proxy's get_dbus_method_handler
type verdict int

const (
	pass verdict = iota
	deny
	hide
	filterHasOwner
	filterGetOwner
	validateOwn
	validateSee
	validateTalk
	validateMatch
	filterNameList
)

func generatesReply(m *wire.Message) bool {
	return m.Type == dbus.TypeMethodCall && m.Flags&dbus.FlagNoReplyExpected == 0
}

func isReply(m *wire.Message) bool {
	return m.Type == dbus.TypeMethodReply || m.Type == dbus.TypeError
}

func isBusCall(m *wire.Message) bool {
	return m.Type == dbus.TypeMethodCall && m.Header(dbus.FieldDestination) == busName &&
		m.Header(dbus.FieldInterface) == busIface
}

// Refused whatever the rules: what lets a client read traffic not addressed to it. The bus resolves a call
// without an interface by its member, so those count too
func readsOthersTraffic(m *wire.Message) bool {
	if m.Type != dbus.TypeMethodCall || m.Header(dbus.FieldDestination) != busName {
		return false
	}
	iface, member := m.Header(dbus.FieldInterface), m.Header(dbus.FieldMember)
	if iface == "org.freedesktop.DBus.Monitoring" || (member == "BecomeMonitor" && (iface == "" || iface == busIface)) {
		return true
	}
	if member == "AddMatch" && (iface == "" || iface == busIface) {
		rule, ok := arg0(m)
		return !ok || isEavesdrop(rule)
	}
	return false
}

// The verdict for a call or signal from the client, by its destination's policy and the rules
func (c *client) verdict(m *wire.Message) verdict {
	dest := m.Header(dbus.FieldDestination)
	p, fs := c.lookup(dest)
	if p < policySee {
		return hide
	}
	if p < policyTalk {
		return deny
	}
	iface, member := m.Header(dbus.FieldInterface), m.Header(dbus.FieldMember)
	if dest != busName {
		if p == policyOwn || anyMatches(fs, filterCall, m.Header(dbus.FieldPath), iface, member) {
			return pass
		}
		return deny
	}
	if m.Type == dbus.TypeMethodCall && iface == "org.freedesktop.DBus.Introspectable" {
		return pass
	}
	if !isBusCall(m) {
		return deny
	}
	switch member {
	case "AddMatch":
		return validateMatch
	case "Hello", "RemoveMatch", "GetId":
		return pass
	case "RequestName", "ReleaseName", "ListQueuedOwners":
		return validateOwn
	case "NameHasOwner":
		return filterHasOwner
	case "GetNameOwner":
		return filterGetOwner
	case "GetConnectionUnixProcessID", "GetConnectionCredentials", "GetAdtAuditSessionData",
		"GetConnectionSELinuxSecurityContext", "GetConnectionUnixUser":
		return validateSee
	case "StartServiceByName":
		return validateTalk
	case "ListNames", "ListActivatableNames":
		return filterNameList
	}
	// UpdateActivationEnvironment, BecomeMonitor and whatever the bus adds later
	return deny
}

// The policy of the name in a bus call's first argument; none when it has no string there
func (c *client) arg0Policy(m *wire.Message) policy {
	name, ok := arg0(m)
	if !ok || name == "" {
		return policyNone
	}
	p, _ := c.lookup(name)
	return p
}

// Handles a message from the client: forwarded, refused through a Ping whose reply becomes the refusal, or dropped
func (c *client) fromClient(m *wire.Message) error {
	if m.Serial() > maxClientSerial {
		return fmt.Errorf("Client serial %d is in the proxy's range", m.Serial())
	}
	if len(m.FDs()) > 0 && !c.unixFDs {
		return fmt.Errorf("File descriptors from a client that didn't negotiate them")
	}
	var fakes [][]byte
	c.mu.Lock()
	c.cur = c.p.current()
	out, err := c.judgeClient(m, &fakes)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if out != nil {
		m.CloseFDs()
		if err := c.toBus.Send(out, nil); err != nil {
			return err
		}
	} else if m.Message != nil {
		if err := forward(c.toBus, m); err != nil {
			return err
		}
	}
	return sendAll(c.toBus, fakes)
}

// Decides under mu. Returns the bytes to send instead of m, or nil with m left to forward, or nil with m.Message
// cleared to drop it
func (c *client) judgeClient(m *wire.Message, fakes *[][]byte) ([]byte, error) {
	drop := func() ([]byte, error) {
		m.CloseFDs()
		m.Message = nil
		return nil, nil
	}
	if isReply(m) {
		// Only to a call the client got, and to its caller
		rs, _ := m.ReplySerial()
		call := peerCall{m.Header(dbus.FieldDestination), rs}
		if _, ok := c.awaitPeer[call]; !ok {
			return drop()
		}
		delete(c.awaitPeer, call)
		return nil, nil
	}
	refuse := func(name string) ([]byte, error) {
		if !generatesReply(m) {
			return drop()
		}
		return c.rewrite(m, errorReply(m.Serial(), name))
	}
	if _, ok := m.ReplySerial(); ok {
		// xdg-dbus-proxy takes any message with a reply serial for a reply, so a call carrying the serial of a
		// pending call to the client would pass unchecked
		return refuse(errAccessDenied)
	}
	if m.Type == dbus.TypeMethodCall && m.Header(dbus.FieldDestination) == "" {
		// The bus refuses them, or delivers them to monitors only; the proxy doesn't rely on that
		return refuse(errAccessDenied)
	}
	if readsOthersTraffic(m) {
		return refuse(errAccessDenied)
	}
	kind := expectNormal
	hello := isBusCall(m) && m.Header(dbus.FieldMember) == "Hello"
	if hello {
		if c.helloSeen {
			// The bus would end the connection; refusing it here keeps a second Hello's reply from being taken
			// for the first's
			return refuse(errAccessDenied)
		}
		kind = expectHello
	}
	v := c.verdict(m)
	switch v {
	case filterHasOwner, filterGetOwner:
		if c.arg0Policy(m) < policySee {
			if v == filterGetOwner {
				return c.rewrite(m, errorReply(m.Serial(), errNameHasNoOwner))
			}
			return c.rewrite(m, boolReply(m.Serial(), false))
		}
	case validateMatch:
		// readsOthersTraffic refused eavesdropping already
	case validateOwn, validateSee, validateTalk:
		need := map[verdict]policy{validateOwn: policyOwn, validateSee: policySee, validateTalk: policyTalk}[v]
		if p := c.arg0Policy(m); p < need {
			if p < policySee {
				v = hide
			} else {
				v = deny
			}
		}
	case filterNameList:
		kind = expectListNames
	}
	switch v {
	case hide:
		dest := m.Header(dbus.FieldDestination)
		if (dest != "" && dest[0] == ':') || m.Flags&dbus.FlagNoAutoStart != 0 {
			return refuse(errNameHasNoOwner)
		}
		return refuse(errServiceUnknown)
	case deny:
		return refuse(errAccessDenied)
	}
	if generatesReply(m) {
		e := expect{kind: kind, fromBus: m.Header(dbus.FieldDestination) == busName}
		if err := c.expectFromBus(m.Serial(), e); err != nil {
			return nil, err
		}
	}
	if hello && !c.helloSeen {
		c.helloSeen = true
		return nil, c.initialNameOps(fakes)
	}
	return nil, nil
}

// A refused call goes to the bus as a Ping with its serial; the reply to it becomes the refusal
func (c *client) rewrite(m *wire.Message, reply *dbus.Message) ([]byte, error) {
	data, err := wire.Encode(ping(m.Flags), m.Serial())
	if err != nil {
		return nil, err
	}
	if err := c.expectFromBus(m.Serial(), expect{kind: expectRewrite, rewrite: reply, fromBus: true}); err != nil {
		return nil, err
	}
	return data, nil
}

// After Hello: watch every name the rules mention and ask who owns it now, so its owner's unique name gets its
// policy, and hold the client until the answers came
func (c *client) initialNameOps(fakes *[][]byte) error {
	for _, rs := range c.cur.live() {
		if err := c.lookupSet(rs, fakes); err != nil {
			return err
		}
	}
	// Those added since the client's message were taken with the rules above, under the same mu
	c.newSets = nil
	_, err := c.lookupNames(c.cur.names(), fakes)
	return err
}
