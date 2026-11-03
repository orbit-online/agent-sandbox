package main

import (
	"fmt"

	"github.com/godbus/dbus/v5"
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

func generatesReply(m *message) bool {
	return m.Type == dbus.TypeMethodCall && m.Flags&dbus.FlagNoReplyExpected == 0
}

func isReply(m *message) bool {
	return m.Type == dbus.TypeMethodReply || m.Type == dbus.TypeError
}

func isBusCall(m *message) bool {
	return m.Type == dbus.TypeMethodCall && m.header(dbus.FieldDestination) == busName &&
		m.header(dbus.FieldInterface) == busIface
}

// Refused with and without --filter: what lets a client read traffic not addressed to it. The bus resolves a call
// without an interface by its member, so those count too
func readsOthersTraffic(m *message) bool {
	if m.Type != dbus.TypeMethodCall || m.header(dbus.FieldDestination) != busName {
		return false
	}
	iface, member := m.header(dbus.FieldInterface), m.header(dbus.FieldMember)
	if iface == "org.freedesktop.DBus.Monitoring" || (member == "BecomeMonitor" && (iface == "" || iface == busIface)) {
		return true
	}
	if member == "AddMatch" && (iface == "" || iface == busIface) {
		rule, ok := m.arg0()
		return !ok || isEavesdrop(rule)
	}
	return false
}

// The verdict for a call or signal from the client, by its destination's policy and the rules
func (c *client) verdict(m *message) verdict {
	dest := m.header(dbus.FieldDestination)
	p, fs := c.names.lookup(c.p.rules, dest)
	if p < policySee {
		return hide
	}
	if p < policyTalk {
		return deny
	}
	iface, member := m.header(dbus.FieldInterface), m.header(dbus.FieldMember)
	if dest != busName {
		if p == policyOwn || anyMatches(fs, filterCall, m.header(dbus.FieldPath), iface, member) {
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
func (c *client) arg0Policy(m *message) policy {
	name, ok := m.arg0()
	if !ok || name == "" {
		return policyNone
	}
	p, _ := c.names.lookup(c.p.rules, name)
	return p
}

// Handles a message from the client: forwarded, refused through a Ping whose reply becomes the refusal, or dropped
func (c *client) fromClient(m *message) error {
	if m.Serial() > maxClientSerial {
		return fmt.Errorf("Client serial %d is in the proxy's range", m.Serial())
	}
	if len(m.fds) > 0 && !c.unixFDs {
		return fmt.Errorf("File descriptors from a client that didn't negotiate them")
	}
	var fakes [][]byte
	c.mu.Lock()
	out, err := c.judgeClient(m, &fakes)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if out != nil {
		m.closeFDs()
		if err := c.toBus.send(out, nil); err != nil {
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
func (c *client) judgeClient(m *message, fakes *[][]byte) ([]byte, error) {
	drop := func() ([]byte, error) {
		m.closeFDs()
		m.Message = nil
		return nil, nil
	}
	if isReply(m) {
		rs, _ := m.replySerial()
		if _, ok := c.awaitPeer[rs]; !ok && c.p.filter {
			return drop()
		}
		delete(c.awaitPeer, rs)
		return nil, nil
	}
	refuse := func(name string) ([]byte, error) {
		if !generatesReply(m) {
			return drop()
		}
		return c.rewrite(m, errorReply(m.Serial(), name))
	}
	if _, ok := m.replySerial(); ok {
		// xdg-dbus-proxy takes any message with a reply serial for a reply, so a call carrying the serial of a
		// pending call to the client would pass unchecked
		return refuse(errAccessDenied)
	}
	if readsOthersTraffic(m) {
		return refuse(errAccessDenied)
	}
	if !c.p.filter {
		return nil, nil
	}
	kind := expectNormal
	hello := isBusCall(m) && m.header(dbus.FieldMember) == "Hello"
	if hello {
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
		dest := m.header(dbus.FieldDestination)
		if (dest != "" && dest[0] == ':') || m.Flags&dbus.FlagNoAutoStart != 0 {
			return refuse(errNameHasNoOwner)
		}
		return refuse(errServiceUnknown)
	case deny:
		return refuse(errAccessDenied)
	}
	if generatesReply(m) {
		if err := c.expectFromBus(m.Serial(), expect{kind: kind}); err != nil {
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
func (c *client) rewrite(m *message, reply *dbus.Message) ([]byte, error) {
	data, err := encodeNew(ping(m.Flags), m.Serial())
	if err != nil {
		return nil, err
	}
	if err := c.expectFromBus(m.Serial(), expect{kind: expectRewrite, rewrite: reply}); err != nil {
		return nil, err
	}
	return data, nil
}

// After Hello: watch every name the rules mention and ask who owns it now, so its owner's unique name gets its
// policy; names under a wildcard need ListNames first, and the client waits for it
func (c *client) initialNameOps(fakes *[][]byte) error {
	wildcard := false
	for name, subtree := range c.p.rules.names() {
		if err := c.fakeCall(fakes, busCall("AddMatch", ownerMatch(name, subtree)), expect{kind: expectFakeMatch}); err != nil {
			return err
		}
		if subtree {
			wildcard = true
			continue
		}
		if err := c.fakeCall(fakes, busCall("GetNameOwner", name), expect{kind: expectFakeOwner, name: name}); err != nil {
			return err
		}
	}
	if wildcard {
		c.synced = make(chan struct{})
		return c.fakeCall(fakes, busCall("ListNames"), expect{kind: expectFakeList})
	}
	return nil
}
