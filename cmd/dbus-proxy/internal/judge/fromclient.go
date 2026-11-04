package judge

import (
	"fmt"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
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
func (j *Judge) verdict(m *wire.Message) verdict {
	dest := m.Header(dbus.FieldDestination)
	p, fs := j.lookup(dest)
	if p < rules.See {
		return hide
	}
	if p < rules.Talk {
		return deny
	}
	iface, member := m.Header(dbus.FieldInterface), m.Header(dbus.FieldMember)
	if dest != busName {
		if p == rules.Own || rules.AnyMatches(fs, rules.Call, m.Header(dbus.FieldPath), iface, member) {
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
func (j *Judge) arg0Policy(m *wire.Message) rules.Policy {
	name, ok := arg0(m)
	if !ok || name == "" {
		return rules.None
	}
	p, _ := j.lookup(name)
	return p
}

// FromClient judges a message from the client: forwarded, refused through a Ping whose reply becomes the refusal
// (Replace), or dropped. An error ends the connection
func (j *Judge) FromClient(m *wire.Message) (Action, error) {
	if m.Serial() > MaxClientSerial {
		return Action{}, fmt.Errorf("Client serial %d is in the proxy's range", m.Serial())
	}
	if len(m.FDs()) > 0 && !j.unixFDs {
		return Action{}, fmt.Errorf("File descriptors from a client that didn't negotiate them")
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var calls [][]byte
	a, err := j.judgeClient(m, &calls)
	a.Calls = calls
	return a, err
}

// Decides under mu; the proxy's own calls go in fakes
func (j *Judge) judgeClient(m *wire.Message, fakes *[][]byte) (Action, error) {
	if isReply(m) {
		// Only to a call the client got, and to its caller
		rs, _ := m.ReplySerial()
		call := peerCall{m.Header(dbus.FieldDestination), rs}
		if _, ok := j.awaitPeer[call]; !ok {
			return dropped, nil
		}
		delete(j.awaitPeer, call)
		return forwarded, nil
	}
	refuse := func(name string) (Action, error) {
		if !generatesReply(m) {
			return dropped, nil
		}
		return j.rewrite(m, errorReply(m.Serial(), name))
	}
	if _, ok := m.ReplySerial(); ok {
		// xdg-dbus-proxy takes any message with a reply serial for a reply, so a call carrying the serial of a
		// pending call to the client would pass unchecked
		return refuse(ErrAccessDenied)
	}
	if m.Type == dbus.TypeMethodCall && m.Header(dbus.FieldDestination) == "" {
		// The bus refuses them, or delivers them to monitors only; the proxy doesn't rely on that
		return refuse(ErrAccessDenied)
	}
	if readsOthersTraffic(m) {
		return refuse(ErrAccessDenied)
	}
	kind := expectNormal
	hello := isBusCall(m) && m.Header(dbus.FieldMember) == "Hello"
	if hello {
		if j.helloSeen {
			// The bus would end the connection; refusing it here keeps a second Hello's reply from being taken
			// for the first's
			return refuse(ErrAccessDenied)
		}
		kind = expectHello
	}
	v := j.verdict(m)
	switch v {
	case filterHasOwner, filterGetOwner:
		if j.arg0Policy(m) < rules.See {
			if !generatesReply(m) {
				// No reply expected: a Ping would await the bus's reply forever
				return dropped, nil
			}
			if v == filterGetOwner {
				return j.rewrite(m, errorReply(m.Serial(), ErrNameHasNoOwner))
			}
			return j.rewrite(m, boolReply(m.Serial(), false))
		}
	case validateMatch:
		// readsOthersTraffic refused eavesdropping already
	case validateOwn, validateSee, validateTalk:
		need := map[verdict]rules.Policy{validateOwn: rules.Own, validateSee: rules.See, validateTalk: rules.Talk}[v]
		if p := j.arg0Policy(m); p < need {
			if p < rules.See {
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
			return refuse(ErrNameHasNoOwner)
		}
		return refuse(ErrServiceUnknown)
	case deny:
		return refuse(ErrAccessDenied)
	}
	if generatesReply(m) {
		e := expect{kind: kind, fromBus: m.Header(dbus.FieldDestination) == busName}
		if err := j.expectFromBus(m.Serial(), e); err != nil {
			return Action{}, err
		}
	}
	if hello && !j.helloSeen {
		j.helloSeen = true
		return forwarded, j.initialNameOps(fakes)
	}
	return forwarded, nil
}

// A refused call goes to the bus as a Ping with its serial; the reply to it becomes the refusal
func (j *Judge) rewrite(m *wire.Message, reply *dbus.Message) (Action, error) {
	data, err := wire.Encode(ping(m.Flags), m.Serial())
	if err != nil {
		return Action{}, err
	}
	if err := j.expectFromBus(m.Serial(), expect{kind: expectRewrite, rewrite: reply, fromBus: true}); err != nil {
		return Action{}, err
	}
	return Action{Verdict: Replace, Message: data}, nil
}

// After Hello: watch every name the rules mention and ask who owns it now, so its owner's unique name gets its
// policy, and hold the client until the answers came
func (j *Judge) initialNameOps(fakes *[][]byte) error {
	return j.lookupNames(j.rules.Names(), fakes)
}
