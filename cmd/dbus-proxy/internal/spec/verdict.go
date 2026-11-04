package spec

import "regexp"

// The proxy's verdict on a message from a client, from docs/permissions.md (D-Bus) and xdg-dbus-proxy's verdicts, for
// a message the specification's model read: what the rules let through, what's refused with which error, what's
// dropped, and what ends the connection. From the message's fields alone and what the caller's model knows, without
// the proxy's own code

// Policy levels, each implying the ones before it, as xdg-dbus-proxy has them
type Level int

const (
	None Level = iota
	See
	Talk
	Own
)

// Rules is what the caller's model knows of one client's connection
type Rules interface {
	// Level is a name's policy for the client: a well-known name's by the rules, a unique name's by the names the
	// proxy saw it own (and TALK for the client's own, once its Hello was answered)
	Level(name string) Level
	// Calls is whether a call or a call rule lets the client call member of iface at path on name
	Calls(name, path, iface, member string) bool
	// Asked is whether a call from caller with serial awaits the client's reply
	Asked(caller string, serial uint32) bool
	// Awaiting is whether a call of the client's with serial awaits its reply from the bus side
	Awaiting(serial uint32) bool
	// HelloSent is whether the client sent a Hello the proxy let through
	HelloSent() bool
}

// What becomes of a message
type Kind int

const (
	Forward Kind = iota
	Refuse       // Refused with Error, the client getting the error from the proxy
	Drop
	End // The connection ends
)

// Verdict is the proxy's verdict on one message
type Verdict struct {
	Kind  Kind
	Error string // For Refuse: the error, or FalseReply
	ToBus bool   // For Forward: a call to the bus driver
}

const (
	AccessDenied   = "org.freedesktop.DBus.Error.AccessDenied"
	NameHasNoOwner = "org.freedesktop.DBus.Error.NameHasNoOwner"
	ServiceUnknown = "org.freedesktop.DBus.Error.ServiceUnknown"
	// NameHasOwner of a hidden name: a reply of false the proxy makes up
	FalseReply = "false"

	DriverName = "org.freedesktop.DBus"
	BusIface   = "org.freedesktop.DBus"
	// The client's serials go up to here; above are the proxy's own, as in xdg-dbus-proxy
	MaxClientSerial = ^uint32(0) - 65536
)

// xdg-dbus-proxy's is_eavesdrop: "eavesdrop", blanks, "="
var eavesdrop = regexp.MustCompile(`eavesdrop[ \t\n\r]*=`)

// The bus driver's methods the proxy passes, and the policy of the first argument each needs. Any other, on any
// interface but Introspectable, is refused: UpdateActivationEnvironment among them
var Driver = map[string]Level{
	"Hello": None, "AddMatch": None, "RemoveMatch": None, "GetId": None, "ListNames": None,
	"ListActivatableNames": None, "RequestName": Own, "ReleaseName": Own, "ListQueuedOwners": Own,
	"NameHasOwner": See, "GetNameOwner": See, "GetConnectionUnixProcessID": See, "GetConnectionCredentials": See,
	"GetAdtAuditSessionData": See, "GetConnectionSELinuxSecurityContext": See, "GetConnectionUnixUser": See,
	"StartServiceByName": Talk,
}

// ProxyVerdict is the verdict on m, which the proxy read (ProxyReads)
func ProxyVerdict(m *Message, r Rules) Verdict {
	if m.Serial > MaxClientSerial {
		return Verdict{Kind: End}
	}
	dest, iface, member := m.Str(FieldDestination), m.Str(FieldInterface), m.Str(FieldMember)
	if m.Type == TypeReturn || m.Type == TypeError {
		rs, _ := m.Field(FieldReplySerial)
		if r.Asked(dest, rs.U32) {
			return Verdict{Kind: Forward}
		}
		return Verdict{Kind: Drop}
	}
	reply := m.Type == TypeCall && m.Flags&FlagNoReplyExpected == 0
	refuse := func(err string) Verdict {
		switch {
		case !reply:
			return Verdict{Kind: Drop}
		case r.Awaiting(m.Serial):
			return Verdict{Kind: End}
		}
		return Verdict{Kind: Refuse, Error: err}
	}
	if _, ok := m.Field(FieldReplySerial); ok {
		return refuse(AccessDenied)
	}
	call := m.Type == TypeCall
	if call && dest == "" {
		return refuse(AccessDenied)
	}
	toDriver := call && dest == DriverName
	driverIface := iface == "" || iface == BusIface
	arg0, hasArg0 := ProxyArg0(m)
	switch {
	case toDriver && (iface == "org.freedesktop.DBus.Monitoring" || member == "BecomeMonitor" && driverIface):
		return refuse(AccessDenied)
	case toDriver && member == "AddMatch" && driverIface && (!hasArg0 || eavesdrop.MatchString(arg0)):
		return refuse(AccessDenied)
	case toDriver && iface == BusIface && member == "Hello" && r.HelloSent():
		return refuse(AccessDenied)
	}
	level := func(name string) Level {
		if name == "" || name == DriverName {
			return Talk
		}
		return r.Level(name)
	}
	hide := func() Verdict {
		if dest != "" && dest[0] == ':' || m.Flags&FlagNoAutoStart != 0 {
			return refuse(NameHasNoOwner)
		}
		return refuse(ServiceUnknown)
	}
	forward := func(toBus bool) Verdict {
		if reply && r.Awaiting(m.Serial) {
			return Verdict{Kind: End}
		}
		return Verdict{Kind: Forward, ToBus: toBus}
	}
	p := level(dest)
	switch {
	case p < See:
		return hide()
	case p < Talk:
		return refuse(AccessDenied)
	case dest != DriverName:
		if p == Own || dest == "" || r.Calls(dest, m.Str(FieldPath), iface, member) {
			return forward(false)
		}
		return refuse(AccessDenied)
	case call && iface == "org.freedesktop.DBus.Introspectable":
		return forward(true)
	}
	need, known := Driver[member]
	if !call || iface != BusIface || !known {
		return refuse(AccessDenied)
	}
	a := None
	if hasArg0 && arg0 != "" {
		a = level(arg0)
	}
	switch {
	case member == "NameHasOwner" && a < See:
		return refuse(FalseReply)
	case member == "GetNameOwner" && a < See:
		return refuse(NameHasNoOwner)
	case a < need && a < See:
		return hide()
	case a < need:
		return refuse(AccessDenied)
	}
	return forward(true)
}
