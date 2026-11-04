package spec

import "fmt"

// The proxy's rules beyond the specification, from docs/permissions.md (D-Bus) and the proxy's own documented
// choices, each a connection ended: a message past 4 MiB; what the specification says to ignore, which the proxy
// refuses as xdg-dbus-proxy does (unknown message types and header fields) or godbus does (unknown flags); more file
// descriptors claimed than one sendmsg carries, or than arrived

const (
	ProxyMaxMessage = 4 << 20
	ProxyMaxFDs     = 253
)

// ProxyHeader checks what the proxy adds to the specification's header rules, for a message whose header the
// specification takes
func ProxyHeader(m *Message, fdsArrived int) error {
	if m.Type > TypeSignal {
		return fmt.Errorf("unknown type %d", m.Type)
	}
	if m.Flags&^KnownFlags != 0 {
		return fmt.Errorf("unknown flags %#x", m.Flags)
	}
	for _, f := range m.Fields {
		if _, known := FieldTypes[f.Code]; !known {
			return fmt.Errorf("unknown field %d", f.Code)
		}
	}
	if f, ok := m.Field(FieldUnixFDs); ok && (f.U32 > ProxyMaxFDs || int(f.U32) > fdsArrived) {
		return fmt.Errorf("%d file descriptors claimed, %d arrived", f.U32, fdsArrived)
	}
	return nil
}

// Outcome of one message from a client at the wire, before any rule: read and judged by the rules, the connection
// ended, or waiting for more bytes
type Outcome int

const (
	Judged Outcome = iota
	Closed
	Waiting
)

// ProxyReads is what the proxy makes of the first message in a client's stream, with fdsArrived file descriptors
// sent along: the message, when it gets judged, and how many bytes it took
func ProxyReads(stream []byte, fdsArrived int) (Outcome, *Message, string) {
	framing, n, why := Frame(stream, ProxyMaxMessage)
	switch framing {
	case Short:
		return Waiting, nil, ""
	case Broken:
		return Closed, nil, why
	}
	m, err := Read(stream[:n])
	if err == nil {
		err = ProxyHeader(m, fdsArrived)
	}
	if err != nil {
		return Closed, m, err.Error()
	}
	return Judged, m, ""
}

// The largest body of a bus driver call the proxy looks into (docs/permissions.md: "bus driver calls up to 4 KiB")
const ProxyMaxInspect = 4 << 10

// ProxyArg0 is the first argument of a message the proxy looks into, when it's a string: a body of at most 4 KiB that
// holds the values of its signature
func ProxyArg0(m *Message) (string, bool) {
	sig := ""
	if f, ok := m.Field(FieldSignature); ok {
		sig = f.Str
	}
	if len(m.Body) > ProxyMaxInspect || sig == "" || sig[0] != 's' || CheckBody(m) != nil {
		return "", false
	}
	r := &reader{b: m.Body, order: m.Order}
	s, err := r.str()
	return s, err == nil
}
