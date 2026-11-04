package main

import (
	"encoding/binary"

	"github.com/godbus/dbus/v5"
)

const (
	busName  = "org.freedesktop.DBus"
	busPath  = dbus.ObjectPath("/org/freedesktop/DBus")
	busIface = "org.freedesktop.DBus"

	errAccessDenied   = "org.freedesktop.DBus.Error.AccessDenied"
	errNameHasNoOwner = "org.freedesktop.DBus.Error.NameHasNoOwner"
	errServiceUnknown = "org.freedesktop.DBus.Error.ServiceUnknown"

	// Serials above it are the proxy's own messages to the bus, as in xdg-dbus-proxy
	maxClientSerial = ^uint32(0) - 65536
)

// The messages the proxy makes up. Serials are set when they're encoded

// An error reply as xdg-dbus-proxy makes them: no sender, the error's name as its message
func errorReply(replySerial uint32, name string) *dbus.Message {
	return &dbus.Message{
		Type:  dbus.TypeError,
		Flags: dbus.FlagNoReplyExpected,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldReplySerial: dbus.MakeVariant(replySerial),
			dbus.FieldErrorName:   dbus.MakeVariant(name),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf("")),
		},
		Body: []any{name},
	}
}

func boolReply(replySerial uint32, v bool) *dbus.Message {
	return &dbus.Message{
		Type:  dbus.TypeMethodReply,
		Flags: dbus.FlagNoReplyExpected,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldReplySerial: dbus.MakeVariant(replySerial),
			dbus.FieldSignature:   dbus.MakeVariant(dbus.SignatureOf(true)),
		},
		Body: []any{v},
	}
}

// What a refused call becomes on its way to the bus, with the call's serial and flags: the bus's reply to it keeps
// replies in the bus's order, and the proxy swaps it for the refusal
func ping(flags dbus.Flags) *dbus.Message {
	return &dbus.Message{
		Type:  dbus.TypeMethodCall,
		Flags: flags,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldDestination: dbus.MakeVariant(busName),
			dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/")),
			dbus.FieldInterface:   dbus.MakeVariant("org.freedesktop.DBus.Peer"),
			dbus.FieldMember:      dbus.MakeVariant("Ping"),
		},
	}
}

// A call of the proxy's own to the bus
func busCall(member string, args ...any) *dbus.Message {
	m := &dbus.Message{
		Type: dbus.TypeMethodCall,
		Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldDestination: dbus.MakeVariant(busName),
			dbus.FieldPath:        dbus.MakeVariant(busPath),
			dbus.FieldInterface:   dbus.MakeVariant(busIface),
			dbus.FieldMember:      dbus.MakeVariant(member),
		},
		Body: args,
	}
	if len(args) > 0 {
		m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(args...))
	}
	return m
}

// The match rule that tells the proxy who owns a name
func ownerMatch(name string) string {
	return "type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged'," +
		"arg0='" + name + "'"
}

func encodeNew(m *dbus.Message, serial uint32) ([]byte, error) {
	return encodeWith(m, binary.LittleEndian, serial, nil)
}

// Whether a match rule asks for messages not addressed to the client: any "eavesdrop" followed by "=", as
// xdg-dbus-proxy's is_eavesdrop has it, which also refuses eavesdrop='false'
func isEavesdrop(rule string) bool {
	for i := 0; ; {
		j := indexFrom(rule, "eavesdrop", i)
		if j < 0 {
			return false
		}
		k := j + len("eavesdrop")
		for k < len(rule) && (rule[k] == ' ' || rule[k] == '\t' || rule[k] == '\n' || rule[k] == '\r') {
			k++
		}
		if k < len(rule) && rule[k] == '=' {
			return true
		}
		i = j + 1
	}
}

func indexFrom(s, sub string, from int) int {
	for i := from; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
