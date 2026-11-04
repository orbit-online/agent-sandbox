package main

import (
	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/judge"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
)

// The bus driver and the errors the proxy answers with, for the tests through it
const (
	busName  = rules.BusName
	busPath  = dbus.ObjectPath("/org/freedesktop/DBus")
	busIface = "org.freedesktop.DBus"

	errAccessDenied   = judge.ErrAccessDenied
	errNameHasNoOwner = judge.ErrNameHasNoOwner
	errServiceUnknown = judge.ErrServiceUnknown
)

// A call to the bus driver
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

// The first argument when it's a string
func arg0(m *wire.Message) (string, bool) {
	if !m.DecodeBody(wire.MaxMessageSize) || len(m.Body) == 0 {
		return "", false
	}
	s, ok := m.Body[0].(string)
	return s, ok
}
