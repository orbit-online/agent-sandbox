package wire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

// godbus's decoder takes bodies the D-Bus specification refuses: trailing bytes, padding that isn't nul, booleans
// past 1, strings with a nul or invalid UTF-8. A body the proxy looks into must be what godbus's encoder writes for the
// values it read, and its strings valid, or the proxy reads no arguments from it, as if it had none

// Whether body, decoded into values under sig, is exactly their encoding, with every string valid
func canonical(order binary.ByteOrder, sig dbus.Signature, values []any, body []byte) bool {
	for _, v := range values {
		if !validStrings(v) {
			return false
		}
	}
	m := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
		dbus.FieldPath:      dbus.MakeVariant(dbus.ObjectPath("/")),
		dbus.FieldInterface: dbus.MakeVariant("a.b"),
		dbus.FieldMember:    dbus.MakeVariant("C"),
		dbus.FieldSignature: dbus.MakeVariant(sig),
	}, Body: values}
	var buf bytes.Buffer
	if _, err := m.EncodeToWithFDs(&buf, order); err != nil {
		return false
	}
	out := buf.Bytes()
	n := int(order.Uint32(out[4:8]))
	return n == len(body) && bytes.Equal(out[len(out)-n:], body)
}

func validString(s string) bool { return utf8.ValidString(s) && !strings.Contains(s, "\x00") }

// Every string, object path and signature in a decoded value is valid UTF-8 without a nul
func validStrings(v any) bool {
	switch x := v.(type) {
	case string:
		return validString(x)
	case dbus.ObjectPath:
		return validString(string(x))
	case dbus.Signature:
		return validString(x.String())
	case dbus.Variant:
		return validString(x.Signature().String()) && validStrings(x.Value())
	case []string:
		for _, s := range x {
			if !validString(s) {
				return false
			}
		}
	case []any:
		for _, e := range x {
			if !validStrings(e) {
				return false
			}
		}
	case []dbus.Variant:
		for _, e := range x {
			if !validStrings(e) {
				return false
			}
		}
	case map[string]dbus.Variant:
		for k, e := range x {
			if !validString(k) || !validStrings(e) {
				return false
			}
		}
	}
	return true
}
