package wire

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// One header field as it goes on the wire, little-endian: its code, the variant's signature and value
type rawField struct {
	code byte
	sig  byte
	val  any // string, or uint32 for 'u'
}

// A message of type typ with exactly these header fields and no body, serial 1
func rawMessage(typ dbus.Type, fields ...rawField) []byte {
	var h []byte
	for i, f := range fields {
		if i > 0 {
			for len(h)%8 != 0 {
				h = append(h, 0)
			}
		}
		h = append(h, f.code, 1, f.sig, 0)
		switch v := f.val.(type) {
		case uint32:
			h = binary.LittleEndian.AppendUint32(h, v)
		case string:
			if f.sig == 'g' {
				h = append(append(append(h, byte(len(v))), v...), 0)
				continue
			}
			h = append(append(binary.LittleEndian.AppendUint32(h, uint32(len(v))), v...), 0)
		}
	}
	out := []byte{'l', byte(typ), 0, 1, 0, 0, 0, 0, 1, 0, 0, 0}
	out = binary.LittleEndian.AppendUint32(out, uint32(len(h)))
	out = append(out, h...)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	return out
}

var (
	pathField   = rawField{byte(dbus.FieldPath), 'o', "/a"}
	memberField = rawField{byte(dbus.FieldMember), 's', "M"}
)

// What the header checks refuse, each on its own: a field twice, a known field of the wrong type (an object path
// where a string goes, laid out alike), an unknown field, and what godbus's IsValid checks (the required fields,
// names). A well-formed call passes, as the control
func TestHeaderChecks(t *testing.T) {
	if _, err := Parse(rawMessage(dbus.TypeMethodCall, pathField, memberField)); err != nil {
		t.Fatalf("Control: %v", err)
	}
	for what, raw := range map[string][]byte{
		"a field twice":      rawMessage(dbus.TypeMethodCall, pathField, memberField, rawField{byte(dbus.FieldMember), 's', "N"}),
		"the wrong type":     rawMessage(dbus.TypeMethodCall, pathField, rawField{byte(dbus.FieldMember), 'o', "M"}),
		"an unknown field":   rawMessage(dbus.TypeMethodCall, pathField, memberField, rawField{10, 's', "x"}),
		"no member":          rawMessage(dbus.TypeMethodCall, pathField),
		"a signal's no path": rawMessage(dbus.TypeSignal, memberField, rawField{byte(dbus.FieldInterface), 's', "a.b"}),
		"an invalid member":  rawMessage(dbus.TypeMethodCall, pathField, rawField{byte(dbus.FieldMember), 's', "1M"}),
		"an invalid path":    rawMessage(dbus.TypeMethodCall, rawField{byte(dbus.FieldPath), 'o', "/a/"}, memberField),
		"an invalid error":   rawMessage(dbus.TypeError, rawField{byte(dbus.FieldReplySerial), 'u', uint32(1)}, rawField{byte(dbus.FieldErrorName), 's', "nodots"}),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("A header with %s parsed", what)
		}
	}
}

// Encoding stops at MaxMessageSize, the cap a forwarded message keeps too
func TestEncodeCap(t *testing.T) {
	m := hello()
	m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(""))
	m.Body = []any{strings.Repeat("x", MaxMessageSize)}
	if _, err := Encode(m, 1); err == nil {
		t.Error("A message past the cap encoded")
	}
	m.Body = []any{strings.Repeat("x", MaxMessageSize-1024)}
	if _, err := Encode(m, 1); err != nil {
		t.Errorf("A message under the cap: %v", err)
	}
}

// DecodeBody decodes nothing past its limit
func TestDecodeLimit(t *testing.T) {
	m := hello()
	m.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(""))
	m.Body = []any{strings.Repeat("x", 100)}
	data, err := Encode(m, 1)
	if err != nil {
		t.Fatal(err)
	}
	for limit, want := range map[int]bool{104: false, 105: true} {
		w, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		if got := w.DecodeBody(limit); got != want {
			t.Errorf("A 105-byte body with limit %d: decoded %v", limit, got)
		}
	}
}

// Padding is nul: between header fields, and between the header and the body
func TestPaddingNul(t *testing.T) {
	// The path field ends at 16+4+4+3 = 27, padded to 32 before the member; the member's ends at 32+4+4+2 = 42,
	// padded to 48 before the body
	ok := rawMessage(dbus.TypeMethodCall, pathField, memberField)
	if _, err := Parse(ok); err != nil {
		t.Fatalf("Control: %v", err)
	}
	for _, at := range []int{29, 45} {
		raw := append([]byte(nil), ok...)
		raw[at] = 1
		if _, err := Parse(raw); err == nil {
			t.Errorf("Padding byte %d not nul, parsed", at)
		}
	}
}
