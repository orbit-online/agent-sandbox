package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

// parseHeader against godbus's decoder, which reads the same fields as the body of a message of its own: a body of
// signature (ua(yv)) puts the array at the offsets it has in a header, so alignment works out the same. Whatever
// parseHeader takes, godbus reads alike; whatever godbus reads that has only known fields of their type, once each,
// with strings of valid UTF-8 and no nul, parseHeader takes too, unless a string's terminator isn't a nul, which
// godbus doesn't check. Run longer with go test -run '^$' -fuzz FuzzParseHeader -fuzztime 30s
func FuzzParseHeader(f *testing.F) {
	for _, m := range []*dbus.Message{
		{Type: dbus.TypeMethodCall, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath:        dbus.MakeVariant(dbus.ObjectPath("/org/freedesktop/DBus")),
			dbus.FieldDestination: dbus.MakeVariant("org.freedesktop.DBus"), dbus.FieldInterface: dbus.MakeVariant("org.freedesktop.DBus"),
			dbus.FieldMember: dbus.MakeVariant("GetNameOwner"), dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf(""))},
			Body: []any{"org.test.A"}},
		{Type: dbus.TypeError, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldReplySerial: dbus.MakeVariant(uint32(7)), dbus.FieldErrorName: dbus.MakeVariant("org.test.Error")}},
		{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath: dbus.MakeVariant(dbus.ObjectPath("/a/b")), dbus.FieldInterface: dbus.MakeVariant("a.b"),
			dbus.FieldMember: dbus.MakeVariant("C"), dbus.FieldSender: dbus.MakeVariant(":1.5"),
			dbus.FieldUnixFDs: dbus.MakeVariant(uint32(1))}}} {
		data, err := Encode(m, 1)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(false, data[16:16+binary.LittleEndian.Uint32(data[12:16])])
	}
	f.Fuzz(func(t *testing.T, big bool, fields []byte) {
		var order binary.ByteOrder = binary.LittleEndian
		raw := []byte{'l', byte(dbus.TypeSignal), 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}
		if big {
			order, raw[0] = binary.BigEndian, 'B'
		}
		order.PutUint32(raw[12:16], uint32(len(fields)))
		raw = append(raw, fields...)
		ours, err := parseHeader(raw, order, len(raw))

		body := append([]byte{0, 0, 0, 0}, raw[12:]...)
		carrier := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath:      dbus.MakeVariant(dbus.ObjectPath("/")),
			dbus.FieldInterface: dbus.MakeVariant("a.b"),
			dbus.FieldMember:    dbus.MakeVariant("C"),
			dbus.FieldSignature: dbus.MakeVariant(dbus.ParseSignatureMust("(ua(yv))")),
		}}
		data, eerr := encodeWith(carrier, order, 1, body)
		if eerr != nil {
			t.Skip("Too long to carry")
		}
		var theirs [][]any
		msg, gerr := decode(data)
		if gerr == nil {
			theirs = msg.Body[0].([]any)[1].([][]any)
		}

		if err == nil {
			if gerr != nil {
				t.Fatalf("parseHeader took what godbus refuses (%v): %x", gerr, fields)
			}
			if len(theirs) != len(ours) {
				t.Fatalf("parseHeader read %d fields, godbus %d: %x", len(ours), len(theirs), fields)
			}
			for _, f := range theirs {
				v, ok := ours[dbus.HeaderField(f[0].(byte))]
				g := f[1].(dbus.Variant)
				if !ok || v.Signature() != g.Signature() || !reflect.DeepEqual(v.Value(), g.Value()) {
					t.Fatalf("Field %d: parseHeader read %v, godbus %v: %x", f[0], v, g, fields)
				}
			}
			return
		}
		if gerr != nil || errors.Is(err, errUnterminated) {
			return
		}
		seen := map[dbus.HeaderField]bool{}
		for _, f := range theirs {
			code, v := dbus.HeaderField(f[0].(byte)), f[1].(dbus.Variant)
			want, known := fieldSigs[code]
			if !known || seen[code] || v.Signature().String() != string(want) {
				return
			}
			seen[code] = true
			var s string
			switch x := v.Value().(type) {
			case string:
				s = x
			case dbus.ObjectPath:
				s = string(x)
			case dbus.Signature:
				s = x.String()
			}
			if !utf8.ValidString(s) || bytes.IndexByte([]byte(s), 0) >= 0 {
				return
			}
		}
		t.Fatalf("parseHeader refused what godbus read cleanly (%v): %x", err, fields)
	})
}
