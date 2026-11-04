package gen

import (
	"encoding/binary"

	"pgregory.net/rapid"
)

// Field is one header field to write: its code, the variant's signature, and its value as that signature lays it out
// (Str for s, o and g, U32 for u, Raw for anything else)
type Field struct {
	Code byte
	Sig  string
	Str  string
	U32  uint32
	Raw  []byte
}

// Msg is a message to write as it stands, whatever the specification says of it
type Msg struct {
	Big    bool // Big-endian
	Type   byte
	Flags  byte
	Serial uint32
	Fields []Field
	Body   []byte
}

// Order is the byte order the message is written in
func (m *Msg) Order() Order {
	if m.Big {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Encode lays the message out on the wire: the fixed header, the fields each 8-aligned, padding, the body
func (m *Msg) Encode() []byte {
	order := m.Order()
	end := byte('l')
	if m.Big {
		end = 'B'
	}
	w := &writer{order: order, b: []byte{end, m.Type, m.Flags, 1}}
	w.b = order.AppendUint32(w.b, uint32(len(m.Body)))
	w.b = order.AppendUint32(w.b, m.Serial)
	w.b = order.AppendUint32(w.b, 0)
	for _, f := range m.Fields {
		w.pad(8)
		w.b = append(w.b, f.Code)
		w.sig(f.Sig)
		switch f.Sig {
		case "s", "o":
			w.str(f.Str)
		case "g":
			w.sig(f.Str)
		case "u":
			w.u32(f.U32)
		default:
			w.b = append(w.b, f.Raw...)
		}
	}
	order.PutUint32(w.b[12:16], uint32(len(w.b)-16))
	w.pad(8)
	return append(w.b, m.Body...)
}

// The known fields' types
var fieldSig = map[byte]string{1: "o", 2: "s", 3: "s", 4: "s", 5: "u", 6: "s", 7: "s", 8: "g", 9: "u"}

// Str is the field's string value, "" when it's missing
func (m *Msg) Str(code byte) string {
	for _, f := range m.Fields {
		if f.Code == code {
			return f.Str
		}
	}
	return ""
}

// Set replaces or adds a field
func (m *Msg) Set(f Field) {
	for i := range m.Fields {
		if m.Fields[i].Code == f.Code {
			m.Fields[i] = f
			return
		}
	}
	m.Fields = append(m.Fields, f)
}

// StrField and U32Field are a known field of its own type
func StrField(code byte, v string) Field { return Field{Code: code, Sig: fieldSig[code], Str: v} }
func U32Field(code byte, v uint32) Field { return Field{Code: code, Sig: "u", U32: v} }

// Perturb breaks a message's header the way a near miss does, now and then: a required field dropped, a field twice,
// a known field of another type (laid out alike or not), an unknown field code, an unknown type or flag, version or
// byte order. Returns whether it changed anything
func Perturb(t *rapid.T, m *Msg) bool {
	if rapid.IntRange(0, 4).Draw(t, "perturb") > 0 || len(m.Fields) == 0 {
		return false
	}
	i := rapid.IntRange(0, len(m.Fields)-1).Draw(t, "field")
	f := m.Fields[i]
	switch rapid.IntRange(0, 6).Draw(t, "how") {
	case 0:
		m.Fields = append(m.Fields[:i:i], m.Fields[i+1:]...)
	case 1:
		m.Fields = append(m.Fields, f)
	case 2:
		// Another type: strings and object paths are laid out alike, so only the type tells them apart
		other := map[string]string{"s": "o", "o": "s", "g": "s", "u": "s"}[f.Sig]
		g := Field{Code: f.Code, Sig: other, Str: f.Str}
		if other == "s" && f.Sig == "u" {
			g.Str = "1"
		}
		m.Fields[i] = g
	case 3:
		m.Fields = append(m.Fields, Field{Code: byte(rapid.IntRange(10, 255).Draw(t, "code")),
			Sig: rapid.SampledFrom([]string{"s", "u", "y"}).Draw(t, "sig"), Str: "x", Raw: []byte{7}})
	case 4:
		m.Type = byte(rapid.SampledFrom([]int{0, 5, 200}).Draw(t, "type"))
	case 5:
		m.Flags |= byte(rapid.SampledFrom([]int{0x8, 0x40, 0x80}).Draw(t, "flag"))
	case 6:
		m.Fields[i] = Field{Code: f.Code, Sig: "y", Raw: []byte{1}}
	}
	return true
}

// Args sets the body to the given arguments, strings, uint32s and string arrays, with their signature
func (m *Msg) Args(args ...any) {
	w := &writer{order: m.Order()}
	sig := ""
	for _, a := range args {
		switch v := a.(type) {
		case string:
			sig += "s"
			w.str(v)
		case uint32:
			sig += "u"
			w.u32(v)
		case []string:
			sig += "as"
			w.u32(0)
			at := len(w.b) - 4
			start := len(w.b)
			for _, s := range v {
				w.str(s)
			}
			w.order.PutUint32(w.b[at:], uint32(len(w.b)-start))
		}
	}
	m.Body = w.b
	m.Set(StrField(8, sig))
}
