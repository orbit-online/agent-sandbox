package spec

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

// Messages ("Message Format"): a fixed header of 16 bytes (byte order, type, flags, version 1, body length, serial),
// an array of (byte, variant) header fields, padding to 8, then the body. Padding is nul throughout

// Message types and flags
const (
	TypeCall   = 1
	TypeReturn = 2
	TypeError  = 3
	TypeSignal = 4

	FlagNoReplyExpected  = 0x1
	FlagNoAutoStart      = 0x2
	FlagAllowInteractive = 0x4
	KnownFlags           = FlagNoReplyExpected | FlagNoAutoStart | FlagAllowInteractive
)

// Header field codes
const (
	FieldPath        = 1
	FieldInterface   = 2
	FieldMember      = 3
	FieldErrorName   = 4
	FieldReplySerial = 5
	FieldDestination = 6
	FieldSender      = 7
	FieldSignature   = 8
	FieldUnixFDs     = 9
)

// The type each known field must have
var FieldTypes = map[byte]string{
	FieldPath: "o", FieldInterface: "s", FieldMember: "s", FieldErrorName: "s", FieldReplySerial: "u",
	FieldDestination: "s", FieldSender: "s", FieldSignature: "g", FieldUnixFDs: "u",
}

// The fields each known type requires
var Required = map[byte][]byte{
	TypeCall:   {FieldPath, FieldMember},
	TypeReturn: {FieldReplySerial},
	TypeError:  {FieldErrorName, FieldReplySerial},
	TypeSignal: {FieldPath, FieldInterface, FieldMember},
}

const (
	MaxMessage = 1 << 27
	MaxArray   = 1 << 26
)

// Field: one header field as read, its variant's signature and value (a string, or uint32 for "u", nil otherwise)
type Field struct {
	Code byte
	Sig  string
	Str  string
	U32  uint32
}

// Message: one message as read. Fields keeps every field in order, duplicates included
type Message struct {
	Order    binary.ByteOrder
	Type     byte
	Flags    byte
	Serial   uint32
	Fields   []Field
	Body     []byte
	Len      int // The bytes the message took in the stream
	HeadSize int // Fixed header and fields, before the padding to the body
}

// Field returns the first field with code, and whether there is one
func (m *Message) Field(code byte) (Field, bool) {
	for _, f := range m.Fields {
		if f.Code == code {
			return f, true
		}
	}
	return Field{}, false
}

// Str is a string field's value, "" when it's missing
func (m *Message) Str(code byte) string {
	f, _ := m.Field(code)
	return f.Str
}

// Framing: whether a stream holds a whole message, too few bytes for one yet, or bytes no reading of can make one
type Framing int

const (
	Whole Framing = iota
	Short
	Broken
)

// Frame reads the first message's frame in stream: the fixed header and the lengths. A message within maxLen
// bytes; Broken with the reason otherwise
func Frame(stream []byte, maxLen int) (Framing, int, string) {
	if len(stream) < 16 {
		return Short, 0, ""
	}
	var order binary.ByteOrder
	switch stream[0] {
	case 'l':
		order = binary.LittleEndian
	case 'B':
		order = binary.BigEndian
	default:
		return Broken, 0, "byte order"
	}
	if stream[3] != 1 {
		return Broken, 0, "protocol version"
	}
	total := align(16+uint64(order.Uint32(stream[12:16])), 8) + uint64(order.Uint32(stream[4:8]))
	if total > uint64(maxLen) {
		return Broken, 0, "too long"
	}
	if uint64(len(stream)) < total {
		return Short, int(total), ""
	}
	return Whole, int(total), ""
}

func align(n, a uint64) uint64 { return (n + a - 1) / a * a }

// Read parses one whole message (Frame said Whole) and checks its header against the specification. The body is
// checked apart (CheckBody): a bus reads it, the proxy passes it as it came
func Read(raw []byte) (*Message, error) {
	order := binary.ByteOrder(binary.LittleEndian)
	if raw[0] == 'B' {
		order = binary.BigEndian
	}
	m := &Message{Order: order, Type: raw[1], Flags: raw[2], Serial: order.Uint32(raw[8:12]), Len: len(raw)}
	fieldsLen := int(order.Uint32(raw[12:16]))
	end := 16 + fieldsLen
	m.HeadSize = end
	bodyStart := int(align(uint64(end), 8))
	m.Body = raw[bodyStart:]
	if fieldsLen > MaxArray {
		return m, fmt.Errorf("header fields past the array limit")
	}
	if err := nulPadding(raw[end:bodyStart]); err != nil {
		return m, err
	}
	r := &reader{b: raw[:end], pos: 16, order: order}
	for r.pos < end {
		if err := r.pad(8); err != nil {
			return m, err
		}
		f, err := r.field()
		if err != nil {
			return m, err
		}
		m.Fields = append(m.Fields, f)
	}
	return m, m.checkHeader()
}

func nulPadding(b []byte) error {
	for _, c := range b {
		if c != 0 {
			return fmt.Errorf("padding not nul")
		}
	}
	return nil
}

// The fixed header and the header fields by the specification's rules
func (m *Message) checkHeader() error {
	if m.Type == 0 {
		return fmt.Errorf("type 0")
	}
	if m.Serial == 0 {
		return fmt.Errorf("serial 0")
	}
	seen := map[byte]bool{}
	for _, f := range m.Fields {
		want, known := FieldTypes[f.Code]
		if !known {
			continue
		}
		// libdbus refuses a known field twice (DBUS_INVALID_HEADER_FIELD_APPEARS_TWICE); the specification's
		// table has one value per field
		if seen[f.Code] {
			return fmt.Errorf("field %d twice", f.Code)
		}
		seen[f.Code] = true
		if f.Sig != want {
			return fmt.Errorf("field %d of type %q", f.Code, f.Sig)
		}
		if err := checkField(f); err != nil {
			return err
		}
	}
	for _, code := range Required[m.Type] {
		if !seen[code] {
			return fmt.Errorf("type %d without field %d", m.Type, code)
		}
	}
	return nil
}

func checkField(f Field) error {
	ok := true
	switch f.Code {
	case FieldPath:
		ok = Path(f.Str) && f.Str != LocalPath
	case FieldInterface:
		ok = Interface(f.Str) && f.Str != LocalInterface
	case FieldMember:
		ok = Member(f.Str)
	case FieldErrorName:
		ok = ErrorName(f.Str)
	case FieldDestination, FieldSender:
		ok = BusName(f.Str)
	case FieldSignature:
		ok = Signature(f.Str) == Valid
	}
	if !ok {
		return fmt.Errorf("field %d: %q", f.Code, f.Str)
	}
	return nil
}

// A reader of marshalled values
type reader struct {
	b     []byte
	pos   int
	order binary.ByteOrder
	depth int
	nfds  uint32
}

func (r *reader) pad(a int) error {
	next := int(align(uint64(r.pos), uint64(a)))
	if next > len(r.b) {
		return fmt.Errorf("padding past the end")
	}
	if err := nulPadding(r.b[r.pos:next]); err != nil {
		return err
	}
	r.pos = next
	return nil
}

func (r *reader) need(n int) error {
	if n < 0 || r.pos+n > len(r.b) {
		return fmt.Errorf("value past the end")
	}
	return nil
}

func (r *reader) u32() (uint32, error) {
	if err := r.pad(4); err != nil {
		return 0, err
	}
	if err := r.need(4); err != nil {
		return 0, err
	}
	v := r.order.Uint32(r.b[r.pos:])
	r.pos += 4
	return v, nil
}

// n bytes, a nul after them, valid UTF-8 without nuls
func (r *reader) text(n int) (string, error) {
	if err := r.need(n + 1); err != nil {
		return "", err
	}
	s := r.b[r.pos : r.pos+n]
	if r.b[r.pos+n] != 0 {
		return "", fmt.Errorf("string not nul-terminated")
	}
	for _, c := range s {
		if c == 0 {
			return "", fmt.Errorf("nul in a string")
		}
	}
	if !utf8.Valid(s) {
		return "", fmt.Errorf("string not UTF-8")
	}
	r.pos += n + 1
	return string(s), nil
}

func (r *reader) str() (string, error) {
	n, err := r.u32()
	if err != nil {
		return "", err
	}
	return r.text(int(n))
}

func (r *reader) sig() (string, error) {
	if err := r.need(1); err != nil {
		return "", err
	}
	n := int(r.b[r.pos])
	r.pos++
	return r.text(n)
}

// One header field: its code, a variant of one single complete type, its value. A known field's value is read by
// its own type; an unknown field's value is read by its signature, which must be valid
func (r *reader) field() (Field, error) {
	if err := r.need(1); err != nil {
		return Field{}, err
	}
	f := Field{Code: r.b[r.pos]}
	r.pos++
	sig, err := r.sig()
	if err != nil {
		return f, err
	}
	f.Sig = sig
	if SingleType(sig) == Invalid {
		return f, fmt.Errorf("field %d: variant signature %q", f.Code, sig)
	}
	switch sig {
	case "s", "o":
		f.Str, err = r.str()
	case "g":
		f.Str, err = r.sig()
	case "u":
		f.U32, err = r.u32()
	default:
		err = r.value(sig, 1)
	}
	return f, err
}
