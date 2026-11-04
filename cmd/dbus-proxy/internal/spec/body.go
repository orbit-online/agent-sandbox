package spec

import (
	"encoding/binary"
	"fmt"
)

// Bodies ("Marshaling"): the values of the signature in order, each aligned to its type, padding nul, booleans 0 or
// 1, strings UTF-8 with a nul after them, arrays at most 64 MiB, a variant's signature a single complete type, file
// descriptors indexes below the message's UNIX_FDS, and containers, variants included, nested at most 64 deep

const MaxDepth = 64

// CheckBody checks a message's body against its SIGNATURE field: none means an empty body
func CheckBody(m *Message) error {
	sig := ""
	if f, ok := m.Field(FieldSignature); ok && f.Sig == "g" {
		sig = f.Str
	}
	var nfds uint32
	if f, ok := m.Field(FieldUnixFDs); ok && f.Sig == "u" {
		nfds = f.U32
	}
	return CheckValues(m.Order, sig, m.Body, nfds)
}

// CheckValues checks that body holds exactly the values of sig, a valid signature, marshalled in order (the body
// starts 8-aligned)
func CheckValues(order binary.ByteOrder, sig string, body []byte, nfds uint32) error {
	if Signature(sig) == Invalid {
		return fmt.Errorf("signature %q", sig)
	}
	r := &reader{b: body, order: order, nfds: nfds}
	for rest := sig; rest != ""; {
		t := firstType(rest)
		if err := r.value(t, 0); err != nil {
			return err
		}
		rest = rest[len(t):]
	}
	if r.pos != len(body) {
		return fmt.Errorf("%d bytes after the values", len(body)-r.pos)
	}
	return nil
}

// The first single complete type of a valid signature
func firstType(s string) string {
	switch s[0] {
	case 'a':
		return s[:1+len(firstType(s[1:]))]
	case '(', '{':
		depth := 0
		for i := 0; i < len(s); i++ {
			switch s[i] {
			case '(', '{':
				depth++
			case ')', '}':
				depth--
				if depth == 0 {
					return s[:i+1]
				}
			}
		}
	}
	return s[:1]
}

func alignment(c byte) int {
	switch c {
	case 'y', 'g', 'v':
		return 1
	case 'n', 'q':
		return 2
	case 'x', 't', 'd', '(', '{':
		return 8
	}
	return 4
}

// One value of single complete type t, depth containers deep
func (r *reader) value(t string, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("nested past %d", MaxDepth)
	}
	c := t[0]
	if err := r.pad(alignment(c)); err != nil {
		return err
	}
	switch c {
	case 'y':
		return r.skip(1)
	case 'n', 'q':
		return r.skip(2)
	case 'i', 'u':
		return r.skip(4)
	case 'x', 't', 'd':
		return r.skip(8)
	case 'b':
		v, err := r.u32()
		if err == nil && v > 1 {
			err = fmt.Errorf("boolean %d", v)
		}
		return err
	case 'h':
		v, err := r.u32()
		if err == nil && v >= r.nfds {
			err = fmt.Errorf("file descriptor %d of %d", v, r.nfds)
		}
		return err
	case 's':
		_, err := r.str()
		return err
	case 'o':
		s, err := r.str()
		if err == nil && !Path(s) {
			err = fmt.Errorf("object path %q", s)
		}
		return err
	case 'g':
		s, err := r.sig()
		if err == nil && Signature(s) == Invalid {
			err = fmt.Errorf("signature %q", s)
		}
		return err
	case 'v':
		s, err := r.sig()
		if err != nil {
			return err
		}
		if SingleType(s) == Invalid {
			return fmt.Errorf("variant signature %q", s)
		}
		return r.value(s, depth+1)
	case 'a':
		n, err := r.u32()
		if err != nil {
			return err
		}
		if n > MaxArray {
			return fmt.Errorf("array of %d bytes", n)
		}
		elem := t[1:]
		if err := r.pad(alignment(elem[0])); err != nil {
			return err
		}
		if err := r.need(int(n)); err != nil {
			return err
		}
		end := r.pos + int(n)
		for r.pos < end {
			if err := r.value(elem, depth+1); err != nil {
				return err
			}
		}
		if r.pos != end {
			return fmt.Errorf("array elements overrun its length")
		}
		return nil
	case '(', '{':
		inner := t[1 : len(t)-1]
		for inner != "" {
			ft := firstType(inner)
			if err := r.value(ft, depth+1); err != nil {
				return err
			}
			inner = inner[len(ft):]
		}
		return nil
	}
	return fmt.Errorf("type %q", t)
}

func (r *reader) skip(n int) error {
	if err := r.need(n); err != nil {
		return err
	}
	r.pos += n
	return nil
}
