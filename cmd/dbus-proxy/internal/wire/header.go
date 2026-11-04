package wire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/godbus/dbus/v5"
)

// The header fields and the type each must have. Any other field fails the message, as in xdg-dbus-proxy
var fieldSigs = map[dbus.HeaderField]byte{
	dbus.FieldPath:        'o',
	dbus.FieldInterface:   's',
	dbus.FieldMember:      's',
	dbus.FieldErrorName:   's',
	dbus.FieldReplySerial: 'u',
	dbus.FieldDestination: 's',
	dbus.FieldSender:      's',
	dbus.FieldSignature:   'g',
	dbus.FieldUnixFDs:     'u',
}

// Parses the header fields of raw, whose fixed part was checked already. Only the header: the body stays bytes
// until something needs to look into it, so its size alone bounds what a message costs
func parseHeader(raw []byte, order binary.ByteOrder, end int) (map[dbus.HeaderField]dbus.Variant, error) {
	fields := map[dbus.HeaderField]dbus.Variant{}
	pos := 16
	for pos < end {
		if pos = skipPadding(raw, pos, int(align8(uint64(pos))), end); pos < 0 {
			return nil, errPadding
		}
		if pos+4 > end {
			return nil, errors.New("Header field past the header's end")
		}
		code := dbus.HeaderField(raw[pos])
		want, known := fieldSigs[code]
		if !known {
			return nil, fmt.Errorf("Unknown header field %d", code)
		}
		if _, dup := fields[code]; dup {
			return nil, fmt.Errorf("Header field %d twice", code)
		}
		// The variant's signature: one type code
		if raw[pos+1] != 1 || raw[pos+2] != want {
			return nil, fmt.Errorf("Header field %d has the wrong type", code)
		}
		if raw[pos+3] != 0 {
			return nil, errUnterminated
		}
		pos += 4
		var v dbus.Variant
		switch want {
		case 'u':
			if pos = skipPadding(raw, pos, int(align4(uint64(pos))), end); pos < 0 {
				return nil, errPadding
			}
			if pos+4 > end {
				return nil, errors.New("Header field past the header's end")
			}
			v = dbus.MakeVariant(order.Uint32(raw[pos:]))
			pos += 4
		case 'g':
			if pos+1 > end {
				return nil, errors.New("Header field past the header's end")
			}
			n := int(raw[pos])
			s, err := cString(raw, pos+1, n, end)
			if err != nil {
				return nil, err
			}
			sig, err := dbus.ParseSignature(s)
			if err != nil {
				return nil, fmt.Errorf("Invalid signature: %w", err)
			}
			v = dbus.MakeVariant(sig)
			pos += 1 + n + 1
		default:
			if pos = skipPadding(raw, pos, int(align4(uint64(pos))), end); pos < 0 {
				return nil, errPadding
			}
			if pos+4 > end {
				return nil, errors.New("Header field past the header's end")
			}
			n := order.Uint32(raw[pos:])
			if uint64(n) > uint64(end) {
				return nil, errors.New("Header string past the header's end")
			}
			s, err := cString(raw, pos+4, int(n), end)
			if err != nil {
				return nil, err
			}
			if want == 'o' {
				v = dbus.MakeVariant(dbus.ObjectPath(s))
			} else {
				v = dbus.MakeVariant(s)
			}
			pos += 4 + int(n) + 1
		}
		fields[code] = v
	}
	if pos != end {
		return nil, errors.New("Header fields overrun the header")
	}
	return fields, nil
}

func align4(n uint64) uint64 { return (n + 3) &^ 3 }

var errPadding = errors.New("Header padding not nul, or past the header's end")

// Skips the padding from pos to next, nul bytes before end; -1 when they aren't
func skipPadding(raw []byte, pos, next, end int) int {
	if next > end {
		return -1
	}
	for _, c := range raw[pos:next] {
		if c != 0 {
			return -1
		}
	}
	return next
}

var errUnterminated = errors.New("Header string or signature not followed by a nul")

// n bytes at pos followed by a nul, before end, valid UTF-8 without nuls
func cString(raw []byte, pos, n, end int) (string, error) {
	if pos+n+1 > end {
		return "", errors.New("Header string past the header's end")
	}
	if raw[pos+n] != 0 {
		return "", errUnterminated
	}
	s := raw[pos : pos+n]
	if bytes.IndexByte(s, 0) >= 0 || !utf8.Valid(s) {
		return "", errors.New("Header string with a nul or invalid UTF-8")
	}
	return string(s), nil
}
