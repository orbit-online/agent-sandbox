package gen

import (
	"encoding/binary"
	"strings"

	"pgregory.net/rapid"
)

// Order is a byte order to write in: binary.LittleEndian or binary.BigEndian
type Order interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

// A writer of marshalled values, its offsets those of a body (8-aligned at 0)
type writer struct {
	b     []byte
	order Order
}

func (w *writer) pad(a int) {
	for len(w.b)%a != 0 {
		w.b = append(w.b, 0)
	}
}

func (w *writer) u32(v uint32) {
	w.pad(4)
	w.b = w.order.AppendUint32(w.b, v)
}

func (w *writer) str(s string) {
	w.u32(uint32(len(s)))
	w.b = append(append(w.b, s...), 0)
}

func (w *writer) sig(s string) {
	w.b = append(append(append(w.b, byte(len(s))), s...), 0)
}

func alignOf(c byte) int {
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

// A string for a body: short text, UTF-8 beyond ASCII among it
func text(t *rapid.T) string {
	return rapid.SampledFrom([]string{"", "x", "token", "héllo", "日本", strings.Repeat("z", 300)}).Draw(t, "text")
}

// value writes one value of single complete type typ; variants nest at most depth more, and arrays below the third
// level hold at most one element, so a deep signature's body stays small
func (w *writer) value(t *rapid.T, typ string, depth int) { w.valueIn(t, typ, depth, 0) }

func (w *writer) valueIn(t *rapid.T, typ string, depth, arrays int) {
	c := typ[0]
	w.pad(alignOf(c))
	switch c {
	case 'y':
		w.b = append(w.b, byte(rapid.IntRange(0, 255).Draw(t, "y")))
	case 'n', 'q':
		w.b = w.order.AppendUint16(w.b, uint16(rapid.IntRange(0, 65535).Draw(t, "n")))
	case 'i', 'u', 'h':
		w.u32(rapid.Uint32().Draw(t, "u"))
	case 'b':
		w.u32(uint32(rapid.IntRange(0, 1).Draw(t, "b")))
	case 'x', 't', 'd':
		w.b = w.order.AppendUint64(w.b, rapid.Uint64().Draw(t, "x"))
	case 's':
		w.str(text(t))
	case 'o':
		w.str(rapid.SampledFrom([]string{"/", "/a", "/org/test/0x"}).Draw(t, "o"))
	case 'g':
		w.sig(rapid.SampledFrom([]string{"", "s", "a{sv}", "(ii)"}).Draw(t, "g"))
	case 'v':
		inner := "s"
		if depth > 0 {
			inner = singleType(t, 2)
			if strings.ContainsRune(inner, 'h') {
				inner = "s"
			}
		}
		w.sig(inner)
		w.valueIn(t, inner, depth-1, arrays)
	case 'a':
		w.u32(0)
		lenAt := len(w.b) - 4
		elem := typ[1:]
		w.pad(alignOf(elem[0]))
		start := len(w.b)
		most := 3
		if arrays >= 3 {
			most = 1
		}
		for range rapid.IntRange(0, most).Draw(t, "elems") {
			w.valueIn(t, elem, depth, arrays+1)
		}
		w.order.PutUint32(w.b[lenAt:], uint32(len(w.b)-start))
	case '(', '{':
		inner := typ[1 : len(typ)-1]
		for inner != "" {
			ft := firstType(inner)
			w.valueIn(t, ft, depth, arrays)
			inner = inner[len(ft):]
		}
	}
}

// Body: the values of a valid signature without 'h', marshalled in order
func Body(order Order, sig string) *rapid.Generator[[]byte] {
	if sig == "" {
		return rapid.Just([]byte(nil))
	}
	return rapid.Custom(func(t *rapid.T) []byte {
		w := &writer{order: order}
		for rest := sig; rest != ""; {
			ft := firstType(rest)
			w.value(t, ft, 2)
			rest = rest[len(ft):]
		}
		return w.b
	})
}

// BodyMiss: a body that contradicts its signature: cut short, with bytes after the values, a boolean of 2, a string
// without its nul or of invalid UTF-8, nonzero padding, or arbitrary bytes
func BodyMiss(order Order, sig string, body []byte) *rapid.Generator[[]byte] {
	return rapid.Custom(func(t *rapid.T) []byte {
		out := append([]byte(nil), body...)
		switch rapid.IntRange(0, 4).Draw(t, "miss") {
		case 0:
			if len(out) > 0 {
				return out[:rapid.IntRange(0, len(out)-1).Draw(t, "cut")]
			}
		case 1:
			return append(out, 0xff)
		case 2:
			if len(out) > 0 {
				out[rapid.IntRange(0, len(out)-1).Draw(t, "at")] ^= byte(rapid.IntRange(1, 255).Draw(t, "x"))
				return out
			}
		case 3:
			w := &writer{order: order, b: out}
			w.u32(2)
			return w.b
		}
		return rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(t, "junk")
	})
}
