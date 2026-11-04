package gen

import (
	"encoding/binary"

	"pgregory.net/rapid"
)

// Mutate changes an encoded message at the byte level: bits flipped, the message cut short, a length field lying
// (the body's or the header fields', smaller or larger, or huge), a serial of 0, bytes appended
func Mutate(t *rapid.T, raw []byte) []byte {
	out := append([]byte(nil), raw...)
	var order binary.ByteOrder = binary.LittleEndian
	if out[0] == 'B' {
		order = binary.BigEndian
	}
	switch rapid.IntRange(0, 5).Draw(t, "mutation") {
	case 0:
		for range rapid.IntRange(1, 4).Draw(t, "flips") {
			i := rapid.IntRange(0, len(out)-1).Draw(t, "at")
			out[i] ^= 1 << rapid.IntRange(0, 7).Draw(t, "bit")
		}
	case 1:
		return out[:rapid.IntRange(1, len(out)-1).Draw(t, "cut")]
	case 2:
		at := rapid.SampledFrom([]int{4, 12}).Draw(t, "length")
		v := order.Uint32(out[at:])
		switch rapid.IntRange(0, 2).Draw(t, "lie") {
		case 0:
			v += uint32(rapid.IntRange(1, 64).Draw(t, "more"))
		case 1:
			v -= min(v, uint32(rapid.IntRange(1, 64).Draw(t, "less")))
		default:
			v = rapid.SampledFrom([]uint32{4<<20 - 16, 4 << 20, 1 << 27, ^uint32(0)}).Draw(t, "huge")
		}
		order.PutUint32(out[at:], v)
	case 3:
		order.PutUint32(out[8:], 0)
	case 4:
		out = append(out, rapid.SliceOfN(rapid.Byte(), 1, 24).Draw(t, "tail")...)
	case 5:
		out[rapid.IntRange(0, len(out)-1).Draw(t, "at")] = rapid.Byte().Draw(t, "byte")
	}
	return out
}
