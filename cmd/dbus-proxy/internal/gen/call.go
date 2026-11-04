package gen

import (
	"pgregory.net/rapid"
)

// Names are where a message's names come from: the caller's catalog mixed with the grammar's, as it likes
type Names struct {
	Dest, Path, Iface, Member, ErrorName *rapid.Generator[string]
	// Whether a body may be about the proxy's 4 MiB cap
	Huge bool
}

// GrammarNames draws every name from the grammar
func GrammarNames() Names {
	return Names{Dest: rapid.OneOf(WellKnownName(), UniqueName()), Path: ObjectPath(), Iface: InterfaceName(),
		Member: MemberName(), ErrorName: InterfaceName(), Huge: true}
}

// Message: a method call mostly, then signals, returns and errors, with the fields its type requires and some it
// doesn't (a sender, file descriptors claimed), flags of the known three, a signature and a body that matches it four times in five, sometimes a body of
// about the proxy's 4 MiB cap; then perhaps broken at the header (Perturb). Serial 1: the caller sets its own.
// replySerials are the serials a return or error answers
func Message(n Names, replySerials *rapid.Generator[uint32]) *rapid.Generator[*Msg] {
	return rapid.Custom(func(t *rapid.T) *Msg {
		m := &Msg{Big: rapid.IntRange(0, 4).Draw(t, "big") == 0, Serial: 1}
		m.Type = byte(rapid.SampledFrom([]int{1, 1, 1, 1, 1, 1, 4, 4, 2, 3}).Draw(t, "type"))
		for _, f := range []byte{0x1, 0x2, 0x4} {
			if rapid.IntRange(0, 3).Draw(t, "flag") == 0 {
				m.Flags |= f
			}
		}
		switch m.Type {
		case 1, 4:
			m.Set(StrField(1, n.Path.Draw(t, "path")))
			if m.Type == 4 || rapid.IntRange(0, 5).Draw(t, "iface") > 0 {
				m.Set(StrField(2, n.Iface.Draw(t, "iface")))
			}
			m.Set(StrField(3, n.Member.Draw(t, "member")))
			if m.Type == 1 || rapid.Bool().Draw(t, "unicast") {
				m.Set(StrField(6, n.Dest.Draw(t, "dest")))
			}
		default:
			m.Set(U32Field(5, replySerials.Draw(t, "replySerial")))
			m.Set(StrField(6, n.Dest.Draw(t, "dest")))
			if m.Type == 3 {
				m.Set(StrField(4, n.ErrorName.Draw(t, "error")))
			}
		}
		if rapid.IntRange(0, 9).Draw(t, "sender") == 0 {
			m.Set(StrField(7, n.Dest.Draw(t, "sender")))
		}
		if rapid.IntRange(0, 9).Draw(t, "fds") == 0 {
			m.Set(U32Field(9, uint32(rapid.SampledFrom([]int{0, 1, 253, 254}).Draw(t, "nfds"))))
		}
		sig, sigOK := "", true
		if n.Huge && rapid.IntRange(0, 9).Draw(t, "huge") == 0 {
			// An array of bytes about the cap: the header's few hundred bytes decide which side it lands on
			sig = "ay"
			size := rapid.SampledFrom([]int{4<<20 - 4096, 4<<20 - 600, 4<<20 - 300, 4 << 20}).Draw(t, "size")
			w := &writer{order: m.Order()}
			w.u32(uint32(size))
			m.Body = append(w.b, make([]byte, size)...)
		} else if sigOK = rapid.IntRange(0, 5).Draw(t, "validSig") > 0; sigOK {
			sig = ValidSignature().Draw(t, "sig")
		} else {
			sig = InvalidSignature().Draw(t, "sig")
		}
		if sig != "" || rapid.IntRange(0, 9).Draw(t, "emptySig") == 0 {
			m.Set(StrField(8, sig))
		}
		if m.Body == nil {
			if sigOK {
				m.Body = Body(m.Order(), sig).Draw(t, "body")
			}
			if rapid.IntRange(0, 4).Draw(t, "bodyMiss") == 0 {
				m.Body = BodyMiss(m.Order(), sig, m.Body).Draw(t, "miss")
			}
		}
		Perturb(t, m)
		return m
	})
}
