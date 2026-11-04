package wire

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"pgregory.net/rapid"
)

// The reader's header checks against the specification's model (internal/spec) and the proxy's documented rules on
// top: for generated messages, valid and broken at the header or the bytes, the message is read exactly when the
// model takes it, with the fields the model reads, and refused otherwise. Bodies pass as they came either way
func TestParseAgainstSpec(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := gen.Message(gen.GrammarNames(), rapid.Uint32()).Draw(t, "msg")
		m.Serial = rapid.SampledFrom([]uint32{1, 2, 0x7fffffff, ^uint32(0)}).Draw(t, "serial")
		raw := m.Encode()
		if rapid.IntRange(0, 3).Draw(t, "mutate") == 0 {
			raw = gen.Mutate(t, raw)
		}
		outcome, want, why := spec.ProxyReads(raw, 0)
		if outcome == spec.Waiting {
			return
		}
		n := len(raw)
		if want != nil {
			n = want.Len
		}
		got, err := Parse(raw[:n])
		switch {
		case outcome == spec.Closed && err == nil:
			t.Fatalf("Read what the model refuses (%s): %x", why, raw[:min(n, 512)])
		case outcome == spec.Judged && err != nil:
			t.Fatalf("Refused what the model takes (%v): %x", err, raw[:min(n, 512)])
		case err != nil:
			return
		}
		if byte(got.Type) != want.Type || byte(got.Flags) != want.Flags || got.Serial() != want.Serial {
			t.Fatalf("Fixed header: %v %v %d, model %d %d %d", got.Type, got.Flags, got.Serial(), want.Type, want.Flags, want.Serial)
		}
		for code, f := range map[byte]dbus.HeaderField{spec.FieldPath: dbus.FieldPath, spec.FieldInterface: dbus.FieldInterface,
			spec.FieldMember: dbus.FieldMember, spec.FieldErrorName: dbus.FieldErrorName,
			spec.FieldDestination: dbus.FieldDestination, spec.FieldSender: dbus.FieldSender} {
			if got.Header(f) != want.Str(code) {
				t.Fatalf("Field %d: %q, model %q", code, got.Header(f), want.Str(code))
			}
		}
		if rs, ok := got.ReplySerial(); ok != hasField(want, spec.FieldReplySerial) || ok && rs != field(want, spec.FieldReplySerial).U32 {
			t.Fatalf("Reply serial %d %v", rs, ok)
		}
	})
}

func hasField(m *spec.Message, code byte) bool { _, ok := m.Field(code); return ok }
func field(m *spec.Message, code byte) spec.Field {
	f, _ := m.Field(code)
	return f
}
