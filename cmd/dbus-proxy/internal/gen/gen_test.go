package gen

import (
	"encoding/binary"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"pgregory.net/rapid"
)

// What the generators mean to be valid is, by the specification's model, and what they mean to break mostly is: a
// body for a valid signature matches it, a valid signature is valid, a valid name parses
func TestGeneratorsAgainstSpec(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sig := ValidSignature().Draw(t, "sig")
		if v := spec.Signature(sig); v == spec.Invalid {
			t.Fatalf("Valid signature %q refused", sig)
		}
		big := rapid.Bool().Draw(t, "big")
		var order Order = binary.LittleEndian
		if big {
			order = binary.BigEndian
		}
		body := Body(order, sig).Draw(t, "body")
		if err := spec.CheckValues(order, sig, body, 0); err != nil {
			t.Fatalf("Body for %q: %v (%x)", sig, err, body)
		}
		if s := InvalidSignature().Draw(t, "bad"); spec.Signature(s) == spec.Valid {
			t.Fatalf("Invalid signature %q passed", s)
		}
	})
}
