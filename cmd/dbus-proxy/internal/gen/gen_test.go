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

// A config without misses from valid names is valid by the specification's model, and the near misses are mostly
// refused
func TestConfigAgainstSpec(t *testing.T) {
	valid := ConfigNames{Name: WellKnownName().Filter(spec.WellKnownName), Path: ObjectPath().Filter(spec.Path),
		Iface: InterfaceName().Filter(spec.Interface), Member: MemberName().Filter(spec.Member)}
	refused, n := 0, 0
	rapid.Check(t, func(t *rapid.T) {
		if data := Config(valid, false).Draw(t, "valid"); !configOK(data) {
			t.Fatalf("Valid config refused: %s", data)
		}
		if data := Config(valid, true).Draw(t, "any"); !configOK(data) {
			refused++
		}
		n++
	})
	// A third are near misses, and a few of those (64 names or rules, whitespace short of the cap) are valid
	if refused < n/5 || refused > n/2 {
		t.Errorf("%d of %d configs refused", refused, n)
	}
}

func configOK(data []byte) bool {
	_, err := spec.ParseConfig(data)
	return err == nil
}
