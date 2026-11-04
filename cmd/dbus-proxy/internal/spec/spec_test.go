package spec

import (
	"encoding/binary"
	"strings"
	"testing"
)

// The specification's own examples and limits, each rule once each way
func TestNames(t *testing.T) {
	long := "a." + strings.Repeat("b", 253)
	for _, c := range []struct {
		f    func(string) bool
		s    string
		want bool
	}{
		{WellKnownName, "org.freedesktop.DBus", true}, {WellKnownName, "com.example-x.A_b", true},
		{WellKnownName, long, true}, {WellKnownName, long + "b", false}, {WellKnownName, "org", false},
		{WellKnownName, "org..x", false}, {WellKnownName, "org.7x", false}, {WellKnownName, ".org.x", false},
		{WellKnownName, "org.x.", false}, {WellKnownName, "org.x*", false}, {WellKnownName, ":1.5", false},
		{UniqueName, ":1.5", true}, {UniqueName, ":1.0x-y", true}, {UniqueName, ":1", false}, {UniqueName, "1.5", false},
		{Interface, "org.freedesktop.DBus", true}, {Interface, "org.free-desktop.DBus", false},
		{Interface, "org.7x", false}, {Member, "Hello", true}, {Member, "_9", true}, {Member, "9a", false},
		{Member, "a.b", false}, {Member, "", false}, {Member, strings.Repeat("m", 256), false},
		{Path, "/", true}, {Path, "/a/0_b", true}, {Path, "/a/", false}, {Path, "//a", false}, {Path, "a", false},
		{Path, "/a-b", false}, {Path, "", false},
	} {
		if c.f(c.s) != c.want {
			t.Errorf("%q: want %v", c.s, c.want)
		}
	}
}

func TestSignatures(t *testing.T) {
	for s, want := range map[string]Validity{
		"": Valid, "a{sv}": Valid, "(i)": Valid, strings.Repeat("a", 32) + "y": Valid,
		strings.Repeat("a", 33) + "y": Invalid, strings.Repeat("(", 32) + "y" + strings.Repeat(")", 32): Valid,
		strings.Repeat("(", 33) + "y" + strings.Repeat(")", 33): Invalid, "()": Invalid, "{sv}": Invalid,
		"a{vs}": Invalid, "a{ss}x": Valid, "a{sss}": Invalid, "a": Invalid, "(i": Invalid, "z": Invalid,
		strings.Repeat("y", 255): Valid, strings.Repeat("y", 256): Invalid,
		strings.Repeat("(", 32) + "a{sy}" + strings.Repeat(")", 32): Unspecified,
	} {
		if got := Signature(s); got != want {
			t.Errorf("%q: %v, want %v", s, got, want)
		}
	}
}

// A body walked against its signature, little-endian
func TestValues(t *testing.T) {
	le := binary.LittleEndian
	str := func(s string) []byte { return append(append(le.AppendUint32(nil, uint32(len(s))), s...), 0) }
	for _, c := range []struct {
		sig  string
		body []byte
		ok   bool
	}{
		{"s", str("hi"), true}, {"s", str("hi")[:6], false}, {"s", append(str("h\xffi"), 0), false},
		{"b", le.AppendUint32(nil, 1), true}, {"b", le.AppendUint32(nil, 2), false},
		{"yu", []byte{1, 0, 0, 0, 2, 0, 0, 0}, true}, {"yu", []byte{1, 9, 0, 0, 2, 0, 0, 0}, false},
		{"ay", append(le.AppendUint32(nil, 2), 1, 2), true}, {"ay", append(le.AppendUint32(nil, 3), 1, 2), false},
		{"", nil, true}, {"", []byte{0}, false}, {"h", le.AppendUint32(nil, 0), false},
		{"v", []byte{1, 'y', 0, 7}, true}, {"v", []byte{2, 'y', 'y', 0, 7, 7}, false},
	} {
		if err := CheckValues(le, c.sig, c.body, 0); (err == nil) != c.ok {
			t.Errorf("%q %x: %v", c.sig, c.body, err)
		}
	}
}
