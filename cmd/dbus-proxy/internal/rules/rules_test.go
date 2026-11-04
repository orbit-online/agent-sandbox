package rules

import (
	"strings"
	"testing"
)

// Rules parse as xdg-dbus-proxy's filter_new_from_rule, its quirk included: "a.b.C" is member C of interface a.b
func TestParseRule(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want Filter
	}{
		{"*", Filter{}},
		{"org.foo.Iface.Method", Filter{iface: "org.foo.Iface", member: "Method"}},
		{"org.foo.Iface.*", Filter{iface: "org.foo.Iface"}},
		{"org.foo.Iface", Filter{iface: "org.foo", member: "Iface"}},
		{"@/a/b", Filter{hasPath: true, path: "/a/b"}},
		{"@/", Filter{hasPath: true, path: "/"}},
		{"@/a/b/*", Filter{hasPath: true, path: "/a/b", pathSubtree: true}},
		{"*@/*", Filter{hasPath: true, pathSubtree: true}},
		{"org.foo.I.M@/a", Filter{iface: "org.foo.I", member: "M", hasPath: true, path: "/a"}},
	} {
		rs, err := Decode([]byte(`{"org.x.Y":{"call":["` + tc.rule + `"]}}`))
		if err != nil {
			t.Fatalf("%q: %v", tc.rule, err)
		}
		got := *rs.byName["org.x.Y"][0]
		tc.want.policy, tc.want.types = Talk, Call
		if got != tc.want {
			t.Errorf("%q: got %+v, want %+v", tc.rule, got, tc.want)
		}
	}
}

func TestRuleLookup(t *testing.T) {
	rs, err := Decode([]byte(`{"org.foo": {"policy": "see"}, "org.foo.bar": {"policy": "own"},
		"org.baz": {"policy": "talk"}, "org.qux": {"broadcast": ["org.qux.I.S"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := New(rs)
	for name, want := range map[string]Policy{
		"org.foo": See, "org.foo.x.y": None, "org.foobar": None, "org.foo.bar": Own,
		"org.baz": Talk, "org.baz.sub": None, "org.qux": Talk, BusName: Talk,
	} {
		if p, _ := r.Lookup(name); p != want {
			t.Errorf("%s: got %d, want %d", name, p, want)
		}
	}
	if got := strings.Join(r.Names(), " "); got != "org.baz org.foo org.foo.bar org.qux" {
		t.Errorf("Names: %s", got)
	}
}

// Anything but the format exactly is refused
func TestDecodeRefuses(t *testing.T) {
	for _, c := range []string{
		``, `null`, `[]`, `{"org.a.B":null}`, `{"org.a.B":{}}`, `{"org.a.B":{"call":[]}}`,
		`{} {}`, `{}x`, `{"org.a.B":{"policy":"see"}`,
		// Names: exact and well-known, not the bus driver's
		`{"org.a.*":{"policy":"see"}}`, `{":1.2":{"policy":"see"}}`, `{"nodots":{"policy":"see"}}`,
		`{"org.freedesktop.DBus":{"policy":"talk"}}`,
		`{"org.a.B":{"policy":"see"},"org.a.B":{"policy":"own"}}`,
		// Fields: exact, once, not null
		`{"org.a.B":{"Policy":"see"}}`, `{"org.a.B":{"policy":"see","policy":"see"}}`, `{"org.a.B":{"talk":true}}`,
		`{"org.a.B":{"policy":null}}`, `{"org.a.B":{"policy":"Talk"}}`, `{"org.a.B":{"policy":""}}`,
		`{"org.a.B":{"call":null}}`, `{"org.a.B":{"call":[null]}}`, `{"org.a.B":{"call":"*"}}`,
		// Rules
		`{"org.a.B":{"call":[""]}}`, `{"org.a.B":{"call":["*.Get"]}}`, `{"org.a.B":{"call":["Iface"]}}`,
		`{"org.a.B":{"call":["org.a.I.M@"]}}`, `{"org.a.B":{"call":["@bad"]}}`, `{"org.a.B":{"call":["@/a/"]}}`,
		`{"org.a.B":{"broadcast":["@//*"]}}`, `{"org.a.B":{"call":["org.a.I.9M"]}}`, `{"org.a.B":{"call":["*@"]}}`,
		// The caps
		`{"org.a.B":{"call":[` + strings.Repeat(`"*",`, MaxRules) + `"*"]}}`,
		`{"org.a.B":{"policy":"see"}}` + strings.Repeat(" ", MaxConfig),
	} {
		if _, err := Decode([]byte(c)); err == nil {
			t.Errorf("Accepted: %.80s", c)
		}
	}
	var b strings.Builder
	for i := range MaxNames + 1 {
		b.WriteString(`,"org.a.N` + strings.Repeat("x", i) + `":{"policy":"see"}`)
	}
	if _, err := Decode([]byte("{" + b.String()[1:] + "}")); err == nil {
		t.Error("Accepted more names than the cap")
	}
}
