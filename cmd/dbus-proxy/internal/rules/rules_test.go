package rules

import "testing"

// Rules parse as xdg-dbus-proxy's filter_new_from_rule, its quirk included: "a.b.C" is member C of interface a.b
func TestParseRule(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want Filter
	}{
		{"*", Filter{}},
		{"", Filter{}},
		{"org.foo.Iface.Method", Filter{iface: "org.foo.Iface", member: "Method"}},
		{"org.foo.Iface.*", Filter{iface: "org.foo.Iface"}},
		{"org.foo.Iface", Filter{iface: "org.foo", member: "Iface"}},
		{"@/a/b", Filter{hasPath: true, path: "/a/b"}},
		{"@/a/b/*", Filter{hasPath: true, path: "/a/b", pathSubtree: true}},
		{"*@/*", Filter{hasPath: true, pathSubtree: true}},
		{"org.foo.I.M@", Filter{iface: "org.foo.I", member: "M"}},
	} {
		rs := newSet()
		if err := rs.addRule("org.x.Y="+tc.rule, Call); err != nil {
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
	rs := newSet()
	for _, err := range []error{
		rs.addPolicy("org.foo", See),
		rs.addPolicy("org.foo.bar", Own),
		rs.addPolicy("org.baz", Talk),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Names are exact: xdg-dbus-proxy's wildcards are refused
	if err := rs.addPolicy("org.foo.*", See); err == nil {
		t.Error("A wildcard accepted")
	}
	r := New(rs)
	for name, want := range map[string]Policy{
		"org.foo": See, "org.foo.x.y": None, "org.foobar": None, "org.foo.bar": Own,
		"org.baz": Talk, "org.baz.sub": None, BusName: Talk,
	} {
		if p, _ := r.Lookup(name); p != want {
			t.Errorf("%s: got %d, want %d", name, p, want)
		}
	}
}
