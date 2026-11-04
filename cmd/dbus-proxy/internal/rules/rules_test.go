package rules

import (
	"fmt"
	"testing"
)

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
		tc.want.policy, tc.want.types, tc.want.Set = Talk, Call, rs
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

// A live set: the command line's syntax, at least one rule and at most MaxLiveEntries, nothing for the bus itself and
// nothing the bus's policy refuses
func TestParseLive(t *testing.T) {
	const app = "com.nixpak.ClaudeDesktop"
	many := make([]string, MaxLiveEntries+1)
	for i := range many {
		many[i] = fmt.Sprintf("org.test.N%d", i)
	}
	for name, a := range map[string]Args{
		"no rules":        {},
		"the bus":         {Talk: []string{BusName}},
		"a call to it":    {Call: []string{BusName + "=*"}},
		"too many":        {See: many},
		"a wildcard":      {Talk: []string{"org.test.A.*"}},
		"refused":         {Talk: []string{"org.freedesktop.secrets"}},
		"not its own":     {Own: []string{"org.test.A"}},
		"not a NAME=RULE": {Call: []string{"org.test.A"}},
	} {
		if _, err := ParseLive("g", a, "session", app); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rs, err := ParseLive("g", Args{See: many[:MaxLiveEntries-1], Own: []string{app + ".Helper"}}, "session", app)
	if err != nil || !rs.Live() || len(rs.Names()) != MaxLiveEntries {
		t.Errorf("A set of %d rules: %v", MaxLiveEntries, err)
	}
	if p, _ := New(rs).Lookup(app + ".Helper"); p != Own {
		t.Errorf("Own of the app's name: %v", p)
	}
}
