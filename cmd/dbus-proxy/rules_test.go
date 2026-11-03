package main

import (
	"fmt"
	"testing"
)

// Rules parse as xdg-dbus-proxy's filter_new_from_rule, its quirk included: "a.b.C" is member C of interface a.b
func TestParseRule(t *testing.T) {
	for _, tc := range []struct {
		rule string
		want filter
	}{
		{"*", filter{}},
		{"", filter{}},
		{"org.foo.Iface.Method", filter{iface: "org.foo.Iface", member: "Method"}},
		{"org.foo.Iface.*", filter{iface: "org.foo.Iface"}},
		{"org.foo.Iface", filter{iface: "org.foo", member: "Iface"}},
		{"@/a/b", filter{hasPath: true, path: "/a/b"}},
		{"@/a/b/*", filter{hasPath: true, path: "/a/b", pathSubtree: true}},
		{"*@/*", filter{hasPath: true, pathSubtree: true}},
		{"org.foo.I.M@", filter{iface: "org.foo.I", member: "M"}},
	} {
		rs := NewRuleSet()
		if err := rs.AddRule("org.x.Y="+tc.rule, filterCall); err != nil {
			t.Fatalf("%q: %v", tc.rule, err)
		}
		got := *rs.byName["org.x.Y"][0]
		tc.want.policy, tc.want.types, tc.want.set = policyTalk, filterCall, rs
		if got != tc.want {
			t.Errorf("%q: got %+v, want %+v", tc.rule, got, tc.want)
		}
	}
}

func TestRuleLookup(t *testing.T) {
	rs := NewRuleSet()
	for _, err := range []error{
		rs.AddPolicy("org.foo.*", policySee),
		rs.AddPolicy("org.foo.bar", policyOwn),
		rs.AddPolicy("org.baz", policyTalk),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	r := NewRules(rs)
	for name, want := range map[string]policy{
		"org.foo": policySee, "org.foo.x.y": policySee, "org.foobar": policyNone, "org.foo.bar": policyOwn,
		"org.baz": policyTalk, "org.baz.sub": policyNone, busName: policyTalk,
	} {
		if p, _ := r.lookup(name); p != want {
			t.Errorf("%s: got %d, want %d", name, p, want)
		}
	}
}

func TestEavesdropMatch(t *testing.T) {
	for rule, want := range map[string]bool{
		"eavesdrop=true": true, "type='signal', eavesdrop\n= 'false'": true, "member='eavesdrop'": false,
		"arg0='eavesdropping'": false, "eavesdrop": false,
	} {
		if isEavesdrop(rule) != want {
			t.Errorf("%q: want %v", rule, want)
		}
	}
}

func TestParseAddress(t *testing.T) {
	addrs, err := parseAddress("tcp:host=x;unix:path=/run/a%2cb,guid=00;unix:abstract=c")
	if err != nil || len(addrs) != 2 || addrs[0].Name != "/run/a,b" || addrs[1].Name != "@c" {
		t.Errorf("Got %v %v", addrs, err)
	}
	for _, bad := range []string{"tcp:host=x", "unix:path=%zz", "unix:path=%2"} {
		if _, err := parseAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// The unique name table stays bounded: past callers go first, then it refuses
func TestNameTableBound(t *testing.T) {
	nt := newNameTable()
	for i := 0; i < maxUniqueIDs; i++ {
		if err := nt.raise(fmt.Sprintf(":1.%d", i), policySee); err != nil {
			t.Fatal(err)
		}
	}
	if err := nt.raise(":2.0", policyTalk); err != nil || len(nt.ids) != maxUniqueIDs || nt.ids[":1.0"] != nil {
		t.Fatalf("Evicting the oldest caller: %v, %d ids", err, len(nt.ids))
	}
	for i := 1; i < maxUniqueIDs; i++ {
		nt.raise(fmt.Sprintf(":1.%d", i), policyTalk)
	}
	if err := nt.raise(":3.0", policySee); err != errTooManyNames {
		t.Errorf("Table full of talkers took another: %v", err)
	}
}
