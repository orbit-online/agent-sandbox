package main

import (
	"net/netip"
	"testing"
)

func TestPick(t *testing.T) {
	block := netip.MustParsePrefix("169.254.100.0/22")
	none := func(netip.Addr) bool { return false }
	a, err := pick(block, seed(1000, ""), none)
	if err != nil {
		t.Fatal(err)
	}
	// A changed derivation moves every sandbox to another address (Python over the same inputs agrees)
	if want := netip.MustParseAddr("169.254.102.205"); a != want {
		t.Errorf("pick = %v, want %v", a, want)
	}
	if b, _ := pick(block, seed(1000, "work"), none); b == a {
		t.Error("Same address for two launchers")
	}
	if b, _ := pick(block, seed(1001, ""), none); b == a {
		t.Error("Same address for two users")
	}
	// Taken: the next one
	b, err := pick(block, seed(1000, ""), func(x netip.Addr) bool { return x == a })
	if err != nil || b != a.Next() {
		t.Errorf("pick past %v = %v, %v", a, b, err)
	}
	// Never the first or last of the block, wrapping within it
	small := netip.MustParsePrefix("169.254.100.0/30")
	seen := map[netip.Addr]bool{}
	for uid := range 64 {
		a, err := pick(small, seed(uid, ""), none)
		if err != nil || !small.Contains(a) || a == small.Addr() || a == netip.MustParseAddr("169.254.100.3") {
			t.Fatalf("pick in %v = %v, %v", small, a, err)
		}
		seen[a] = true
	}
	if len(seen) != 2 {
		t.Errorf("pick used %v of %v", seen, small)
	}
	if a, err := pick(small, seed(1000, ""), func(x netip.Addr) bool { return x.Is4() }); err == nil {
		t.Errorf("pick in a full block = %v", a)
	}
	v6 := netip.MustParsePrefix("fd51:383b:c9ef::/48")
	a6, err := pick(v6, seed(1000, ""), none)
	if err != nil || !v6.Contains(a6) {
		t.Errorf("pick in %v = %v, %v", v6, a6, err)
	}
}

func TestPrimaryName(t *testing.T) {
	for _, tc := range []struct {
		uid  int
		name string
		want string
	}{
		{1000, "", "sbx-rs-e3b0c442"},
		{1000, "work", "sbx-rs-00e13ed7"},
		{4294967294, "", "sbx-1z141z2-e3b"},
	} {
		if got := primaryName("sbx-", tc.uid, tc.name); got != tc.want {
			t.Errorf("primaryName(%d, %q) = %q, want %q", tc.uid, tc.name, got, tc.want)
		}
	}
}
