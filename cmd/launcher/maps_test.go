package main

import (
	"reflect"
	"strings"
	"testing"
)

// The user's subuid range, their own id kept as itself
func TestSubidMap(t *testing.T) {
	subuid := "bob:100000:65536\nalice:200000:65536\n"
	m, err := subidMap(strings.NewReader(subuid), "alice", 1000)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{0, 200000, 1000, 1000, 1000, 1, 1001, 201001, 64535}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("Map %v, want %v", m, want)
	}
	if _, err := subidMap(strings.NewReader(subuid), "carol", 1000); err == nil {
		t.Error("A map for a user without a range")
	}
	if _, err := subidMap(strings.NewReader("alice:200000:1000\n"), "alice", 1000); err == nil {
		t.Error("A map from a range too small to hold the user's own id")
	}
}

// The parent's map as itself, and the subuid lines around the user's own id wherever it falls
func TestIdentityMapAndLines(t *testing.T) {
	m, err := identityMap(strings.NewReader("         0     200000       1000\n      1000       1000          1\n      1001     201001      64535\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{0, 0, 1000, 1000, 1000, 1, 1001, 1001, 64535}; !reflect.DeepEqual(m, want) {
		t.Errorf("Map %v, want %v", m, want)
	}
	if got, want := subidLines(m, "alice", 1000), "alice:0:1000\nalice:1001:64535\n"; got != want {
		t.Errorf("Lines %q, want %q", got, want)
	}
	for _, c := range []struct {
		m    []int
		want string
	}{
		{[]int{0, 0, 10}, "u:1:9\n"}, // own at the start
		{[]int{0, 0, 10, 20, 20, 5}, "u:1:9\nu:20:5\n"},
		{[]int{0, 0, 1}, ""},        // own alone
		{[]int{0, 0, 2}, "u:1:1\n"}, // own at the start of two
		{[]int{5, 5, 3}, "u:5:3\n"}, // own outside
		{[]int{0, 0, 5}, "u:1:4\n"},
	} {
		if got := subidLines(c.m, "u", 0); got != c.want {
			t.Errorf("Lines of %v: %q, want %q", c.m, got, c.want)
		}
	}
	if got := subidLines([]int{0, 0, 5}, "u", 4); got != "u:0:4\n" {
		t.Errorf("Own at the end: %q", got)
	}
	if got := subidLines([]int{0, 0, 5}, "u", 2); got != "u:0:2\nu:3:2\n" {
		t.Errorf("Own in the middle: %q", got)
	}
	if _, err := identityMap(strings.NewReader("0 0\n")); err == nil {
		t.Error("Took a broken map line")
	}
}
