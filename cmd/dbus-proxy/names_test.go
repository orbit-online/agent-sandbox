package main

import (
	"fmt"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
)

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
		if err := nt.raise(fmt.Sprintf(":1.%d", i), rules.See); err != nil {
			t.Fatal(err)
		}
	}
	if err := nt.raise(":2.0", rules.Talk); err != nil || len(nt.ids) != maxUniqueIDs || nt.ids[":1.0"] != nil {
		t.Fatalf("Evicting the oldest caller: %v, %d ids", err, len(nt.ids))
	}
	for i := 1; i < maxUniqueIDs; i++ {
		nt.raise(fmt.Sprintf(":1.%d", i), rules.Talk)
	}
	if err := nt.raise(":3.0", rules.See); err != errTooManyNames {
		t.Errorf("Table full of talkers took another: %v", err)
	}
}
