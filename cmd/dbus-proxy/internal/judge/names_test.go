package judge

import (
	"fmt"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
)

// Match rules that ask for others' traffic, as xdg-dbus-proxy's is_eavesdrop
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

// One unique name is recorded owning at most maxOwnedNames names; the next ends the connection
func TestOwnedNamesBound(t *testing.T) {
	nt := newNameTable()
	for i := range maxOwnedNames {
		if err := nt.addOwned(":1.5", fmt.Sprintf("org.test.N%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := nt.addOwned(":1.5", "org.test.N0"); err != nil {
		t.Errorf("A name recorded again: %v", err)
	}
	if err := nt.addOwned(":1.5", "org.test.More"); err != errTooManyNames {
		t.Errorf("Past the cap: %v", err)
	}
}
