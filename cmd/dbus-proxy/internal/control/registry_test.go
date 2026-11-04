package control

import (
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
)

// A connection that used the set or not, noting what the rules in force held when it heard of the removal
type fakeConn struct {
	reg          *Registry
	used, killed bool
	added        int
	sawSet       bool
}

func (f *fakeConn) AddSet(*rules.Set) { f.added++ }

func (f *fakeConn) RemoveSet(*rules.Set) bool {
	p, _ := f.reg.Current().Lookup("org.test.Live")
	f.sawSet = p != rules.None
	return f.used
}

// A set added reaches every connection and the rules in force; its removal swaps the rules first, then ends only the
// connections that used it
func TestRegistry(t *testing.T) {
	reg := NewRegistry(rules.New())
	rs, err := rules.ParseLive("g", rules.Args{Talk: []string{"org.test.Live"}}, "session", "")
	if err != nil {
		t.Fatal(err)
	}
	user, other := &fakeConn{reg: reg, used: true}, &fakeConn{reg: reg}
	for _, c := range []*fakeConn{user, other} {
		reg.Register(c, func() { c.killed = true })
	}
	gone := &fakeConn{reg: reg, used: true}
	reg.Register(gone, func() { gone.killed = true })()
	reg.Add(rs)
	if p, _ := reg.Current().Lookup("org.test.Live"); p != rules.Talk || user.added != 1 || other.added != 1 || gone.added != 0 {
		t.Fatalf("Added: %v, %d %d %d", p, user.added, other.added, gone.added)
	}
	if n := reg.Remove(rs); n != 1 || !user.killed || other.killed || gone.killed {
		t.Errorf("Removed: %d ended, %v %v %v", n, user.killed, other.killed, gone.killed)
	}
	if user.sawSet || other.sawSet {
		t.Error("A connection heard of the removal while the set was still in force")
	}
}
