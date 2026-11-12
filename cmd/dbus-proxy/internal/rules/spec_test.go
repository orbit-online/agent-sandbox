package rules

import (
	"flag"
	"slices"
	"testing"

	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"pgregory.net/rapid"
)

// Generated configs, valid and near misses (internal/gen), are taken exactly when the specification's model of the
// config takes them, and then give every name the model's policy, calls and broadcasts. 3000 configs in about a
// fifth of a second, unless the command line says otherwise
func TestConfigAgainstSpec(t *testing.T) {
	set := false
	flag.Visit(func(f *flag.Flag) { set = set || f.Name == "rapid.checks" })
	if !set {
		old := flag.Lookup("rapid.checks").Value.String()
		_ = flag.Set("rapid.checks", "3000")
		t.Cleanup(func() { _ = flag.Set("rapid.checks", old) })
	}
	paths := []string{"/", "/a", "/a/b", "/ab", "/a/b/c"}
	ifaces := []string{"org.a.I", "org.a", "org.b.I"}
	members := []string{"M", "I", "N"}
	names := []string{"org.a.B", "org.a.C", "org.b.B", "org.a.B.C"}
	n := gen.ConfigNames{Name: rapid.OneOf(rapid.SampledFrom(names), gen.WellKnownName()),
		Path: rapid.OneOf(rapid.SampledFrom(paths), gen.ObjectPath()), Iface: rapid.OneOf(rapid.SampledFrom(ifaces),
			gen.InterfaceName()), Member: rapid.OneOf(rapid.SampledFrom(members), gen.MemberName())}
	rapid.Check(t, func(t *rapid.T) {
		data := gen.Config(n, true).Draw(t, "config")
		want, werr := spec.ParseConfig(data)
		rs, err := Decode(data)
		if (err == nil) != (werr == nil) {
			t.Fatalf("Decode: %v; the model: %v", err, werr)
		}
		if err != nil {
			return
		}
		r := New(rs)
		if got := r.Names(); !slices.Equal(got, want.Names()) {
			t.Fatalf("Names %v, the model's %v", got, want.Names())
		}
		known := rapid.SampledFrom(append(names, BusName))
		if len(want.Names()) > 0 {
			known = rapid.OneOf(rapid.SampledFrom(want.Names()), known)
		}
		for range 20 {
			name := rapid.OneOf(known, known, gen.WellKnownName()).Draw(t, "name")
			path := rapid.SampledFrom(paths).Draw(t, "path")
			iface := rapid.SampledFrom(append(ifaces, "")).Draw(t, "iface")
			member := rapid.SampledFrom(members).Draw(t, "member")
			p, fs := r.Lookup(name)
			if spec.Level(p) != want.Level(name) {
				t.Fatalf("%s: policy %d, the model's %d", name, p, want.Level(name))
			}
			if got := AnyMatches(fs, Call, path, iface, member); got != want.Calls(name, path, iface, member) {
				t.Fatalf("%s: a call to %s %s.%s passes: %v", name, path, iface, member, got)
			}
			if got := BroadcastPasses(fs, path, iface, member); got != want.Broadcasts(name, path, iface, member) {
				t.Fatalf("%s: a broadcast %s %s.%s passes: %v", name, path, iface, member, got)
			}
		}
	})
}
