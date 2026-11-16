package judge

import (
	"fmt"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/gen"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/rules"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/spec"
	"github.com/orbit-online/agent-sandbox/cmd/dbus-proxy/internal/wire"
	"pgregory.net/rapid"
)

// Properties.Get calls near a version the config gives get the specification's verdict, and an answer carries the
// version. The judge machine's configs give versions too rarely to rely on it for these
func TestVersionAgainstSpec(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var entries []string
		for _, name := range wellKnown[:rapid.IntRange(1, len(wellKnown)).Draw(t, "names")] {
			var versions []string
			seen := map[string]bool{}
			for range rapid.IntRange(1, 3).Draw(t, "versions") {
				key := rapid.SampledFrom(configIfaces).Draw(t, "iface") + "@" + rapid.SampledFrom(configPaths).Draw(t, "path")
				if !seen[key] {
					seen[key] = true
					versions = append(versions, fmt.Sprintf("%q:%d", key, rapid.Uint32().Draw(t, "version")))
				}
			}
			call := rapid.SampledFrom([]string{"", `"call":["*"],`, `"call":["org.freedesktop.DBus.Properties.Get@/"],`}).Draw(t, "call")
			entries = append(entries, fmt.Sprintf(`%q:{%s"versions":{%s}}`, name, call, strings.Join(versions, ",")))
		}
		data := []byte("{" + strings.Join(entries, ",") + "}")
		cfg, err := spec.ParseConfig(data)
		if err != nil {
			t.Fatalf("Config %s: %v", data, err)
		}
		rs, err := rules.Decode(data)
		if err != nil {
			t.Fatal(err)
		}
		m := &judgeMachine{cfg: cfg}
		j := New(rules.New(rs), false)
		for serial := uint32(1); serial <= 20; serial++ {
			msg := gen.Message(machineNames(), rapid.Just(serial)).Draw(t, "msg")
			gen.GetVersion(t, msg, rapid.OneOf(rapid.SampledFrom(wellKnown), machineNames().Dest), configPaths, configIfaces)
			msg.Serial = serial
			read, sm, _ := spec.ProxyReads(msg.Encode(), 0)
			if read != spec.Judged {
				continue
			}
			w, err := wire.Parse(msg.Encode()[:sm.Len])
			if err != nil {
				t.Fatal(err)
			}
			want := spec.ProxyVerdict(sm, oracleView{m, map[uint32]bool{}})
			a, err := j.FromClient(w)
			verdict := map[spec.Kind]Verdict{spec.Forward: Forward, spec.Refuse: Replace, spec.Drop: Drop}[want.Kind]
			if err != nil || a.Verdict != verdict {
				t.Fatalf("Verdict %v %v, want %+v", a.Verdict, err, want)
			}
			if a.Verdict != Replace {
				continue
			}
			// The bus answers the Ping of a refusal or an answer
			a, err = j.FromBus(parsed(t, reply(serial, busName), 1<<20))
			if err != nil {
				t.Fatal(err)
			}
			if want.Error != spec.VersionReply {
				continue
			}
			r, err := wire.Parse(a.Message)
			if err != nil || !r.DecodeBody(64) || r.Type != dbus.TypeMethodReply || r.Body[0] != dbus.MakeVariant(want.Version) {
				t.Fatalf("Version %d answered with %v %v", want.Version, err, r)
			}
		}
	})
}
