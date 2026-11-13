package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A /sys/class/net of devices, each with its type and whether it has a device link (a physical NIC)
func fakeSysNet(t *testing.T, devs map[string]struct {
	typ      string
	physical bool
}) string {
	dir := t.TempDir()
	for name, d := range devs {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(p, "type"), []byte(d.typ+"\n"), 0o644)
		if d.physical {
			os.Symlink(dir, filepath.Join(p, "device"))
		}
	}
	return dir
}

func TestUplinks(t *testing.T) {
	sys := fakeSysNet(t, map[string]struct {
		typ      string
		physical bool
	}{
		"lo":      {"772", false},
		"wlp2s0":  {"1", true},
		"enp3s0":  {"1", true},
		"wwan0":   {"65534", true}, // raw IP, no Ethernet header
		"docker0": {"1", false},
		"sbx-1":   {"1", false},
		"wg0":     {"65534", false},
		// A name the einat config can't hold: skipped, the others still taken
		`en"p4`: {"1", true},
	})
	got, err := uplinks(sys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"enp3s0", "wlp2s0"}; !slices.Equal(got, want) {
		t.Errorf("uplinks = %v, want %v", got, want)
	}
	// Named ones replace the search, whatever sysfs says
	if got, _ := uplinks(sys, []string{"wg0", "eth1", "eth1"}); !slices.Equal(got, []string{"eth1", "wg0"}) {
		t.Errorf("named uplinks = %v", got)
	}
	// None: no error, einat idles
	if got, err := uplinks(fakeSysNet(t, nil), nil); err != nil || len(got) != 0 {
		t.Errorf("no physical NIC: %v, %v", got, err)
	}
	for _, bad := range []string{`eth"0`, "a b", "", "0123456789abcdef", "x\n"} {
		if _, err := uplinks(sys, []string{bad}); err == nil {
			t.Errorf("Uplink %q taken", bad)
		}
	}
}

// A NIC enslaved to a bridge (or a bond in a bridge) is the bridge, its master
func TestUplinksMaster(t *testing.T) {
	sys := fakeSysNet(t, map[string]struct {
		typ      string
		physical bool
	}{
		"enp3s0": {"1", true},
		"enp4s0": {"1", true},
		"enp5s0": {"1", true},
		"br0":    {"1", false},
		"bond0":  {"1", false},
	})
	for nic, master := range map[string]string{"enp3s0": "br0", "enp4s0": "bond0", "bond0": "br0"} {
		if err := os.Symlink("../"+master, filepath.Join(sys, nic, "master")); err != nil {
			t.Fatal(err)
		}
	}
	got, err := uplinks(sys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"br0", "enp5s0"}; !slices.Equal(got, want) {
		t.Errorf("uplinks = %v, want %v", got, want)
	}
}

func TestEinatConfig(t *testing.T) {
	got := einatConfig([]string{"enp3s0", "wlan0"}, netip.MustParsePrefix("169.254.100.0/22"),
		netip.MustParsePrefix("fd51:383b:c9ef::/48"))
	want := `# Written by sandbox-uplink einat-config
[defaults]
tcp_ranges = ["61000-63999"]
udp_ranges = ["61000-63999"]
`
	iface := `
[[interfaces]]
if_name = "IF"
nat44 = true
nat66 = true
snat_internals = ["169.254.100.0/22", "fd51:383b:c9ef::/48"]

[[interfaces.externals]]
match_address = "fe80::/10"
no_snat = true
no_hairpin = true

[[interfaces.externals]]
match_address = "fc00::/7"
no_snat = true
no_hairpin = true
`
	want += strings.ReplaceAll(iface, "IF", "enp3s0") + strings.ReplaceAll(iface, "IF", "wlan0")
	if got != want {
		t.Errorf("einatConfig:\n%s\nwant:\n%s", got, want)
	}
}
