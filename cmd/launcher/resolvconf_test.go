package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// The host in these tests: eth0 (2) the uplink, wg0 (5) a VPN, docker0 (7) a bridge; 192.168.1.10 its own address
var testIfindex = map[string]int{"eth0": 2, "wg0": 5, "docker0": 7}

func testRoute(a netip.Addr) (int, bool, error) {
	switch {
	case a == netip.MustParseAddr("192.168.1.10"):
		return 1, true, nil
	case netip.MustParsePrefix("192.168.1.0/24").Contains(a), netip.MustParsePrefix("2001:db8:1::/48").Contains(a):
		return 2, false, nil
	case netip.MustParsePrefix("172.17.0.0/16").Contains(a):
		return 7, false, nil
	default:
		// A full-tunnel VPN takes the rest
		return 5, false, nil
	}
}

var testUplinks = map[int]bool{2: true}

func ip(s string) []byte { return netip.MustParseAddr(s).AsSlice() }

func TestResolved(t *testing.T) {
	servers := []resolvedServer{
		{Ifindex: 2, Family: 2, Addr: ip("192.168.1.1")},
		{Ifindex: 2, Family: 10, Addr: ip("2001:db8:1::1"), Port: 53},
		// A port resolv.conf can't say
		{Ifindex: 2, Family: 2, Addr: ip("192.168.1.2"), Port: 5353},
		// The VPN's, by its link
		{Ifindex: 5, Family: 2, Addr: ip("10.8.0.1")},
		// Unreachable from the sandbox
		{Ifindex: 2, Family: 2, Addr: ip("127.0.0.53")},
		{Ifindex: 2, Family: 2, Addr: ip("169.254.169.254")},
		{Ifindex: 2, Family: 10, Addr: ip("fe80::1")},
		{Ifindex: 2, Family: 2, Addr: ip("192.168.1.10")},
		// Twice
		{Ifindex: 0, Family: 2, Addr: ip("192.168.1.1")},
		// Global: public through the VPN kept, private through the VPN or the bridge not, private on the uplink kept
		{Ifindex: 0, Family: 2, Addr: ip("9.9.9.9")},
		{Ifindex: 0, Family: 2, Addr: ip("10.0.0.53")},
		{Ifindex: 0, Family: 2, Addr: ip("100.100.100.100")},
		{Ifindex: 0, Family: 2, Addr: ip("172.17.0.2")},
		{Ifindex: 0, Family: 2, Addr: ip("192.168.1.3")},
		{Ifindex: 0, Family: 2, Addr: ip("::1")},
	}
	domains := []resolvedDomain{
		{Ifindex: 2, Name: "lan"},
		{Ifindex: 5, Name: "corp.example"},
		{Ifindex: 2, Name: "routed.example", RouteOnly: true},
		{Ifindex: 0, Name: "example.org."},
		{Ifindex: 0, Name: "lan"},
	}
	got := resolvConf(fromResolved(servers, domains), testUplinks, testRoute)
	want := "nameserver 192.168.1.1\nnameserver 2001:db8:1::1\nnameserver 9.9.9.9\nnameserver 192.168.1.3\n" +
		"search lan example.org\n"
	if got != want {
		t.Errorf("Got\n%s\nwant\n%s", got, want)
	}
}

func TestNM(t *testing.T) {
	v := dbus.MakeVariant
	entries := []map[string]dbus.Variant{
		{"nameservers": v([]string{"10.8.0.1"}), "domains": v([]string{"corp.example"}), "interface": v("wg0"),
			"priority": v(int32(50)), "vpn": v(true)},
		// A VPN's by NetworkManager's word, though on the uplink
		{"nameservers": v([]string{"192.168.1.9"}), "domains": v([]string{"vpn.example"}), "interface": v("eth0"), "priority": v(int32(60)), "vpn": v(true)},
		{"nameservers": v([]string{"192.168.1.1", "fe80::1%eth0", "192.168.1.1"}), "domains": v([]string{"lan", "~."}),
			"interface": v("eth0"), "priority": v(int32(100)), "vpn": v(false)},
		{"nameservers": v([]string{"2001:db8:1::1"}), "interface": v("eth0"), "priority": v(int32(-10)),
			"vpn": v(false)},
		{"nameservers": v([]string{"172.17.0.2"}), "interface": v("docker0"), "priority": v(int32(100)), "vpn": v(false)},
		// Gone meanwhile
		{"nameservers": v([]string{"192.168.1.7"}), "interface": v("eth9"), "priority": v(int32(100)), "vpn": v(false)},
	}
	c := fromNM(entries, func(name string) int { return testIfindex[name] })
	got := resolvConf(c, testUplinks, testRoute)
	if want := "nameserver 2001:db8:1::1\nnameserver 192.168.1.1\nsearch lan\n"; got != want {
		t.Errorf("Got\n%s\nwant\n%s", got, want)
	}
	// Only the VPN's: nothing
	if got := resolvConf(fromNM(entries[:1], func(string) int { return 5 }), testUplinks, testRoute); got != "" {
		t.Errorf("A VPN's server alone gave %q", got)
	}
}

// The option wins; without it and without a bus, no DNS; without a network none, the option set or not
func TestDNSSources(t *testing.T) {
	d := &dns{cfg: &config{Network: true, Nameservers: []string{"192.168.1.1", "2001:db8::1"}}}
	if got, src := d.read(); got != "nameserver 192.168.1.1\nnameserver 2001:db8::1\n" || src != "nameservers option" {
		t.Errorf("Static: %q from %s", got, src)
	}
	d = &dns{cfg: &config{Network: true}}
	if got, src := d.read(); got != "" || src != "none" {
		t.Errorf("Without a source: %q from %s", got, src)
	}
	d = newDNS(&config{Nameservers: []string{"192.168.1.1"}})
	if got, src := d.read(); got != "" || src != "no network" || d.bus != nil {
		t.Errorf("Without a network: %q from %s, bus %v", got, src, d.bus)
	}
}

// update writes through the state script, and only what changed
func TestDNSUpdate(t *testing.T) {
	w := newWorld(t)
	out := filepath.Join(w.dir, "resolv.conf")
	w.cfg.State = w.script("state", "cat >"+out)
	w.cfg.Network = true
	w.cfg.Nameservers = []string{"192.168.1.1"}
	d := &dns{cfg: w.cfg}
	for range 2 {
		if err := d.update(); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(w.calls(), "state "+w.cfg.Home+" -- resolv"); n != 1 {
		t.Errorf("Wrote %d times:\n%s", n, w.calls())
	}
	if got, _ := os.ReadFile(out); string(got) != "nameserver 192.168.1.1\n" {
		t.Errorf("Wrote %q", got)
	}
}
