package main

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The DNS configuration of the host as systemd-resolved or NetworkManager has it, and which of it the sandbox gets in its
// resolv.conf (dns.go follows it)

// dnsServer is a DNS server of the host: on the link of ifindex, 0 for a global one, from a VPN by the word of NetworkManager
type dnsServer struct {
	ifindex int
	addr    netip.Addr
	vpn     bool
}

// dnsDomain is a search domain of the host, as dnsServer
type dnsDomain struct {
	ifindex int
	name    string
	vpn     bool
}

type dnsConfig struct {
	servers []dnsServer
	domains []dnsDomain
}

// resolvedServer is an entry of Manager.DNSEx of resolved, a(iiayqs)
type resolvedServer struct {
	Ifindex int32
	Family  int32
	Addr    []byte
	Port    uint16
	Name    string
}

// resolvedDomain is an entry of Manager.Domains of resolved, a(isb)
type resolvedDomain struct {
	Ifindex   int32
	Name      string
	RouteOnly bool
}

// fromResolved takes the servers on port 53 (resolv.conf has no ports) and the search domains (routing-only ones left
// out)
func fromResolved(servers []resolvedServer, domains []resolvedDomain) dnsConfig {
	var c dnsConfig
	for _, s := range servers {
		a, ok := netip.AddrFromSlice(s.Addr)
		if ok && (s.Port == 0 || s.Port == 53) {
			c.servers = append(c.servers, dnsServer{ifindex: int(s.Ifindex), addr: a.Unmap()})
		}
	}
	for _, d := range domains {
		if !d.RouteOnly {
			c.domains = append(c.domains, dnsDomain{ifindex: int(d.Ifindex), name: d.Name})
		}
	}
	return c
}

// fromNM takes DnsManager.Configuration of NetworkManager, aa{sv}, highest priority (lowest value) first. ifindex maps
// an interface name, empty for a global entry, to its ifindex, 0 for none
func fromNM(entries []map[string]dbus.Variant, ifindex func(string) int) dnsConfig {
	entries = slices.Clone(entries)
	slices.SortStableFunc(entries, func(a, b map[string]dbus.Variant) int {
		pa, _ := a["priority"].Value().(int32)
		pb, _ := b["priority"].Value().(int32)
		return cmp.Compare(pa, pb)
	})
	var c dnsConfig
	for _, e := range entries {
		iface, _ := e["interface"].Value().(string)
		vpn, _ := e["vpn"].Value().(bool)
		idx := 0
		if iface != "" {
			if idx = ifindex(iface); idx == 0 {
				continue
			}
		}
		servers, _ := e["nameservers"].Value().([]string)
		for _, s := range servers {
			if a, err := netip.ParseAddr(s); err == nil {
				c.servers = append(c.servers, dnsServer{ifindex: idx, addr: a.Unmap(), vpn: vpn})
			}
		}
		domains, _ := e["domains"].Value().([]string)
		for _, d := range domains {
			// NetworkManager marks routing-only domains with a leading ~
			if !strings.HasPrefix(d, "~") {
				c.domains = append(c.domains, dnsDomain{ifindex: idx, name: d, vpn: vpn})
			}
		}
	}
	return c
}

// hostRoute is how the host routes to an address: the ifindex of the device, and whether the host delivers it
// locally
type hostRoute func(netip.Addr) (ifindex int, local bool, err error)

// resolvConf is what the sandbox gets of c, given the ifindexes of the uplinks it leaves through: the servers on those
// links, and the global ones the host routes through them or that are public. Never those of a VPN (the sandbox leaves
// through the uplink, around the VPN), and nothing the sandbox can't reach: loopback, link-local and multicast
// addresses and those of the host (the PEER program drops local delivery). A global server with a private address the
// host routes elsewhere is behind a VPN or on a host-only network. Empty when no server is left
func resolvConf(c dnsConfig, uplinks map[int]bool, route hostRoute) string {
	var b strings.Builder
	seen := map[netip.Addr]bool{}
	for _, s := range c.servers {
		a := s.addr
		if s.vpn || seen[a] || !a.IsGlobalUnicast() {
			continue
		}
		if s.ifindex != 0 && !uplinks[s.ifindex] {
			continue
		}
		dev, local, err := route(a)
		if err != nil || local {
			continue
		}
		if s.ifindex == 0 && !uplinks[dev] && !public(a) {
			continue
		}
		seen[a] = true
		b.WriteString("nameserver " + a.String() + "\n")
	}
	if b.Len() == 0 {
		return ""
	}
	var search []string
	for _, d := range c.domains {
		name := strings.TrimSuffix(d.name, ".")
		if d.vpn || name == "" || slices.Contains(search, name) || d.ifindex != 0 && !uplinks[d.ifindex] {
			continue
		}
		search = append(search, name)
	}
	if len(search) > 0 {
		b.WriteString("search " + strings.Join(search, " ") + "\n")
	}
	return b.String()
}

// Shared address space (RFC 6598), which IsPrivate leaves out: carrier-grade NAT, and the addresses of Tailscale
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// public is whether a is an address of the internet, which the sandbox reaches through its uplink whatever the host
// does
func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !sharedSpace.Contains(a)
}
