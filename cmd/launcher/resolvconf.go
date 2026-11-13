package main

import (
	"cmp"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/godbus/dbus/v5"
)

// The DNS configuration of the host as systemd-resolved or NetworkManager has it, and which of it the sandbox gets in its
// resolv.conf (dns.go follows it)

// dnsServer is a DNS server of the host: on the link of ifindex, 0 for a global one, from a VPN by the word of
// NetworkManager. split is a server for its routing domains alone (split DNS, `~corp.example`), which resolv.conf can't
// say: a link that isn't a default route of resolved, or a scope with routing domains other than `~.`
type dnsServer struct {
	ifindex int
	addr    netip.Addr
	vpn     bool
	split   bool
}

// dnsDomain is a search domain of the host, as dnsServer
type dnsDomain struct {
	ifindex int
	name    string
	vpn     bool
	split   bool
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
// out). defaultRoute has the DefaultRoute of the links, a link missing from it is one. resolved sends every query the
// routing domains don't match to the global servers too, whatever their domains; here a global scope with routing
// domains other than `~.` is split DNS like a link of resolved with them (ops-cluster: CoreDNS of k3s, on an address
// of Cilium the sandbox can't reach, for `~k3s.internal`)
func fromResolved(servers []resolvedServer, domains []resolvedDomain, defaultRoute map[int]bool) dnsConfig {
	var c dnsConfig
	globalSplit := slices.ContainsFunc(domains, func(d resolvedDomain) bool {
		return d.Ifindex == 0 && d.RouteOnly && strings.TrimSuffix(d.Name, ".") != ""
	})
	for _, s := range servers {
		a, ok := netip.AddrFromSlice(s.Addr)
		if ok && (s.Port == 0 || s.Port == 53) {
			dr, known := defaultRoute[int(s.Ifindex)]
			split := s.Ifindex == 0 && globalSplit || s.Ifindex != 0 && known && !dr
			c.servers = append(c.servers, dnsServer{ifindex: int(s.Ifindex), addr: a.Unmap(), split: split})
		}
	}
	for _, d := range domains {
		if !d.RouteOnly {
			dr, known := defaultRoute[int(d.Ifindex)]
			split := d.Ifindex == 0 && globalSplit || d.Ifindex != 0 && known && !dr
			c.domains = append(c.domains, dnsDomain{ifindex: int(d.Ifindex), name: d.Name, split: split})
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
		domains, _ := e["domains"].Value().([]string)
		// Routing domains other than ~. make the entry split DNS, as they make a link of resolved no default route
		split := slices.ContainsFunc(domains, func(d string) bool { return strings.HasPrefix(d, "~") && d != "~." })
		servers, _ := e["nameservers"].Value().([]string)
		for _, s := range servers {
			if a, err := netip.ParseAddr(s); err == nil {
				c.servers = append(c.servers, dnsServer{ifindex: idx, addr: a.Unmap(), vpn: vpn, split: split})
			}
		}
		for _, d := range domains {
			// NetworkManager marks routing-only domains with a leading ~
			if !strings.HasPrefix(d, "~") {
				c.domains = append(c.domains, dnsDomain{ifindex: idx, name: d, vpn: vpn, split: split})
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
// through the uplink, around the VPN) or of split DNS (resolv.conf would send every query there; a search domain of
// such a scope goes with its servers, or every name under it would go to the LAN resolver), and nothing the sandbox can't reach: loopback, link-local and multicast
// addresses and those of the host (the `peer` program drops local delivery). A global server with a private address the
// host routes elsewhere is behind a VPN or on a host-only network. Empty when no server is left
func resolvConf(c dnsConfig, uplinks map[int]bool, route hostRoute) string {
	var b strings.Builder
	seen := map[netip.Addr]bool{}
	for _, s := range c.servers {
		a := s.addr
		if s.vpn || s.split || seen[a] || !a.IsGlobalUnicast() {
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
		if d.vpn || d.split || !hostname(name) || slices.Contains(search, name) || d.ifindex != 0 && !uplinks[d.ifindex] {
			continue
		}
		search = append(search, name)
	}
	if len(search) > 0 {
		b.WriteString("search " + strings.Join(search, " ") + "\n")
	}
	return b.String()
}

// A domain name of LDH labels (RFC 1123), which is all a search line takes: no whitespace or newline to add lines of
// its own to resolv.conf
var ldh = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func hostname(name string) bool {
	return len(name) <= 253 && ldh.MatchString(name)
}

// Shared address space (RFC 6598), which IsPrivate leaves out: carrier-grade NAT, and the addresses of Tailscale
var sharedSpace = netip.MustParsePrefix("100.64.0.0/10")

// public is whether a is an address of the internet, which the sandbox reaches through its uplink whatever the host
// does
func public(a netip.Addr) bool {
	return a.IsGlobalUnicast() && !a.IsPrivate() && !sharedSpace.Contains(a)
}
