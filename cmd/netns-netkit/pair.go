package main

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/orbit-online/agent-sandbox/internal/uplink"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// addPair creates the netkit pair of a sandbox: the primary in the host netns, the peer eth0 straight in the sandbox
// netns. L3, and both ends drop while no program is attached (NETKIT_POLICY_BLACKHOLE is NETKIT_DROP in the kernel).
// The primary keeps skb->mark and priority for its program, which reads the mark of mDNS copies and clears both
func addPair(primary string, netnsFd int) (netlink.Link, error) {
	nk := &netlink.Netkit{
		LinkAttrs:  netlink.LinkAttrs{Name: primary},
		Mode:       netlink.NETKIT_MODE_L3,
		Policy:     netlink.NETKIT_POLICY_BLACKHOLE,
		PeerPolicy: netlink.NETKIT_POLICY_BLACKHOLE,
		Scrub:      netlink.NETKIT_SCRUB_NONE,
		PeerScrub:  netlink.NETKIT_SCRUB_DEFAULT,
	}
	nk.SetPeerAttrs(&netlink.LinkAttrs{Name: "eth0", Namespace: netlink.NsFd(netnsFd)})
	if err := netlink.LinkAdd(nk); err != nil {
		return nil, fmt.Errorf("Create the netkit pair %s: %w", primary, err)
	}
	link, err := netlink.LinkByName(primary)
	if err != nil {
		return nil, fmt.Errorf("Find %s: %w", primary, err)
	}
	// No IPv6 link-local address while still down, so device auto-detection (of Cilium) takes no primary for a NIC
	if err := netlink.LinkSetIP6AddrGenMode(link, nl.IN6_ADDR_GEN_MODE_NONE); err != nil {
		netlink.LinkDel(link)
		return nil, fmt.Errorf("Turn IPv6 address generation off on %s: %w", primary, err)
	}
	return link, nil
}

// routePair readies the host end: routes to the sandbox addresses, which the host needs to reach a forwarded port and
// to take its replies past rp_filter, and forwarding on the primary alone, without which bpf_fib_lookup refuses
// (FWD_DISABLED). sandbox-uplink puts forwarding back when a change of all.forwarding resets it
func routePair(link netlink.Link, addrs ...netip.Addr) error {
	// Up first: IPv4 refuses a route through a device that's down
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("Set %s up: %w", link.Attrs().Name, err)
	}
	for _, a := range addrs {
		dst := netip.PrefixFrom(a, a.BitLen())
		r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: prefixNet(dst), Scope: netlink.SCOPE_LINK}
		if err := netlink.RouteAdd(r); err != nil {
			return fmt.Errorf("Route %v to %s: %w", dst, link.Attrs().Name, err)
		}
	}
	_, err := uplink.Forward(link.Attrs().Name)
	return err
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// hostAddrs are the addresses on the devices of the host and those it has a host route to (a primary that an up
// killed before it pinned keeps its routes until sandbox-uplink deletes it), which no sandbox may take
func hostAddrs() (map[netip.Addr]bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("List the host addresses: %w", err)
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("List the host routes: %w", err)
	}
	m := map[netip.Addr]bool{}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			m[ip.Unmap()] = true
		}
	}
	for _, a := range hostRoutes(routes) {
		m[a] = true
	}
	return m, nil
}

// hostRoutes are the destinations of the routes to a single address, /32 or /128
func hostRoutes(routes []netlink.Route) []netip.Addr {
	var as []netip.Addr
	for _, r := range routes {
		if r.Dst == nil {
			continue
		}
		ones, bits := r.Dst.Mask.Size()
		if ip, ok := netip.AddrFromSlice(r.Dst.IP); ok && bits > 0 && ones == bits {
			as = append(as, ip.Unmap())
		}
	}
	return as
}
