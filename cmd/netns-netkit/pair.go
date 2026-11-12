package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
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
	return forward(link.Attrs().Name)
}

// forward turns forwarding on for dev, IPv4 and IPv6
func forward(dev string) error {
	for _, f := range []string{"ipv4", "ipv6"} {
		path := "/proc/sys/net/" + f + "/conf/" + dev + "/forwarding"
		if err := os.WriteFile(path, []byte("1"), 0); err != nil {
			return fmt.Errorf("Turn %s forwarding on for %s: %w", f, dev, err)
		}
	}
	return nil
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

// hostAddrs are the addresses on the devices of the host, which no sandbox may take
func hostAddrs() (map[netip.Addr]bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("List the host addresses: %w", err)
	}
	m := map[netip.Addr]bool{}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP); ok {
			m[ip.Unmap()] = true
		}
	}
	return m, nil
}
