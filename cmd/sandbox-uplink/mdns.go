package main

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

// mdnsGroups holds the mDNS groups, 224.0.0.251 and ff02::fb, joined on every uplink, so the NIC takes the responses
// pre copies to the sandboxes (its multicast filter drops groups nobody joined) and IGMP and MLD snooping switches
// forward them. The sockets bind no port: the host stack receives nothing through them
type mdnsGroups struct{ v4, v6 int }

func openMdnsGroups() (*mdnsGroups, error) {
	v4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("Open a socket for the mDNS group: %w", err)
	}
	v6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("Open a socket for the mDNS group: %w", err)
	}
	return &mdnsGroups{v4, v6}, nil
}

// join joins both groups on the uplink of ifindex; a family the uplink lacks only logs
func (g *mdnsGroups) join(uplink string, ifindex int) {
	err := unix.SetsockoptIPMreqn(g.v4, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP,
		&unix.IPMreqn{Multiaddr: [4]byte{224, 0, 0, 251}, Ifindex: int32(ifindex)})
	if err != nil {
		slog.Warn("Join the IPv4 mDNS group", "uplink", uplink, "err", err)
	}
	err = unix.SetsockoptIPv6Mreq(g.v6, unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP,
		&unix.IPv6Mreq{Multiaddr: [16]byte{0: 0xff, 1: 0x02, 15: 0xfb}, Interface: uint32(ifindex)})
	if err != nil {
		slog.Warn("Join the IPv6 mDNS group", "uplink", uplink, "err", err)
	}
}
