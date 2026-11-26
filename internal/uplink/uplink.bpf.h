// SPDX-License-Identifier: MIT OR GPL-2.0-only
// What the programs of cmd/netns-netkit/netkit.bpf.c and cmd/sandbox-uplink/uplink.bpf.c share
#pragma once

#define MDNS_PORT 5353
// The mark of the mDNS responses pre copies to the primaries, whose `primary` program passes them
#define MDNS_MARK 0x5a6d0002

// An address in network order, IPv4 mapped into ::ffff:0:0/96 (netip.Addr.As16)
struct addr {
	union {
		__u8 b[16];
		__be32 w[4];
	};
};

// A value of the gateways map (internal/uplink.Gateway), which sandbox-uplink keeps per family (0 IPv4, 1 IPv6): the
// einat uplink with the default route and its gateway. Ifindex 0: none. src and mac are what mDNS queries leave the
// uplink with: the first IPv4 address of the uplink or its IPv6 link-local one (zero: none), and the MAC
struct gateway {
	__u32 ifindex;
	struct addr gw, src;
	__u8 mac[6], pad[2];
};
