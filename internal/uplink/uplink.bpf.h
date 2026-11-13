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
