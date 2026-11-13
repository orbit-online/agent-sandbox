// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Built by nix/packages/netns-netkit, not by go build:
//go:build ignore

// The programs on the netkit pair of a sandbox (models/network.als), attached through the primary in the host netns:
// `peer` runs when the sandbox sends, `primary` when the host sends to it. Both ends have policy drop, and neither
// program ends on NETKIT_NEXT, which netkit counts as pass. netkit in L3 mode still carries a 14-byte Ethernet header
// (zero MACs), so both parse past one.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define AF_INET 2
#define AF_INET6 10

// bpf_fib_lookup and bpf_redirect_neigh want a GPL-compatible program, which the kernel takes this for (license.h)
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// An address in network order, IPv4 mapped into ::ffff:0:0/96 (internal/uplink.Key)
struct addr {
	union {
		__u8 b[16];
		__be32 w[4];
	};
};

// This sandbox (internal/uplink.Sandbox): its addresses and the ifindex of its primary
struct sandbox {
	struct addr v4, v6;
	__u32 primary;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct sandbox);
} sandbox SEC(".maps");

// The einat uplinks, which sandbox-uplink keeps current and netns-netkit puts in place of this one
// (internal/uplink.UplinksMap): the only devices a sandbox packet leaves through
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} uplinks SEC(".maps");

// Per family (0 IPv4, 1 IPv6) the einat uplink with the default route and its gateway, kept by sandbox-uplink like
// uplinks (internal/uplink.GatewaysMap). Ifindex 0: none
struct gateway {
	__u32 ifindex;
	struct addr gw;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct gateway);
} gateways SEC(".maps");

// The ports granted for forwarding from the host: protocol << 16 | port
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u32);
	__type(value, __u8);
} ports SEC(".maps");

// Flows the host opened to a granted port, as the replies of the sandbox carry them. Ports in host order
struct flow {
	struct addr host;
	__u16 port, host_port;
	__u8 proto, pad[3];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow);
	__type(value, __u8);
} flows SEC(".maps");

static __always_inline int mapped(const struct addr *a)
{
	return !a->w[0] && !a->w[1] && a->w[2] == bpf_htonl(0xffff);
}

struct pkt {
	struct addr src, dst;
	__be32 flowinfo; // IPv4: the TOS
	__u8 family, proto, ports;
	__u16 sport, dport;
};

// Parses an IPv4 or IPv6 packet past the Ethernet header, its TCP or UDP ports when they follow the IP header
// directly (not for fragments, IPv4 options or IPv6 extension headers). 0 for anything else
static __always_inline int parse(struct __sk_buff *skb, struct pkt *p)
{
	void *data = (void *)(long)skb->data + ETH_HLEN, *end = (void *)(long)skb->data_end;
	void *l4;
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data;
		if ((void *)(ip + 1) > end)
			return 0;
		p->family = AF_INET;
		p->src = (struct addr){.w = {0, 0, bpf_htonl(0xffff), ip->saddr}};
		p->dst = (struct addr){.w = {0, 0, bpf_htonl(0xffff), ip->daddr}};
		p->flowinfo = ip->tos;
		p->proto = ip->protocol;
		// Ports only without IP options: a variable offset is pointer arithmetic the verifier refuses without
		// CAP_PERFMON, and Linux sends none
		if (ip->ihl != 5 || ip->frag_off & bpf_htons(0x3fff))
			return 1;
		l4 = ip + 1;
	} else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data;
		if ((void *)(ip6 + 1) > end)
			return 0;
		p->family = AF_INET6;
		__builtin_memcpy(p->src.b, &ip6->saddr, 16);
		__builtin_memcpy(p->dst.b, &ip6->daddr, 16);
		// IPv4-mapped addresses are IPv4's here
		if (mapped(&p->src) || mapped(&p->dst))
			return 0;
		p->flowinfo = *(__be32 *)ip6 & bpf_htonl(0x0fffffff);
		p->proto = ip6->nexthdr;
		l4 = ip6 + 1;
	} else {
		return 0;
	}
	if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP) {
		// TCP and UDP both start with the ports
		struct udphdr *u = l4;
		if ((void *)(u + 1) <= end) {
			p->ports = 1;
			p->sport = bpf_ntohs(u->source);
			p->dport = bpf_ntohs(u->dest);
		}
	}
	return 1;
}

static __always_inline int same(const struct addr *a, const struct addr *b)
{
	return a->w[0] == b->w[0] && a->w[1] == b->w[1] && a->w[2] == b->w[2] && a->w[3] == b->w[3];
}

// Whether a is an address of sb. Both compared, as parse leaves IPv4-mapped addresses to IPv4: picking one by the
// family is a pointer the verifier refuses without CAP_PERFMON
static __always_inline int own(const struct sandbox *sb, const struct addr *a)
{
	return same(a, &sb->v4) || same(a, &sb->v6);
}

// Multicast (224.0.0.0/4, ff00::/8) and the IPv4 limited broadcast, which match the default route in the lookup
static __always_inline int multi(const struct pkt *p)
{
	if (p->family == AF_INET)
		return p->dst.w[3] == 0xffffffff || (p->dst.w[3] & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000);
	return p->dst.b[0] == 0xff;
}

// Sandbox to host: leaves only through an einat uplink, reaches the host only as a reply on a recorded flow
SEC("tc")
int peer(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct sandbox *sb = bpf_map_lookup_elem(&sandbox, &zero);
	struct pkt p = {};
	if (!sb || !parse(skb, &p) || multi(&p))
		return NETKIT_DROP;
	// No source but its own: einat binds what leaves to its source, and the flows are keyed without it
	if (!own(sb, &p.src))
		return NETKIT_DROP;
	// tot_len stays 0: GSO packets exceed the MTU otherwise (FRAG_NEEDED). skb->ifindex is the primary, so the lookup
	// runs in the host netns, which needs forwarding on the primary (FWD_DISABLED otherwise)
	struct bpf_fib_lookup fib = {.family = p.family, .l4_protocol = p.proto, .ifindex = skb->ifindex};
	if (p.ports) {
		fib.sport = bpf_htons(p.sport);
		fib.dport = bpf_htons(p.dport);
	}
	if (p.family == AF_INET) {
		fib.tos = p.flowinfo;
		fib.ipv4_src = p.src.w[3];
		fib.ipv4_dst = p.dst.w[3];
	} else {
		fib.flowinfo = p.flowinfo;
		__builtin_memcpy(fib.ipv6_src, p.src.b, 16);
		__builtin_memcpy(fib.ipv6_dst, p.dst.b, 16);
	}
	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), BPF_FIB_LOOKUP_SKIP_NEIGH);
	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
		// Local delivery: only a reply on a flow the host opened to a granted port
		struct flow f = {.host = p.dst, .port = p.sport, .host_port = p.dport, .proto = p.proto};
		if (p.ports && bpf_map_lookup_elem(&flows, &f))
			return NETKIT_PASS;
		return NETKIT_DROP;
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS)
		return NETKIT_DROP;
	struct bpf_redir_neigh nh = {.nh_family = fib.family};
	if (bpf_map_lookup_elem(&uplinks, &fib.ifindex)) {
		// The lookup left the next hop in the destination
		if (fib.family == AF_INET)
			nh.ipv4_nh = fib.ipv4_dst;
		else
			__builtin_memcpy(nh.ipv6_nh, fib.ipv6_dst, 16);
		// TC_ACT_REDIRECT, or TC_ACT_SHOT (NETKIT_DROP) when it fails
		return bpf_redirect_neigh(fib.ifindex, &nh, sizeof(nh), 0);
	}
	// The host routes it through another device: a full-tunnel VPN, a bridge, a mesh. Never into it: out through the
	// einat uplink with the default route, to its gateway, as a macvlan on that uplink would send it
	__u32 fam = p.family == AF_INET6;
	struct gateway *gw = bpf_map_lookup_elem(&gateways, &fam);
	if (!gw || !gw->ifindex || !bpf_map_lookup_elem(&uplinks, &gw->ifindex))
		return NETKIT_DROP;
	if (!gw->gw.w[0] && !gw->gw.w[1] && !gw->gw.w[2] && !gw->gw.w[3])
		return bpf_redirect_neigh(gw->ifindex, NULL, 0, 0);
	if (p.family == AF_INET)
		nh.ipv4_nh = gw->gw.w[3];
	else
		__builtin_memcpy(nh.ipv6_nh, gw->gw.b, 16);
	return bpf_redirect_neigh(gw->ifindex, &nh, sizeof(nh), 0);
}

// Host to sandbox: only what the host itself sends (a socket attached; forwarded packets have none) over TCP or UDP to
// a granted port, recorded for the replies
SEC("tc")
int primary(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct sandbox *sb = bpf_map_lookup_elem(&sandbox, &zero);
	struct pkt p = {};
	if (!sb || !skb->sk || !parse(skb, &p) || !p.ports)
		return NETKIT_DROP;
	if (!own(sb, &p.dst))
		return NETKIT_DROP;
	__u32 port = (__u32)p.proto << 16 | p.dport;
	if (!bpf_map_lookup_elem(&ports, &port))
		return NETKIT_DROP;
	struct flow f = {.host = p.src, .port = p.dport, .host_port = p.sport, .proto = p.proto};
	__u8 one = 1;
	bpf_map_update_elem(&flows, &f, &one, BPF_ANY);
	return NETKIT_PASS;
}
