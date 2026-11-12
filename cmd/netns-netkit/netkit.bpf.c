// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Built by nix/packages/netns-netkit, not by go build:
//go:build ignore

// The programs on the netkit pair of a sandbox (models/network.als), attached through the primary in the host netns:
// `peer` runs when the sandbox sends, `primary` when the host sends to it. Both ends have policy drop, and neither
// program ends on NETKIT_NEXT, which netkit counts as pass. netkit in L3 mode still carries a 14-byte Ethernet header
// (zero MACs), so both parse past one. With mdns set, peer copies the mDNS queries of the sandbox out of the uplink
// with the default route, and primary passes the mDNS responses pre (cmd/sandbox-uplink/uplink.bpf.c) copies in.
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
#define MDNS_PORT 5353
// The mark of the mDNS responses pre copies to the primaries (cmd/sandbox-uplink/uplink.bpf.c)
#define MDNS_MARK 0x5a6d0002
// The labels and questions peer walks in an mDNS query, all questions together: a query with more isn't copied out
#define MDNS_STEPS 128

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

// Set at load by netns-netkit up --mdns
volatile const __u8 mdns;

// The einat uplinks, which sandbox-uplink keeps current and netns-netkit puts in place of this one
// (internal/uplink.UplinksMap): the only devices a sandbox packet leaves through
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} uplinks SEC(".maps");

// Per family (0 IPv4, 1 IPv6) the einat uplink with the default route and its gateway, kept by sandbox-uplink like
// uplinks (internal/uplink.GatewaysMap). Ifindex 0: none. src and mac are what mDNS queries leave the uplink with:
// the first IPv4 address of the uplink or its IPv6 link-local one (zero: none), and the MAC
struct gateway {
	__u32 ifindex;
	struct addr gw, src;
	__u8 mac[6], pad[2];
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

// Whether p goes to the mDNS group, 224.0.0.251 or ff02::fb, port 5353
static __always_inline int to_mdns(const struct pkt *p)
{
	if (p->proto != IPPROTO_UDP || !p->ports || p->dport != MDNS_PORT)
		return 0;
	if (p->family == AF_INET)
		return p->dst.w[3] == bpf_htonl(0xe00000fb);
	return p->dst.w[0] == bpf_htonl(0xff020000) && !p->dst.w[1] && !p->dst.w[2] && p->dst.w[3] == bpf_htonl(0xfb);
}

struct dnshdr {
	__be16 id;
	__u8 flags[2];
	__be16 qd, an, ns, ar;
};

// Copies an mDNS query of the sandbox out of the einat uplink with the default route of its family, as the uplink
// sends one: from the uplink address and port 5353, which einat leaves alone (an external source, a port outside its
// range), so responders answer to the group (RFC 6762 section 6); from another port it is a legacy unicast query, whose
// answer goes to the port alone. Not a response, nor a probe (an authority section, section 8.2): the sandbox claims
// no name on the LAN. The questions lose the unicast-response bit (QU, section 5.4), so the answer comes by multicast,
// which pre copies in. Packet data is read through helpers: a variable offset into it is pointer arithmetic the
// verifier refuses without CAP_PERFMON. Rewrites the packet, which peer drops after
static __always_inline void query_out(struct __sk_buff *skb, const struct pkt *p)
{
	__u32 fam = p->family == AF_INET6;
	struct gateway *gw = bpf_map_lookup_elem(&gateways, &fam);
	if (!gw || !gw->ifindex || !bpf_map_lookup_elem(&uplinks, &gw->ifindex))
		return;
	if (!gw->src.w[0] && !gw->src.w[1] && !gw->src.w[2] && !gw->src.w[3])
		return;
	// parse found the ports right after a fixed IP header
	__u32 l4 = ETH_HLEN + (fam ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
	__u32 csum = l4 + offsetof(struct udphdr, check), off = l4 + sizeof(struct udphdr);
	struct dnshdr h;
	if (bpf_skb_load_bytes(skb, off, &h, sizeof(h)))
		return;
	// QR 0 and opcode 0: a standard query
	if (h.flags[0] & 0xf8 || h.ns || !h.qd)
		return;
	off += sizeof(h);
	__u16 left = bpf_ntohs(h.qd);
	for (int i = 0; i < MDNS_STEPS && left; i++) {
		__u8 len;
		if (bpf_skb_load_bytes(skb, off, &len, 1))
			return;
		if (len && len <= 63) {
			off += len + 1;
			continue;
		}
		// The end of the name: its root label, or a compression pointer of 2 bytes. Then QTYPE and QCLASS
		if (len && (len & 0xc0) != 0xc0)
			return;
		off += len ? 2 : 1;
		__be16 cls, qm;
		if (bpf_skb_load_bytes(skb, off + 2, &cls, 2))
			return;
		qm = cls & bpf_htons(0x7fff);
		if (qm != cls &&
		    (bpf_l4_csum_replace(skb, csum, cls, qm, BPF_F_MARK_MANGLED_0 | 2) ||
		     bpf_skb_store_bytes(skb, off + 2, &qm, 2, 0)))
			return;
		off += 4;
		left--;
	}
	if (left)
		return;
	__be16 port = bpf_htons(MDNS_PORT), sport = bpf_htons(p->sport);
	if (bpf_l4_csum_replace(skb, csum, sport, port, BPF_F_MARK_MANGLED_0 | 2) ||
	    bpf_skb_store_bytes(skb, l4 + offsetof(struct udphdr, source), &port, 2, 0))
		return;
	struct ethhdr eth = {.h_proto = bpf_htons(fam ? ETH_P_IPV6 : ETH_P_IP)};
	__builtin_memcpy(eth.h_source, gw->mac, ETH_ALEN);
	if (fam) {
		// 33:33 and the low 32 bits of ff02::fb
		__u8 dst[ETH_ALEN] = {0x33, 0x33, 0, 0, 0, 0xfb};
		__builtin_memcpy(eth.h_dest, dst, ETH_ALEN);
		__s64 diff = bpf_csum_diff((__be32 *)p->src.w, 16, gw->src.w, 16, 0);
		if (diff < 0 || bpf_l4_csum_replace(skb, csum, 0, diff, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0) ||
		    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct ipv6hdr, saddr), gw->src.b, 16, 0))
			return;
	} else {
		// 01:00:5e and the low 23 bits of 224.0.0.251
		__u8 dst[ETH_ALEN] = {0x01, 0x00, 0x5e, 0, 0, 0xfb};
		__builtin_memcpy(eth.h_dest, dst, ETH_ALEN);
		__be32 from = p->src.w[3], to = gw->src.w[3];
		if (bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), from, to, 4) ||
		    bpf_l4_csum_replace(skb, csum, from, to, BPF_F_PSEUDO_HDR | BPF_F_MARK_MANGLED_0 | 4) ||
		    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr), &to, 4, 0))
			return;
	}
	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0))
		return;
	bpf_clone_redirect(skb, gw->ifindex, 0);
}

// Sandbox to host: leaves only through an einat uplink, reaches the host only as a reply on a recorded flow
SEC("tc")
int peer(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct sandbox *sb = bpf_map_lookup_elem(&sandbox, &zero);
	struct pkt p = {};
	if (!sb || !parse(skb, &p))
		return NETKIT_DROP;
	if (multi(&p)) {
		if (mdns && to_mdns(&p))
			query_out(skb, &p);
		return NETKIT_DROP;
	}
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
	// einat uplink with the default route, to its gateway, as a host on the LAN of that uplink would send it
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
// a granted port, recorded for the replies. With mdns set, also the mDNS responses pre copied here
SEC("tc")
int primary(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct sandbox *sb = bpf_map_lookup_elem(&sandbox, &zero);
	struct pkt p = {};
	// The primary leaves both to this program (NETKIT_SCRUB_NONE, pair.go), for the mark; the sandbox gets neither
	__u32 mark = skb->mark;
	skb->mark = 0;
	skb->priority = 0;
	if (!sb || !parse(skb, &p) || !p.ports)
		return NETKIT_DROP;
	if (mark == MDNS_MARK)
		return mdns && to_mdns(&p) && p.sport == MDNS_PORT ? NETKIT_PASS : NETKIT_DROP;
	if (!skb->sk)
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
