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
#include "../../internal/uplink/uplink.bpf.h"

#define AF_INET 2
#define AF_INET6 10
// The flags byte of the TCP header
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_ACK 0x10
// How long a flow of a granted port lives without a packet of the host: TCP an hour, a TCP flow the host sent a FIN on
// and UDP 2 minutes (roughly conntrack's established, fin_wait and udp_stream timeouts)
#define IDLE_TCP (3600ULL * 1000000000)
#define IDLE_SHORT (120ULL * 1000000000)
// Per sandbox, sends a second and the burst: packets that make the host resolve a neighbour it doesn't know (each a
// neighbour table entry), and mDNS queries copied out
#define NEIGH_RATE 16
#define NEIGH_BURST 64
#define MDNS_RATE 10
#define MDNS_BURST 20

// bpf_fib_lookup and bpf_redirect_neigh want a GPL-compatible program, which the kernel takes this for (license.h)
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// This sandbox (internal/uplink.Sandbox): its addresses, the ifindex of its primary and the uid of its owner
struct sandbox {
	struct addr v4, v6;
	__u32 primary, uid;
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
// (internal/uplink.UplinksMap). A sandbox packet leaves through the one in gateways alone: what the host routes through
// another is dropped
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
// When a packet of the host on the flow last passed (bpf_ktime_get_boot_ns), and whether the host sent a FIN on it
struct seen {
	__u64 at;
	__u8 fin, pad[7];
};
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, struct flow);
	__type(value, struct seen);
} flows SEC(".maps");

// The rate limits of this sandbox (allow): per limit (LIMIT_NEIGH, LIMIT_MDNS) when the next send is due, in
// bpf_ktime_get_boot_ns
enum { LIMIT_NEIGH, LIMIT_MDNS };
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} limits SEC(".maps");

// Whether a send fits the limit of rate a second with burst: GCRA, a token bucket in one word that a compare and swap
// updates, so two CPUs can't both take the last token. Losing the race four times in a row counts as over the limit
static __always_inline int allow(__u32 limit, __u64 rate, __u64 burst)
{
	__u64 *due = bpf_map_lookup_elem(&limits, &limit);
	if (!due)
		return 0;
	__u64 now = bpf_ktime_get_boot_ns(), step = 1000000000 / rate;
	for (int i = 0; i < 4; i++) {
		__u64 old = *(volatile __u64 *)due, next = (old > now ? old : now) + step;
		if (next - now > burst * step)
			return 0;
		if (__sync_val_compare_and_swap(due, old, next) == old)
			return 1;
	}
	return 0;
}

static __always_inline int mapped(const struct addr *a)
{
	return !a->w[0] && !a->w[1] && a->w[2] == bpf_htonl(0xffff);
}

struct pkt {
	struct addr src, dst;
	__be32 flowinfo; // IPv4: the TOS
	__u8 family, proto, ports, tcp_flags;
	__u16 sport, dport;
};

// Parses an IPv4 or IPv6 packet past the Ethernet header, its TCP or UDP ports when they follow the IP header
// directly (not for fragments, IPv4 options or IPv6 extension headers) in the linear part. 0 for anything else
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
	// TCP ports only with the whole TCP header in the linear part, its flags included: port-less, it reaches no flow
	// (peer) and no port (primary), so a SYN whose flags lie past the linear part can't pass as a reply
	if (p->proto == IPPROTO_TCP) {
		struct tcphdr *t = l4;
		if ((void *)(t + 1) > end)
			return 1;
		p->tcp_flags = ((__u8 *)t)[13];
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

// Where cloud metadata services listen: link-local addresses, 169.254.0.0/16 (169.254.169.254) and fe80::/10, the
// CGNAT one of Alibaba, 100.100.100.200, and the ULAs of AWS (fd00:ec2::254), GCP (fd20:ce::254) and OCI
// (fd00:c1::a9fe:a9fe)
static __always_inline int metadata(const struct addr *a)
{
	if (mapped(a))
		return (a->w[3] & bpf_htonl(0xffff0000)) == bpf_htonl(0xa9fe0000) || a->w[3] == bpf_htonl(0x646464c8);
	if (!a->w[1] && !a->w[2] &&
	    ((a->w[0] == bpf_htonl(0xfd000ec2) && a->w[3] == bpf_htonl(0x254)) ||
	     (a->w[0] == bpf_htonl(0xfd2000ce) && a->w[3] == bpf_htonl(0x254)) ||
	     (a->w[0] == bpf_htonl(0xfd0000c1) && a->w[3] == bpf_htonl(0xa9fea9fe))))
		return 1;
	return a->b[0] == 0xfe && (a->b[1] & 0xc0) == 0x80;
}

// Multicast (224.0.0.0/4, ff00::/8) and the IPv4 limited broadcast, which match the default route in the lookup
static __always_inline int multi(const struct pkt *p)
{
	if (p->family == AF_INET)
		return p->dst.w[3] == 0xffffffff || (p->dst.w[3] & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000);
	return p->dst.b[0] == 0xff;
}

static __always_inline int zero(const struct addr *a)
{
	return !a->w[0] && !a->w[1] && !a->w[2] && !a->w[3];
}

// The einat uplink with the default route of the family (0 IPv4, 1 IPv6), while it is in the uplinks map
static __always_inline struct gateway *default_gw(__u32 fam)
{
	struct gateway *gw = bpf_map_lookup_elem(&gateways, &fam);
	if (!gw || !gw->ifindex || !bpf_map_lookup_elem(&uplinks, &gw->ifindex))
		return 0;
	return gw;
}

// Whether the host socket a UDP reply of the sandbox goes to is connected to the sandbox address and port it comes
// from, as the one that started the flow is (primary): a flow outlives its socket, and a socket bound to its port after
// it closed gets nothing unless it connected to the sandbox itself (bpf_sock has no uid to compare). The lookup runs in
// the netns of skb->dev, the primary
static __always_inline int connected(struct __sk_buff *skb, const struct pkt *p)
{
	struct bpf_sock_tuple t = {};
	struct bpf_sock *sk;
	if (p->family == AF_INET) {
		t.ipv4.saddr = p->src.w[3];
		t.ipv4.daddr = p->dst.w[3];
		t.ipv4.sport = bpf_htons(p->sport);
		t.ipv4.dport = bpf_htons(p->dport);
		sk = bpf_sk_lookup_udp(skb, &t, sizeof(t.ipv4), BPF_F_CURRENT_NETNS, 0);
	} else {
		__builtin_memcpy(t.ipv6.saddr, p->src.w, 16);
		__builtin_memcpy(t.ipv6.daddr, p->dst.w, 16);
		t.ipv6.sport = bpf_htons(p->sport);
		t.ipv6.dport = bpf_htons(p->dport);
		sk = bpf_sk_lookup_udp(skb, &t, sizeof(t.ipv6), BPF_F_CURRENT_NETNS, 0);
	}
	if (!sk)
		return 0;
	// A connected UDP socket is in TCP_ESTABLISHED. dst_ip4 also holds the IPv4 peer of an IPv6 socket
	int ok = sk->state == BPF_TCP_ESTABLISHED && sk->dst_port == bpf_htons(p->sport);
	if (p->family == AF_INET)
		ok = ok && sk->dst_ip4 == p->src.w[3];
	else
		ok = ok && sk->dst_ip6[0] == p->src.w[0] && sk->dst_ip6[1] == p->src.w[1] &&
		     sk->dst_ip6[2] == p->src.w[2] && sk->dst_ip6[3] == p->src.w[3];
	bpf_sk_release(sk);
	return ok;
}

#include "mdns.bpf.h"

// Sandbox to host: leaves only through an einat uplink, reaches the host only as a reply on a recorded flow
SEC("tc")
int peer(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct sandbox *sb = bpf_map_lookup_elem(&sandbox, &key);
	struct pkt p = {};
	// A VLAN tag netkit offloaded to the skb (a VLAN device on eth0) would go out with the packet
	if (!sb || skb->vlan_present || !parse(skb, &p))
		return NETKIT_DROP;
	if (multi(&p)) {
		if (mdns && to_mdns(&p))
			query_out(skb, &p);
		return NETKIT_DROP;
	}
	// No source but its own: einat binds what leaves to its source, and the flows are keyed without it
	if (!own(sb, &p.src))
		return NETKIT_DROP;
	// Never to a cloud metadata address: einat would NAT it to the host address, which a metadata service there answers
	// with the credentials of the host
	if (metadata(&p.dst))
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
	// Without BPF_FIB_LOOKUP_SKIP_NEIGH, so NO_NEIGH tells a next hop the host has no neighbour entry for
	long rc = bpf_fib_lookup(skb, &fib, sizeof(fib), 0);
	if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
		// Local delivery: only a reply on a flow the host opened to a port still granted, within its idle timeout,
		// which only packets of the host renew (primary), so the sandbox can't keep a flow alive alone. Never a SYN:
		// the sandbox opens no connection on the tuple of a flow
		struct flow f = {.host = p.dst, .port = p.sport, .host_port = p.dport, .proto = p.proto};
		__u32 port = (__u32)p.proto << 16 | p.sport;
		struct seen *s = p.ports ? bpf_map_lookup_elem(&flows, &f) : 0;
		if (!s || !bpf_map_lookup_elem(&ports, &port) || (p.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN)
			return NETKIT_DROP;
		if (bpf_ktime_get_boot_ns() - s->at > (p.proto == IPPROTO_TCP && !s->fin ? IDLE_TCP : IDLE_SHORT))
			return NETKIT_DROP;
		if (p.proto == IPPROTO_UDP && !connected(skb, &p))
			return NETKIT_DROP;
		return NETKIT_PASS;
	}
	if (rc != BPF_FIB_LKUP_RET_SUCCESS && rc != BPF_FIB_LKUP_RET_NO_NEIGH)
		return NETKIT_DROP;
	struct gateway *gw = default_gw(p.family == AF_INET6);
	if (!gw)
		return NETKIT_DROP;
	struct bpf_redir_neigh nh = {.nh_family = fib.family};
	if (bpf_map_lookup_elem(&uplinks, &fib.ifindex)) {
		// Only through the uplink with the default route, as the macvlan did: never onto the subnets of the other
		// NICs (storage, BMC, point-to-point links)
		if (fib.ifindex != gw->ifindex)
			return NETKIT_DROP;
		// The lookup left the next hop in the destination
		struct addr hop = {};
		if (fib.family == AF_INET) {
			nh.ipv4_nh = fib.ipv4_dst;
			hop.w[2] = bpf_htonl(0xffff);
			hop.w[3] = fib.ipv4_dst;
		} else {
			__builtin_memcpy(nh.ipv6_nh, fib.ipv6_dst, 16);
			__builtin_memcpy(hop.b, fib.ipv6_dst, 16);
		}
		// An on-link next hop the host has no neighbour entry for: the redirect creates one, so a sandbox sending to
		// random addresses of the subnet (a /64) would fill the neighbour table of the host. The gateway and known
		// neighbours pass
		if (rc == BPF_FIB_LKUP_RET_NO_NEIGH && !same(&hop, &gw->gw) && !allow(LIMIT_NEIGH, NEIGH_RATE, NEIGH_BURST))
			return NETKIT_DROP;
		// TC_ACT_REDIRECT, or TC_ACT_SHOT (NETKIT_DROP) when it fails
		return bpf_redirect_neigh(fib.ifindex, &nh, sizeof(nh), 0);
	}
	// The host routes it through another device: a full-tunnel VPN, a bridge, a mesh. Never into it: out through the
	// einat uplink with the default route, to its gateway, as a host on the LAN of that uplink would send it
	if (zero(&gw->gw))
		return bpf_redirect_neigh(gw->ifindex, NULL, 0, 0);
	if (p.family == AF_INET)
		nh.ipv4_nh = gw->gw.w[3];
	else
		__builtin_memcpy(nh.ipv6_nh, gw->gw.b, 16);
	return bpf_redirect_neigh(gw->ifindex, &nh, sizeof(nh), 0);
}

// Host to sandbox: only what processes of the owner of the sandbox send (a socket of theirs attached; forwarded packets
// and the replies of the kernel's control sockets have none) over TCP or UDP to a granted port. A flow starts only with
// a TCP SYN without ACK or a datagram of a connected UDP socket, and is recorded for the replies; anything else passes
// only on a recorded flow, which it renews. So a packet from a sandbox address that reached the host some other way (a
// bridge without rp_filter) and that a listener answers starts nothing. A TCP RST ends the flow. With mdns set, also
// the mDNS responses pre copied here
SEC("tc")
int primary(struct __sk_buff *skb)
{
	__u32 key = 0;
	struct sandbox *sb = bpf_map_lookup_elem(&sandbox, &key);
	struct pkt p = {};
	// The primary leaves both to this program (NETKIT_SCRUB_NONE, pair.go), for the mark; the sandbox gets neither
	__u32 mark = skb->mark;
	skb->mark = 0;
	skb->priority = 0;
	if (!sb || skb->vlan_present || !parse(skb, &p) || !p.ports)
		return NETKIT_DROP;
	if (mark == MDNS_MARK)
		return mdns && to_mdns(&p) && p.sport == MDNS_PORT ? NETKIT_PASS : NETKIT_DROP;
	// overflowuid for a socket that isn't a full one (a request or timewait socket)
	struct bpf_sock *sk = skb->sk;
	if (!sk || bpf_get_socket_uid(skb) != sb->uid)
		return NETKIT_DROP;
	if (!own(sb, &p.dst))
		return NETKIT_DROP;
	__u32 port = (__u32)p.proto << 16 | p.dport;
	if (!bpf_map_lookup_elem(&ports, &port))
		return NETKIT_DROP;
	struct flow f = {.host = p.src, .port = p.dport, .host_port = p.sport, .proto = p.proto};
	__u8 fl = p.tcp_flags;
	struct seen *s = bpf_map_lookup_elem(&flows, &f);
	if (p.proto == IPPROTO_TCP && fl & TCP_RST) {
		if (!s)
			return NETKIT_DROP;
		bpf_map_delete_elem(&flows, &f);
		return NETKIT_PASS;
	}
	int start = p.proto == IPPROTO_TCP ? (fl & (TCP_SYN | TCP_ACK)) == TCP_SYN : 0;
	if (p.proto == IPPROTO_UDP) {
		// A connected UDP socket is in TCP_ESTABLISHED
		sk = bpf_sk_fullsock(sk);
		start = sk && sk->state == BPF_TCP_ESTABLISHED;
	}
	// A SYN starts the flow again, FIN mark cleared
	if (start && (!s || p.proto == IPPROTO_TCP)) {
		struct seen n = {.at = bpf_ktime_get_boot_ns()};
		bpf_map_update_elem(&flows, &f, &n, BPF_ANY);
		return NETKIT_PASS;
	}
	if (!s)
		return NETKIT_DROP;
	// In place: two CPUs updating at once can't lose the FIN mark. The FIN of the host shortens the timeout until a SYN
	// starts the flow again; deleting the flow would drop the rest of the close (and a half-closed connection) of the
	// sandbox
	s->at = bpf_ktime_get_boot_ns();
	if (fl & TCP_FIN)
		s->fin = 1;
	return NETKIT_PASS;
}
