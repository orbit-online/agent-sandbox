// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Built by nix/packages/sandbox-uplink, not by go build:
//go:build ignore

// The programs of the sandbox network on each einat uplink (models/network.als): on tcx ingress `pre` ahead of einat and
// `post` after it, on tcx egress `egress` after it. einat ends its reverse SNAT with TCX_NEXT, so post sees the
// rewritten destination. pre also copies the mDNS responses from the LAN to the sandboxes that take them.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "../../internal/uplink/uplink.bpf.h"

// bpf_redirect_peer and every kfunc want a GPL-compatible program, which the kernel takes this for (license.h)
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Set at load from internal/uplink: the sandboxes' IPv4 block and IPv6 /48
volatile const __be32 v4_net, v4_mask;
volatile const __u8 v6_block[6];

// The registration map (internal/uplink.SandboxesMap): a sandbox address to the ifindex of its netkit primary. Pinned,
// so it outlives this program and the per-launcher helper writes it. Two entries a sandbox (IPv4 and IPv6): 512
// sandboxes, 32 users at the limit of internal/uplink.MaxSandboxesPerUID (16); an up past that fails to register
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct addr);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sandboxes SEC(".maps");

// The netkit primaries of the sandboxes with mDNS (internal/uplink.MdnsMap): ifindex to 1, written by the per-launcher
// helper like sandboxes
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} mdns SEC(".maps");

// What pre leaves for post in skb->cb[0] and cb[1] (the qdisc control block, which einat leaves alone), so the mark of
// the host stays as it came. Two words, as the block comes in with what GRO left in it, not zeroed
#define PASSED0 0x5a6d0001
#define PASSED1 0x7e3c91a5

// Makes the IP header of an IPv4 or IPv6 frame readable in place, by its EtherType (skb->protocol is the sender's to
// pick on AF_PACKET). The stack keeps it in the linear part; a frame built otherwise (AF_PACKET with a vnet header, a
// driver) may not. 0 when the frame is shorter than its headers: the programs drop it, as they can't tell its addresses
static __always_inline int pull(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	__be16 proto;
	if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &proto, 2))
		return 1;
	// Each length apart: a variable offset is pointer arithmetic the verifier refuses without CAP_PERFMON
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + ETH_HLEN;
		return (void *)(ip + 1) <= end || !bpf_skb_pull_data(skb, ETH_HLEN + sizeof(*ip));
	}
	if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + ETH_HLEN;
		return (void *)(ip6 + 1) <= end || !bpf_skb_pull_data(skb, ETH_HLEN + sizeof(*ip6));
	}
	return 1;
}

// The source and destination of an Ethernet frame carrying IPv4 or IPv6, IPv4 mapped; 0 for anything else.
// sandbox-uplink attaches to Ethernet-framed uplinks alone (ARPHRD_ETHER: Ethernet and Wi-Fi)
static __always_inline int addrs(struct __sk_buff *skb, struct addr *src, struct addr *dst)
{
	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return 0;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > end)
			return 0;
		*src = (struct addr){.w = {0, 0, bpf_htonl(0xffff), ip->saddr}};
		*dst = (struct addr){.w = {0, 0, bpf_htonl(0xffff), ip->daddr}};
		return 1;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > end)
			return 0;
		__builtin_memcpy(src->b, &ip6->saddr, 16);
		__builtin_memcpy(dst->b, &ip6->daddr, 16);
		return 1;
	}
	return 0;
}

// Whether an address is in the sandboxes' IPv4 block or IPv6 /48, IPv4 mapped too
static __always_inline int v4_in(__be32 a)
{
	return (a & v4_mask) == v4_net;
}
static __always_inline int v6_in(const struct in6_addr *a)
{
	if (!a->s6_addr32[0] && !a->s6_addr32[1] && a->s6_addr32[2] == bpf_htonl(0xffff))
		return v4_in(a->s6_addr32[3]);
	for (int i = 0; i < 6; i++)
		if (a->s6_addr[i] != v6_block[i])
			return 0;
	return 1;
}

// Whether skb carries a source or destination in the sandbox blocks, read from the headers in place: copied out for
// both ends, the unprivileged verifier refuses how clang spills the pointers
static __always_inline int sandbox_end(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return 0;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		return (void *)(ip + 1) <= end && (v4_in(ip->saddr) || v4_in(ip->daddr));
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		return (void *)(ip6 + 1) <= end && (v6_in(&ip6->saddr) || v6_in(&ip6->daddr));
	}
	return 0;
}

// Whether skb is an mDNS response to the group, 224.0.0.251 or ff02::fb, from and to port 5353: QR set in the DNS
// header after a fixed IP header
static __always_inline int mdns_response(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct udphdr *udp;
	if ((void *)(eth + 1) > end)
		return 0;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > end || ip->ihl != 5 || ip->frag_off & bpf_htons(0x3fff) ||
		    ip->protocol != IPPROTO_UDP || ip->daddr != bpf_htonl(0xe00000fb))
			return 0;
		udp = (void *)(ip + 1);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > end || ip6->nexthdr != IPPROTO_UDP ||
		    ip6->daddr.s6_addr32[0] != bpf_htonl(0xff020000) || ip6->daddr.s6_addr32[1] ||
		    ip6->daddr.s6_addr32[2] || ip6->daddr.s6_addr32[3] != bpf_htonl(0xfb))
			return 0;
		udp = (void *)(ip6 + 1);
	} else {
		return 0;
	}
	// The UDP header and the DNS ID and flags
	__u8 *dns = (void *)(udp + 1);
	if ((void *)(dns + 3) > end)
		return 0;
	return udp->source == bpf_htons(MDNS_PORT) && udp->dest == bpf_htons(MDNS_PORT) && dns[2] & 0x80;
}

struct copy {
	struct __sk_buff *skb;
};

// A copy of the response to the egress of a primary, where the `primary` program takes the mark
static long copy_in(void *map, __u32 *primary, __u8 *on, struct copy *c)
{
	bpf_clone_redirect(c->skb, *primary, 0);
	return 0;
}

// Uplink ingress, ahead of einat: nothing from outside is addressed to a sandbox before einat rewrote it (network.als
// PreDrop, N3), nor comes from a sandbox address (PreSrcDrop). What passes is marked for post (Handoff)
SEC("tc")
int pre(struct __sk_buff *skb)
{
	if (!pull(skb) || sandbox_end(skb))
		return TCX_DROP;
	// The response goes on to the host stack too, with its mark as it came. Queries from the LAN aren't copied, nor
	// anything with a VLAN tag
	if (!skb->vlan_present && mdns_response(skb)) {
		struct copy c = {skb};
		__u32 mark = skb->mark;
		skb->mark = MDNS_MARK;
		bpf_for_each_map_elem(&mdns, copy_in, &c, 0);
		skb->mark = mark;
	}
	skb->cb[0] = PASSED0;
	skb->cb[1] = PASSED1;
	return TCX_NEXT;
}

// Uplink ingress, after einat: a reply einat reverse-NATed to a registered sandbox goes straight to its netkit peer,
// bypassing the host stack and netfilter. Only what pre passed (Handoff, N3): with pre detached, nothing addressed to
// a sandbox gets through. A sandbox destination that isn't registered is dropped too, and so is a packet with a VLAN
// tag, which the sandbox would get with it
SEC("tc")
int post(struct __sk_buff *skb)
{
	struct addr src, dst;
	int passed = skb->cb[0] == PASSED0 && skb->cb[1] == PASSED1;
	if (passed)
		skb->cb[0] = skb->cb[1] = 0;
	if (!pull(skb))
		return TCX_DROP;
	if (!addrs(skb, &src, &dst) || !v6_in((void *)&dst))
		return TCX_NEXT;
	__u32 *primary = bpf_map_lookup_elem(&sandboxes, &dst);
	if (!passed || skb->vlan_present || !primary)
		return TCX_DROP;
	return bpf_redirect_peer(*primary, 0);
}

// Uplink egress, after einat: a sandbox source einat left alone (einat stopped or restarting) never leaves the host
// (EgressSrcDrop, N2, N5)
SEC("tc")
int egress(struct __sk_buff *skb)
{
	struct addr src, dst;
	if (!pull(skb) || (addrs(skb, &src, &dst) && v6_in((void *)&src)))
		return TCX_DROP;
	return TCX_NEXT;
}
