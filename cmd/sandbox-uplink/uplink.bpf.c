// SPDX-License-Identifier: MIT OR GPL-2.0-only
// Built by nix/packages/sandbox-uplink, not by go build:
//go:build ignore

// The programs of the sandbox network on each einat uplink (models/network.als): on tcx ingress `pre` ahead of einat and
// `post` after it, on tcx egress `egress` after it. einat ends its reverse SNAT with TCX_NEXT, so post sees the
// rewritten destination.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// bpf_redirect_peer and every kfunc want a GPL-compatible program, which the kernel takes this for (license.h)
char LICENSE[] SEC("license") = "Dual MIT/GPL";

// Set at load from internal/uplink: the sandboxes' IPv4 block and IPv6 /48
volatile const __be32 v4_net, v4_mask;
volatile const __u8 v6_block[6];

// The registration map (internal/uplink.SandboxesMap): a sandbox address, IPv4 mapped into ::ffff:0:0/96, to the
// ifindex of its netkit primary. Pinned, so it outlives this program and the per-launcher helper writes it
struct addr {
	union {
		__u8 b[16];
		__be32 w[4];
	};
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct addr);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sandboxes SEC(".maps");

// The mark pre leaves for post. skb->mark comes in 0 at tcx ingress (nothing earlier sets it) and survives einat
#define PASSED 0x5a6d0001

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

// Whether a is in the sandboxes' IPv4 block or IPv6 /48
static __always_inline int in_sandboxes(const struct addr *a)
{
	if (!a->w[0] && !a->w[1] && a->w[2] == bpf_htonl(0xffff))
		return (a->w[3] & v4_mask) == v4_net;
	for (int i = 0; i < 6; i++)
		if (a->b[i] != v6_block[i])
			return 0;
	return 1;
}

// Uplink ingress, ahead of einat: nothing from outside is addressed to a sandbox before einat rewrote it (network.als
// PreDrop, N3). What passes is marked for post (Handoff)
SEC("tc")
int pre(struct __sk_buff *skb)
{
	struct addr src, dst;
	if (addrs(skb, &src, &dst) && in_sandboxes(&dst))
		return TCX_DROP;
	skb->mark = PASSED;
	return TCX_NEXT;
}

// Uplink ingress, after einat: a reply einat reverse-NATed to a registered sandbox goes straight to its netkit peer,
// bypassing the host stack and netfilter. Only what pre passed (Handoff, N3): with pre detached, nothing addressed to
// a sandbox gets through. A sandbox destination that isn't registered is dropped too
SEC("tc")
int post(struct __sk_buff *skb)
{
	struct addr src, dst;
	int passed = skb->mark == PASSED;
	if (passed)
		skb->mark = 0;
	if (!addrs(skb, &src, &dst) || !in_sandboxes(&dst))
		return TCX_NEXT;
	__u32 *primary = bpf_map_lookup_elem(&sandboxes, &dst);
	if (!passed || !primary)
		return TCX_DROP;
	return bpf_redirect_peer(*primary, 0);
}

// Uplink egress, after einat: a sandbox source einat left alone (einat stopped or restarting) never leaves the host
// (EgressSrcDrop, N2, N5)
SEC("tc")
int egress(struct __sk_buff *skb)
{
	struct addr src, dst;
	if (addrs(skb, &src, &dst) && in_sandboxes(&src))
		return TCX_DROP;
	return TCX_NEXT;
}
