// SPDX-License-Identifier: MIT OR GPL-2.0-only
// The mDNS code of `peer` (netkit.bpf.c), which includes it after its maps and helpers
#pragma once

// The labels and questions peer walks in an mDNS query, all questions together: a query with more isn't copied out
#define MDNS_STEPS 128

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

// Copies an mDNS query of the sandbox out of the einat uplink with the default route of its family, as the uplink sends
// one: from the uplink address and port 5353, which einat leaves alone (an external source, a port outside its range),
// so responders answer to the group (RFC 6762 section 6); from another port it is a legacy unicast query, whose answer
// goes to the port alone. Not a response, nor a probe (an authority section, section 8.2): the sandbox claims no name
// on the LAN; known-answer and additional records may come along, and known answers only keep responders from repeating
// them (section 7.1). The questions lose the unicast-response bit (QU, section 5.4), so the answer comes by multicast,
// which pre copies in. At most MDNS_RATE a second, MDNS_BURST at once. Only a single datagram that ends where its IP header says: a GSO packet (UDP_SEGMENT) would
// leave as several, the first a query and the rest anything, a response too. Packet data is read through helpers: a
// variable offset into it is pointer arithmetic the verifier refuses without CAP_PERFMON. Rewrites the packet, which
// peer drops after
static __always_inline void query_out(struct __sk_buff *skb, const struct pkt *p)
{
	__u32 fam = p->family == AF_INET6;
	struct gateway *gw = default_gw(fam);
	if (!gw || zero(&gw->src))
		return;
	if (skb->gso_size || skb->gso_segs > 1)
		return;
	// parse found the ports right after a fixed IP header
	__u32 l4 = ETH_HLEN + (fam ? sizeof(struct ipv6hdr) : sizeof(struct iphdr));
	__be16 iplen;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + (fam ? offsetof(struct ipv6hdr, payload_len) : offsetof(struct iphdr, tot_len)),
			       &iplen, 2) ||
	    skb->len != ETH_HLEN + (fam ? sizeof(struct ipv6hdr) : 0) + bpf_ntohs(iplen))
		return;
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
	if (bpf_skb_store_bytes(skb, 0, &eth, sizeof(eth), 0) || !allow(LIMIT_MDNS, MDNS_RATE, MDNS_BURST))
		return;
	bpf_clone_redirect(skb, gw->ifindex, 0);
}
