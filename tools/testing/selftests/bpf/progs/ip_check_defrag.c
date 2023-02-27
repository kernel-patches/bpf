// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"

#define BPF_F_CURRENT_NETNS	(-1)
#define ETH_P_IP		0x0800
#define ETH_P_IPV6		0x86DD
#define IP_DF			0x4000
#define IP_MF			0x2000
#define IP_OFFSET		0x1FFF
#define NEXTHDR_FRAGMENT	44
#define ctx_ptr(field)		(void *)(long)(field)

int bpf_ip_check_defrag(struct __sk_buff *ctx, u64 netns) __ksym;
int bpf_ipv6_frag_rcv(struct __sk_buff *ctx, u64 netns) __ksym;

volatile int frags_seen = 0;
volatile bool is_final_frag = true;

static bool is_frag_v4(struct iphdr *iph)
{
	int offset;
	int flags;

	offset = bpf_ntohs(iph->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;

	return (flags & IP_MF) || offset;
}

static bool is_frag_v6(struct ipv6hdr *ip6h)
{
	/* Simplifying assumption that there are no extension headers
	 * between fixed header and fragmentation header. This assumption
	 * is only valid in this test case. It saves us the hassle of
	 * searching all potential extension headers.
	 */
	return ip6h->nexthdr == NEXTHDR_FRAGMENT;
}

static int defrag_v4(struct __sk_buff *skb)
{
	void *data_end = ctx_ptr(skb->data_end);
	void *data = ctx_ptr(skb->data);
	struct iphdr *iph;

	iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end)
		return TC_ACT_SHOT;

	if (!is_frag_v4(iph))
		return TC_ACT_OK;

	frags_seen++;
	if (bpf_ip_check_defrag(skb, BPF_F_CURRENT_NETNS))
		return TC_ACT_SHOT;

	data_end = ctx_ptr(skb->data_end);
	data = ctx_ptr(skb->data);
	iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end)
		return TC_ACT_SHOT;
	is_final_frag = is_frag_v4(iph);

	return TC_ACT_OK;
}

static int defrag_v6(struct __sk_buff *skb)
{
	void *data_end = ctx_ptr(skb->data_end);
	void *data = ctx_ptr(skb->data);
	struct ipv6hdr *ip6h;

	ip6h = data + sizeof(struct ethhdr);
	if (ip6h + 1 > data_end)
		return TC_ACT_SHOT;

	if (!is_frag_v6(ip6h))
		return TC_ACT_OK;

	frags_seen++;
	if (bpf_ipv6_frag_rcv(skb, BPF_F_CURRENT_NETNS))
		return TC_ACT_SHOT;

	data_end = ctx_ptr(skb->data_end);
	data = ctx_ptr(skb->data);
	ip6h = data + sizeof(struct ethhdr);
	if (ip6h + 1 > data_end)
		return TC_ACT_SHOT;
	is_final_frag = is_frag_v6(ip6h);

	return TC_ACT_OK;
}

SEC("tc")
int defrag(struct __sk_buff *skb)
{
	switch (bpf_ntohs(skb->protocol)) {
	case ETH_P_IP:
		return defrag_v4(skb);
	case ETH_P_IPV6:
		return defrag_v6(skb);
	default:
		return TC_ACT_OK;
	}
}

SEC("?tc")
int defrag_fail(struct __sk_buff *skb)
{
	void *data_end = ctx_ptr(skb->data_end);
	void *data = ctx_ptr(skb->data);
	struct iphdr *iph;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end)
		return TC_ACT_SHOT;

	if (bpf_ip_check_defrag(skb, BPF_F_CURRENT_NETNS))
		return TC_ACT_SHOT;

	/* Boom. Must revalidate pkt ptrs */
	return iph->ttl ? TC_ACT_OK : TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";
