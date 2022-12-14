// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bpf_tracing_net.h"

#define ETH_P_IP		0x0800
#define IP_DF			0x4000
#define IP_MF			0x2000
#define IP_OFFSET		0x1FFF
#define ctx_ptr(field)		(void *)(long)(field)

int bpf_ip_check_defrag(struct __sk_buff *ctx, u64 netns) __ksym;

volatile int frags_seen = 0;
volatile bool is_final_frag = true;

static inline bool is_frag(struct iphdr *iph)
{
	int offset;
	int flags;

	offset = bpf_ntohs(iph->frag_off);
	flags = offset & ~IP_OFFSET;
	offset &= IP_OFFSET;
	offset <<= 3;

	return (flags & IP_MF) || offset;
}

SEC("tc")
int defrag(struct __sk_buff *skb)
{
	void *data_end = ctx_ptr(skb->data_end);
	void *data = ctx_ptr(skb->data);
	struct iphdr *iph;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end)
		return TC_ACT_SHOT;

	if (!is_frag(iph))
		return TC_ACT_OK;

	frags_seen++;
	if (bpf_ip_check_defrag(skb, BPF_F_CURRENT_NETNS))
		return TC_ACT_SHOT;

	data_end = ctx_ptr(skb->data_end);
	data = ctx_ptr(skb->data);
	iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end)
		return TC_ACT_SHOT;
	is_final_frag = is_frag(iph);

	return TC_ACT_OK;
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
