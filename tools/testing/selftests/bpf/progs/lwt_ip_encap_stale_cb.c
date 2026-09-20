// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tracing_net.h"

#define IPOPT_RR 7
#define IPOPT_MINOFF 4

bool direct_cb_zero;
bool direct_ran;

struct tc_outer_ipv4 {
	struct iphdr iph;
	__u8 options[8];
};

static __always_inline __u16 fold_csum(__u64 csum)
{
	csum = (csum & 0xffffffff) + (csum >> 32);
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);

	return ~csum;
}

SEC("tc")
int tc_pre_encap(struct __sk_buff *skb)
{
	struct tc_outer_ipv4 outer = {};
	struct iphdr inner;
	__s64 csum;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &inner, sizeof(inner)))
		return TC_ACT_SHOT;

	outer.iph.version = 4;
	outer.iph.ihl = sizeof(outer) / 4;
	outer.iph.tos = 8;
	outer.iph.tot_len = bpf_htons(bpf_ntohs(inner.tot_len) + sizeof(outer));
	outer.iph.id = bpf_htons(0x2345);
	outer.iph.ttl = 64;
	outer.iph.protocol = IPPROTO_IPIP;
	outer.iph.saddr = bpf_htonl(0x0a000002); /* 10.0.0.2 */
	outer.iph.daddr = bpf_htonl(0x0a090909); /* 10.9.9.9 */
	outer.options[0] = IPOPT_RR;
	outer.options[1] = sizeof(outer.options);
	outer.options[2] = IPOPT_MINOFF;
	csum = bpf_csum_diff(NULL, 0, (__be32 *)&outer, sizeof(outer), 0);
	if (csum < 0)
		return TC_ACT_SHOT;
	outer.iph.check = fold_csum(csum);

	if (bpf_skb_adjust_room(skb, sizeof(outer), BPF_ADJ_ROOM_MAC,
				BPF_F_ADJ_ROOM_FIXED_GSO |
				BPF_F_ADJ_ROOM_ENCAP_L3_IPV4))
		return TC_ACT_SHOT;
	if (bpf_skb_store_bytes(skb, ETH_HLEN, &outer, sizeof(outer),
				BPF_F_INVALIDATE_HASH))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

__noinline int add_ip_encap(struct __sk_buff *skb)
{
	struct iphdr iph = {};

	iph.version = 4;
	iph.ihl = 5;
	iph.ttl = 1;
	iph.protocol = 4; /* IPPROTO_IPIP */
	iph.tot_len = bpf_htons(skb->len + sizeof(iph));
	iph.saddr = bpf_htonl(0x0a000002); /* 10.0.0.2 */
	iph.daddr = bpf_htonl(0x0a090909); /* 10.9.9.9 */

	if (bpf_lwt_push_encap(skb, BPF_LWT_ENCAP_IP, &iph, sizeof(iph)))
		return BPF_DROP;

	return BPF_OK;
}

SEC("lwt_in")
int lwt_in_direct(struct __sk_buff *skb)
{
	direct_cb_zero = !(skb->cb[0] | skb->cb[1] | skb->cb[2] |
			   skb->cb[3] | skb->cb[4]);
	direct_ran = true;
	return add_ip_encap(skb);
}

SEC("lwt_in")
int lwt_in_freplace_target(struct __sk_buff *skb)
{
	return add_ip_encap(skb);
}

char _license[] SEC("license") = "GPL";
