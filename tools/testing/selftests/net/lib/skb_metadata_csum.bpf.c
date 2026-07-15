// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define UDP_PORT 12345

enum skb_csum {
	SKB_CSUM_NONE		= 0,
	SKB_CSUM_UNNECESSARY	= 1,
	SKB_CSUM_COMPLETE	= 2,
	SKB_CSUM_PARTIAL	= 3,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SKB_CSUM_PARTIAL);
	__type(key, __u32);
	__type(value, __u64);
} map_csum_result SEC(".maps");

extern int bpf_skb_rx_checksum(struct __sk_buff *skb, __u32 *ip_summed,
				__u32 *csum_meta) __ksym;

SEC("tc")
int tc_check_csum(struct __sk_buff *skb)
{
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	__u32 ip_summed, csum_meta;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6;
	struct udphdr *udp;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return TC_ACT_OK;

	if (ip6->nexthdr != IPPROTO_UDP)
		return TC_ACT_OK;

	udp = (void *)(ip6 + 1);
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;

	if (udp->dest != bpf_htons(UDP_PORT))
		return TC_ACT_OK;

	bpf_skb_rx_checksum(skb, &ip_summed, &csum_meta);
	if (ip_summed < SKB_CSUM_PARTIAL) {
		__u64 *cnt;

		cnt = bpf_map_lookup_elem(&map_csum_result, &ip_summed);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
