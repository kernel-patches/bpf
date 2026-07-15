// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "skb_rx_checksum.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SKB_CSUM_PARTIAL);
	__type(key, __u32);
	__type(value, __u64);
} csum_cnt SEC(".maps");

SEC("tc")
int tc_rx_csum(struct __sk_buff *skb)
{
	enum skb_csum ip_summed;
	__u32 csum_meta;
	__u64 *cnt;

	bpf_skb_rx_checksum(skb, &ip_summed, &csum_meta);
	if (ip_summed < SKB_CSUM_PARTIAL) {
		cnt = bpf_map_lookup_elem(&csum_cnt, &ip_summed);
		if (cnt)
			__sync_fetch_and_add(cnt, 1);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
