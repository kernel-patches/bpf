// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("vnet_hash")
int prog(struct __sk_buff *skb)
{
	skb->vnet_hash_value ^= 3;
	skb->vnet_hash_report ^= 2;
	skb->vnet_rss_queue ^= 1;

	return BPF_OK;
}

char _license[] SEC("license") = "GPL";
