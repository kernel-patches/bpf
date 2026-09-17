// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_lru_window.h"

#ifndef ETH_P_IP
#define ETH_P_IP	0x0800
#endif

#ifndef EEXIST
#define EEXIST		17
#endif

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, XDP_LRU_WINDOW_FLOWS);
	__type(key, struct xdp_lru_window_key);
	__type(value, struct xdp_lru_window_state);
} flow_table SEC(".maps");

SEC("xdp")
int xdp_lru_window(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct xdp_lru_window_state init, *st;
	struct xdp_lru_window_key key;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct tcphdr *th;
	__u32 idx, pkt_len;
	int err;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;
	if (iph->protocol != IPPROTO_TCP)
		return XDP_PASS;

	th = (void *)(iph + 1);
	if ((void *)(th + 1) > data_end)
		return XDP_PASS;

	__builtin_memset(&key, 0, sizeof(key));
	key.saddr = iph->saddr;
	key.daddr = iph->daddr;
	key.sport = th->source;
	key.dport = th->dest;
	key.proto = iph->protocol;
	pkt_len = data_end - data;

	st = bpf_map_lookup_elem(&flow_table, &key);
	if (!st) {
		__builtin_memset(&init, 0, sizeof(init));
		err = bpf_map_update_elem(&flow_table, &key, &init,
					  BPF_NOEXIST);
		if (err && err != -EEXIST)
			return XDP_PASS;
		st = bpf_map_lookup_elem(&flow_table, &key);
		if (!st)
			return XDP_PASS;
	}

	idx = st->seq % AGGREGATION_WINDOW;
	barrier_var(idx);
	if (idx >= AGGREGATION_WINDOW)
		return XDP_PASS;

	st->pkt_len[idx] = pkt_len;
	st->seq++;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
