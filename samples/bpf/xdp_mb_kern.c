// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All rights reserved.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>

/* count RX packets */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} rx_cnt SEC(".maps");

/* count RX fragments */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} rx_frags SEC(".maps");

/* count total number of bytes */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, u32);
	__type(value, long);
	__uint(max_entries, 1);
} tot_len SEC(".maps");

SEC("xdp_mb")
int xdp_mb_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 frag_offset = 0, frag_size = 0;
	u32 key = 0, nfrags;
	long *value;
	int i, len;

	value = bpf_map_lookup_elem(&rx_cnt, &key);
	if (value)
		*value += 1;

	len = data_end - data;
	nfrags = bpf_xdp_get_frags_count(ctx);
	len += bpf_xdp_get_frags_total_size(ctx);

	value = bpf_map_lookup_elem(&tot_len, &key);
	if (value)
		*value += len;

	value = bpf_map_lookup_elem(&rx_frags, &key);
	if (value)
		*value += nfrags;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
