// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2016 John Fastabend <john.r.fastabend@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

const volatile int ifindex_out;

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 key = bpf_get_smp_processor_id();
	struct ethhdr *eth = data;
	struct datarec *rec;
	u64 nh_off;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;
	NO_TEAR_INC(rec->processed);

	swap_src_dst_mac(data);
	return bpf_redirect(ifindex_out, 0);
}

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	return bpf_redirect(ifindex_out, 0);
}

const volatile __u16 port_start;
const volatile __u16 port_range;
volatile __u16 next_port = 0;

SEC("xdp")
int xdp_redirect_update_port(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u16 cur_port, cksum_diff;
	struct udphdr *hdr;

	hdr = data + (sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	if (hdr + 1 > data_end)
		return XDP_ABORTED;

	cur_port = bpf_ntohs(hdr->dest);
	cksum_diff = next_port - cur_port;
	if (cksum_diff) {
		hdr->check = bpf_htons(~(~bpf_ntohs(hdr->check) + cksum_diff));
		hdr->dest = bpf_htons(next_port);
	}
	if (next_port++ >= port_start + port_range - 1)
		next_port = port_start;

	return bpf_redirect(ifindex_out, 0);
}

/* Redirect require an XDP bpf_prog loaded on the TX device */
SEC("xdp")
int xdp_redirect_dummy_prog(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
