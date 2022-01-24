// SPDX-License-Identifier: GPL-2.0-only
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#define KBUILD_MODNAME "foo"

#include "vmlinux.h"
#include "xdp_sample.bpf.h"
#include "xdp_sample_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 64);
} br_ports SEC(".maps");

struct bpf_fdb_lookup {
	__u8	addr[ETH_ALEN];
	__u16	vid;
	__u32	ifindex;
};

int br_fdb_find_port_from_ifindex(struct xdp_md *xdp_ctx,
				  struct bpf_fdb_lookup *opt,
				  u32 opt__sz) __ksym;

SEC("xdp")
int xdp_fdb_lookup(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u32 key = bpf_get_smp_processor_id();
	struct bpf_fdb_lookup params = {
		.ifindex = ctx->ingress_ifindex,
	};
	struct ethhdr *eth = data;
	u64 nh_off = sizeof(*eth);
	struct datarec *rec;
	int ret;

	if (data + nh_off > data_end)
		return XDP_DROP;

	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_PASS;

	NO_TEAR_INC(rec->processed);

	__builtin_memcpy(params.addr, eth->h_dest, ETH_ALEN);
	ret = br_fdb_find_port_from_ifindex(ctx, &params,
					    sizeof(struct bpf_fdb_lookup));
	if (ret < 0)
		/* In cases of flooding, XDP_PASS will be returned here */
		return XDP_PASS;

	return bpf_redirect_map(&br_ports, ret, 0);
}

char _license[] SEC("license") = "GPL";
