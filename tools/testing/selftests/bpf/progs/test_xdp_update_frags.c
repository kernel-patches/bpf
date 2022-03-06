// SPDX-License-Identifier: GPL-2.0
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

int _version SEC("version") = 1;

bool force_helper;
bool used_dpa;
bool used_helper;

#define XDP_LEN 16

SEC("xdp.frags")
int xdp_adjust_frags(struct xdp_md *xdp)
{
	__u8 *data_end = (void *)(long)xdp->data_end;
	__u8 *data = (void *)(long)xdp->data;
	__u8 val[XDP_LEN] = {};
	__u8 *ptr = NULL;
	__u32 offset;
	int err;

	used_dpa = false;
	used_helper = false;

	if (data + sizeof(__u32) > data_end)
		return XDP_DROP;

	offset = *(__u32 *)data;
	offset &= 0xffff;
	if (!force_helper)
		ptr = bpf_packet_pointer(xdp, offset, XDP_LEN);
	if (!ptr) {
		used_helper = true;
		err = bpf_xdp_load_bytes(xdp, offset, val, sizeof(val));
		if (err < 0)
			return XDP_DROP;
		ptr = val;
	} else {
		used_dpa = true;
	}

	if (ptr[0] != 0xaa || ptr[15] != 0xaa) /* marker */
		return XDP_DROP;

	ptr[0] = 0xbb; /* update the marker */
	ptr[15] = 0xbb;
	if (ptr == val) {
		err = bpf_xdp_store_bytes(xdp, offset, val, sizeof(val));
		if (err < 0)
			return XDP_DROP;
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
