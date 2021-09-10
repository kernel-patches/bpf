// SPDX-License-Identifier: GPL-2.0
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

int _version SEC("version") = 1;

SEC("xdp_adjust_frags")
int _xdp_adjust_frags(struct xdp_md *xdp)
{
	__u8 *data_end = (void *)(long)xdp->data_end;
	__u8 *data = (void *)(long)xdp->data;
	int base_offset, ret = XDP_DROP;
	__u32 offset;

	if (data + sizeof(__u32) > data_end)
		return XDP_DROP;

	offset = *(__u32 *)data;
	base_offset = bpf_xdp_adjust_data(xdp, offset);
	if (base_offset < 0 || base_offset > offset)
		return XDP_DROP;

	data_end = (void *)(long)xdp->data_end;
	data = (void *)(long)xdp->data;

	if (data + 1 > data_end)
		goto out;

	if (*data != 0xaa) /* marker */
		goto out;

	*data = 0xbb; /* update the marker */
	ret = XDP_PASS;
out:
	bpf_xdp_adjust_data(xdp, 0);
	return ret;
}

char _license[] SEC("license") = "GPL";
