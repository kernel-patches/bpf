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
	__u32 offset = 5000; /* marker offset */
	int ret = XDP_DROP;
	int data_len;

	if (data + sizeof(__u32) > data_end)
		return XDP_DROP;

	data_len = bpf_xdp_adjust_data(xdp, offset);
	if (data_len < 0)
		return XDP_DROP;

	if (data_len > 5000)
		goto out;

	data_end = (void *)(long)xdp->data_end;
	data = (void *)(long)xdp->data;
	offset -= data_len; /* offset in frag0 */

	if (data + offset + 1 > data_end)
		goto out;

	if (data[offset] != 0xaa) /* marker */
		goto out;

	data[offset] = 0xbb; /* update the marker */
	ret = XDP_PASS;
out:
	bpf_xdp_adjust_data(xdp, 0);
	return ret;
}

char _license[] SEC("license") = "GPL";
