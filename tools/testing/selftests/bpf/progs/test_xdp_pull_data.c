// SPDX-License-Identifier: GPL-2.0

#include  "vmlinux.h"
#include <bpf/bpf_helpers.h>

int _version SEC("version") = 1;

int linear_len;
int pull_len;

SEC("xdp.frags")
int xdp_pull_data_prog(struct xdp_md *xdp)
{
	__u8 *data_end = (void *)(long)xdp->data_end;
	__u8 *data = (void *)(long)xdp->data;
	__u8 *val_p;
	int err;

	if (linear_len != data_end - data)
		return XDP_DROP;

	err = bpf_xdp_pull_data(xdp, pull_len, 0);
	if (err)
		return XDP_DROP;

	val_p = (void *)(long)xdp->data + 1024;
	if (val_p + 1 > (void *)(long)xdp->data_end)
		return XDP_DROP;

	if (*val_p != 0xbb)
		return XDP_DROP;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
