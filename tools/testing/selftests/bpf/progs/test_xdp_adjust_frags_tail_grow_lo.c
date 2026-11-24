// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* 1 until the program saw a packet with frags */
int grow_ret = 1;

SEC("xdp.frags")
int xdp_grow_frags(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;

	if (grow_ret != 1 || bpf_xdp_get_buff_len(xdp) <= data_end - data)
		return XDP_PASS;

	/*
	 * More than the tailroom of any frag, so nothing is written: the
	 * result only tells if frag_size of the rxq allows a grow at all.
	 */
	grow_ret = bpf_xdp_adjust_tail(xdp, 0x10000);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
