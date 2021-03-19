// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_adjust_tail_grow")
int _xdp_adjust_tail_grow(struct xdp_md *xdp)
{
	void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	int offset = 0;

	/* Data length determine test case */

	if (xdp->frame_length == 54) { /* sizeof(pkt_v4) */
		offset = 4096; /* test too large offset */
	} else if (xdp->frame_length == 74) { /* sizeof(pkt_v6) */
		offset = 40;
	} else if (xdp->frame_length == 64) {
		offset = 128;
	} else if (xdp->frame_length == 128) {
		offset = 4096 - 256 - 320 - xdp->frame_length; /* Max tail grow 3520 */
	} else if (xdp->frame_length == 9000) {
		offset = 10;
	} else if (xdp->frame_length == 9001) {
		offset = 4096;
	} else {
		return XDP_ABORTED; /* No matching test */
	}

	if (bpf_xdp_adjust_tail(xdp, offset))
		return XDP_DROP;
	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
