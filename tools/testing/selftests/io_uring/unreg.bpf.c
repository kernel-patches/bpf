/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"
#include "common-defs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("struct_ops.s/unreg_loop_step")
int BPF_PROG(unreg_loop_step, struct io_ring_ctx *ring,
			      struct iou_loop_params *ls)
{
	struct unreg_state *us;

	us = (void *)bpf_io_uring_get_region(ring, IOU_REGION_MEM, sizeof(*us));
	if (us)
		us->times_invoked++;
	return IOU_LOOP_STOP;
}

SEC(".struct_ops.link")
struct io_uring_bpf_ops unreg_ops = {
	.loop_step = (void *)unreg_loop_step,
};
