/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"
#include "common-defs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile struct ring_info ri;
static unsigned submitted;

SEC("struct_ops.s/overflow_loop_step")
int BPF_PROG(overflow_loop_step, struct io_ring_ctx *ring,
				 struct iou_loop_params *ls)
{
	struct io_uring *sq_hdr, *cq_hdr;
	struct io_uring_sqe *sqe;
	void *rings;

	sqe = (void *)bpf_io_uring_get_region(ring, IOU_REGION_SQ,
				ri.sq_entries * sizeof(struct io_uring_sqe));
	rings = (void *)bpf_io_uring_get_region(ring, IOU_REGION_CQ,
				ri.cqes_offset + ri.cq_entries * sizeof(struct io_uring_cqe));
	if (!rings || !sqe)
		return IOU_LOOP_STOP;
	sq_hdr = rings + ri.sq_hdr_offset;
	cq_hdr = rings + ri.cq_hdr_offset;

	/* keep submitting until we overrun the CQ and trigger an overflow */
	if (submitted < 2 * ri.cq_entries) {
		*sqe = (struct io_uring_sqe){};
		sqe->opcode = IORING_OP_NOP;
		sq_hdr->tail++;

		bpf_io_uring_submit_sqes(ring, 1);
		submitted++;
		return IOU_LOOP_CONTINUE;
	}

	if (cq_hdr->tail == cq_hdr->head)
		return IOU_LOOP_STOP;
	/* Consume all queued CQEs and let io_uring to flush overflown CQEs */
	cq_hdr->head = cq_hdr->tail;
	return IOU_LOOP_CONTINUE;
}

SEC(".struct_ops.link")
struct io_uring_bpf_ops overflow_ops = {
	.loop_step = (void *)overflow_loop_step,
};
