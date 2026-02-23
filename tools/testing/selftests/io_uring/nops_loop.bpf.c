/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/types.h>
#include <linux/errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "vmlinux.h"
#include "common-defs.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile struct ring_info ri;
const unsigned max_inflight = 32;

#define REQ_TOKEN 0xabba1741

#define t_min(a, b) ((a) < (b) ? (a) : (b))

static unsigned nr_to_submit(struct nops_state *ns)
{
	unsigned to_submit = 0;
	unsigned inflight = ns->reqs_inflight;

	if (inflight < max_inflight) {
		to_submit = max_inflight - inflight;
		to_submit = t_min(to_submit, ns->reqs_left - inflight);
	}
	return to_submit;
}

SEC("struct_ops.s/nops_loop_step")
int BPF_PROG(nops_loop_step, struct io_ring_ctx *ring, struct iou_loop_params *ls)
{
	struct io_uring_sqe *sqes;
	struct io_uring_cqe *cqes;
	struct io_uring *cq_hdr;
	struct nops_state *ns;
	unsigned to_submit;
	unsigned to_wait;
	unsigned nr_cqes;
	void *rings;
	int ret, i;

	sqes = (void *)bpf_io_uring_get_region(ring, IOU_REGION_SQ,
				ri.sq_entries * sizeof(struct io_uring_sqe));
	rings = (void *)bpf_io_uring_get_region(ring, IOU_REGION_CQ,
				ri.cqes_offset + ri.cq_entries * sizeof(struct io_uring_cqe));
	ns = (void *)bpf_io_uring_get_region(ring, IOU_REGION_MEM,
				sizeof(*ns));
	if (!rings || !sqes || !ns)
		return IOU_LOOP_STOP;
	cq_hdr = rings + ri.cq_hdr_offset;
	cqes = rings + ri.cqes_offset;

	to_submit = nr_to_submit(ns);
	if (to_submit) {
		for (i = 0; i < to_submit; i++) {
			struct io_uring_sqe *sqe = &sqes[i];

			*sqe = (struct io_uring_sqe){};
			sqe->opcode = IORING_OP_NOP;
			sqe->user_data = REQ_TOKEN;
		}

		ret = bpf_io_uring_submit_sqes(ring, to_submit);
		if (ret != to_submit) {
			ns->result = ret;
			return IOU_LOOP_STOP;
		}

		ns->reqs_inflight += to_submit;
		ns->stat_nr_sqes += to_submit;
	}

	nr_cqes = cq_hdr->tail - cq_hdr->head;
	nr_cqes = t_min(nr_cqes, max_inflight);
	for (i = 0; i < nr_cqes; i++) {
		struct io_uring_cqe *cqe = &cqes[cq_hdr->head & (ri.cq_entries - 1)];

		if (cqe->user_data != REQ_TOKEN) {
			ns->result = -EINVAL;
			return IOU_LOOP_STOP;
		}
		cq_hdr->head++;
	}

	ns->reqs_inflight -= nr_cqes;
	ns->reqs_left -= nr_cqes;
	ns->stat_nr_cqes += nr_cqes;

	if (ns->reqs_left <= 0 && !ns->reqs_inflight) {
		ns->result = 0;
		if (ns->reqs_left)
			ns->result = -ERANGE;
		return IOU_LOOP_STOP;
	}

	to_wait = ns->reqs_inflight;
	/* Don't sleep if there are still CQEs left */
	if (cq_hdr->tail != cq_hdr->head)
		to_wait = 0;
	ls->cq_wait_idx = cq_hdr->head + to_wait;
	return IOU_LOOP_CONTINUE;
}

SEC(".struct_ops.link")
struct io_uring_bpf_ops nops_ops = {
	.loop_step = (void *)nops_loop_step,
};
