/* SPDX-License-Identifier: GPL-2.0 */
#ifndef IOU_TOOLS_HELPERS_H
#define IOU_TOOLS_HELPERS_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/errno.h>
#include <signal.h>
#include <stdlib.h>

#include <io_uring/mini_liburing.h>
#include "common-defs.h"

struct ring_ctx {
	struct io_uring ring;
	struct ring_info ri;

	void *region;
	size_t region_size;
};

static inline int ring_ctx_run(struct ring_ctx *ctx)
{
	return io_uring_enter(ctx->ring.ring_fd, 0, 0,
			      IORING_ENTER_GETEVENTS, NULL);
}

static inline void ring_ctx_destroy(struct ring_ctx *ctx)
{
	io_uring_queue_exit(&ctx->ring);
	free(ctx->region);
}

static inline void ring_ctx_create(struct ring_ctx *ctx, size_t region_size)
{
	struct io_uring_mem_region_reg mr;
	struct io_uring_region_desc rd;
	struct io_uring_params params;
	unsigned cq_entries = 128;
	unsigned sq_entries = 32;
	struct ring_info *ri;
	long page_size;
	void *buffer;
	int ret;

	page_size = sysconf(_SC_PAGE_SIZE);

	memset(&params, 0, sizeof(params));
	params.cq_entries = cq_entries;
	params.flags = IORING_SETUP_SINGLE_ISSUER |
			IORING_SETUP_DEFER_TASKRUN |
			IORING_SETUP_NO_SQARRAY |
			IORING_SETUP_CQSIZE |
			IORING_SETUP_SQ_REWIND;

	ret = io_uring_queue_init_params(sq_entries, &ctx->ring, &params);
	if (ret) {
		fprintf(stderr, "ring init failed\n");
		exit(1);
	}

	region_size = (region_size + page_size + 1) & ~(page_size - 1);
	buffer = aligned_alloc(page_size, region_size);
	if (!buffer) {
		fprintf(stderr, "Can't allocate memory for mem region\n");
		exit(1);
	}
	memset(buffer, 0, region_size);

	memset(&rd, 0, sizeof(rd));
	rd.user_addr = (__u64)(unsigned long)buffer;
	rd.size = region_size;
	rd.flags = IORING_MEM_REGION_TYPE_USER;
	memset(&mr, 0, sizeof(mr));
	mr.region_uptr = (__u64)(unsigned long)&rd;

	ret = io_uring_register(ctx->ring.ring_fd, IORING_REGISTER_MEM_REGION,
				&mr, 1);
	if (ret) {
		fprintf(stderr, "Can't register region %i\n", ret);
		exit(1);
	}

	ctx->region = buffer;
	ctx->region_size = region_size;

	ri = &ctx->ri;
	ri->cq_hdr_offset = params.cq_off.head;
	ri->sq_hdr_offset = params.sq_off.head;
	ri->cqes_offset = params.cq_off.cqes;
	ri->sq_entries = sq_entries;
	ri->cq_entries = cq_entries;
}

#endif /* IOU_TOOLS_HELPERS_H */
