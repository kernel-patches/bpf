/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Test that the loop handling logic around BPF doesn't deadlock on overflows.
 */
#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <io_uring/mini_liburing.h>

#include "helpers.h"
#include "overflow.bpf.skel.h"

int main()
{
	struct bpf_link *link;
	struct overflow *skel;
	struct ring_ctx ctx;
	int ret;

	ring_ctx_create(&ctx, 0);

	skel = overflow__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		exit(1);
	}
	skel->struct_ops.overflow_ops->ring_fd = ctx.ring.ring_fd;
	skel->rodata->ri = ctx.ri;

	ret = overflow__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}
	link = bpf_map__attach_struct_ops(skel->maps.overflow_ops);
	if (!link) {
		fprintf(stderr, "failed to attach ops\n");
		return 1;
	}

	ring_ctx_run(&ctx);

	bpf_link__destroy(link);
	overflow__destroy(skel);
	ring_ctx_destroy(&ctx);
	return 0;
}
