/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Test BPF registration / unregistration works and doesn't leave a dangling
 * function pointer.
 */
#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <io_uring/mini_liburing.h>

#include "helpers.h"
#include "unreg.bpf.skel.h"

static struct unreg *load_unreg(struct ring_ctx *ctx)
{
	struct unreg *skel;
	int ret;

	skel = unreg__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		exit(1);
	}

	skel->struct_ops.unreg_ops->ring_fd = ctx->ring.ring_fd;

	ret = unreg__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	return skel;
}

int main()
{
	struct bpf_link *link1, *link2;
	struct unreg *skel1, *skel2;
	struct unreg_state *us;
	struct ring_ctx ctx;

	ring_ctx_create(&ctx, sizeof(struct unreg_state));
	us = ctx.region;

	skel1 = load_unreg(&ctx);
	skel2 = load_unreg(&ctx);

	link1 = bpf_map__attach_struct_ops(skel1->maps.unreg_ops);
	if (!link1) {
		fprintf(stderr, "failed to attach ops\n");
		return 1;
	}

	ring_ctx_run(&ctx);
	if (us->times_invoked != 1) {
		fprintf(stderr, "failed to run BPF\n");
		return 1;
	}

	/* remove the program and give the kernel time to actually destroy it */
	bpf_link__destroy(link1);
	unreg__destroy(skel1);
	sleep(1);

	ring_ctx_run(&ctx);
	if (us->times_invoked != 1) {
		fprintf(stderr, "Executed removed BPF\n");
		return 1;
	}

	/* try to attach another program */
	link2 = bpf_map__attach_struct_ops(skel2->maps.unreg_ops);
	if (!link2) {
		fprintf(stderr, "failed to reattach ops\n");
		return 1;
	}

	ring_ctx_run(&ctx);
	if (us->times_invoked != 2) {
		fprintf(stderr, "failed to run reattached BPF\n");
		return 1;
	}

	bpf_link__destroy(link2);
	unreg__destroy(skel2);
	ring_ctx_destroy(&ctx);
	return 0;
}
