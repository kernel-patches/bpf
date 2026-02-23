/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/stddef.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <io_uring/mini_liburing.h>

#include "common-defs.h"
#include "helpers.h"
#include "nops_loop.bpf.skel.h"

static struct nops_loop *skel;
static struct bpf_link *nops_loop_link;

struct ring_ctx {
	struct io_uring ring;
	struct ring_info ri;

	void *region;
	size_t region_size;
};

#define NR_ITERS 1000

static void setup_bpf_prog(struct ring_ctx *ctx)
{
	int ret;

	skel = nops_loop__open();
	if (!skel) {
		fprintf(stderr, "can't generate skeleton\n");
		exit(1);
	}

	skel->struct_ops.nops_ops->ring_fd = ctx->ring.ring_fd;
	skel->rodata->ri = ctx->ri;

	ret = nops_loop__load(skel);
	if (ret) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	nops_loop_link = bpf_map__attach_struct_ops(skel->maps.nops_ops);
	if (!nops_loop_link) {
		fprintf(stderr, "failed to attach ops\n");
		exit(1);
	}
}

static void run_ring(struct ring_ctx *ctx)
{
	struct nops_state *ns = ctx->region;
	int ret;

	ns->reqs_left = NR_ITERS;

	ret = ring_ctx_run(ctx);
	if (ret) {
		fprintf(stderr, "run failed %i\n", ret);
		exit(1);
	}

	if (ns->result)
		fprintf(stderr, "run failed: %i\n", ns->result);
	if (ns->stat_nr_cqes != NR_ITERS)
		fprintf(stderr, "unexpected number of CQEs: %u\n",
				ns->stat_nr_cqes);
	if (ns->stat_nr_sqes != NR_ITERS)
		fprintf(stderr, "unexpected submitted number: %u\n",
				ns->stat_nr_sqes);
}

int main()
{
	struct ring_ctx ctx;

	ring_ctx_create(&ctx, sizeof(struct nops_state));
	setup_bpf_prog(&ctx);

	run_ring(&ctx);

	bpf_link__destroy(nops_loop_link);
	nops_loop__destroy(skel);
	ring_ctx_destroy(&ctx);
	return 0;
}
