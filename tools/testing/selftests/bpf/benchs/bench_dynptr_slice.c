// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <argp.h>
#include "bench.h"
#include "dynptr_slice_bench.skel.h"

static struct dynptr_slice_ctx {
	struct dynptr_slice_bench *skel;
	int pfd;
} ctx;

static void dynptr_slice_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "bpf dynptr_slice benchmark doesn't support consumer!\n");
		exit(1);
	}
}

static void dynptr_slice_setup(void)
{
	LIBBPF_OPTS(bpf_test_run_opts, opts);
	int err;

	setup_libbpf();
	ctx.skel = dynptr_slice_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	ctx.skel->bss->hits = 0;
	err = dynptr_slice_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		dynptr_slice_bench__destroy(ctx.skel);
		exit(1);
	}
}

static void dynptr_slice_encrypt_setup(void)
{
	dynptr_slice_setup();
	ctx.pfd = bpf_program__fd(ctx.skel->progs.dynptr_slice);
}


static void dynptr_slice_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

static void *dynptr_slice_producer(void *unused)
{
	static const char data_in[1000];
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		.repeat = 64,
		.data_in = data_in,
		.data_size_in = sizeof(data_in),
	);

	while (true)
		(void)bpf_prog_test_run_opts(ctx.pfd, &opts);
	return NULL;
}

const struct bench bench_dynptr_slice = {
	.name = "dynptr_slice",
	.validate = dynptr_slice_validate,
	.setup = dynptr_slice_encrypt_setup,
	.producer_thread = dynptr_slice_producer,
	.measure = dynptr_slice_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
