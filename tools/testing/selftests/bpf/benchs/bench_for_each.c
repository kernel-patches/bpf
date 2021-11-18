// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <argp.h>
#include "bench.h"
#include "for_each_helper.skel.h"

/* BPF triggering benchmarks */
static struct ctx {
	struct for_each_helper *skel;
} ctx;

static struct {
	__u32 nr_iters;
} args = {
	.nr_iters = 10,
};

enum {
	ARG_NR_ITERS = 4000,
};

static const struct argp_option opts[] = {
	{ "nr_iters", ARG_NR_ITERS, "nr_iters", 0,
		"Set number of iterations for the bpf_for_each helper"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_NR_ITERS:
		args.nr_iters = strtol(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/* exported into benchmark runner */
const struct argp bench_for_each_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-consumer!\n");
		exit(1);
	}
}

static void *producer(void *input)
{
	while (true)
		/* trigger the bpf program */
		syscall(__NR_getpgid);

	return NULL;
}

static void *consumer(void *input)
{
	return NULL;
}

static void measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
}

static void setup(void)
{
	struct bpf_link *link;

	setup_libbpf();

	ctx.skel = for_each_helper__open_and_load();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	link = bpf_program__attach(ctx.skel->progs.benchmark);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}

	ctx.skel->bss->nr_iterations = args.nr_iters;
}

const struct bench bench_for_each_helper = {
	.name = "for-each-helper",
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
