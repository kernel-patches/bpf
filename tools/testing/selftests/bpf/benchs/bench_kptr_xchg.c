// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2026. Loongson Technology Corporation Limited */
#include <argp.h>
#include "bench.h"
#include "kptr_xchg_bench.skel.h"

static struct ctx {
	struct kptr_xchg_bench *skel;
} ctx;

static struct {
	__u32 nr_loops;
} args = {
	.nr_loops = 256,
};

enum {
	ARG_NR_LOOPS = 7000,
};

static const struct argp_option opts[] = {
	{ "nr_loops", ARG_NR_LOOPS, "nr_loops", 0,
	  "Set number of bpf_kptr_xchg() calls per trigger"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_NR_LOOPS:
		args.nr_loops = strtol(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static const struct argp bench_kptr_xchg_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumer!\n");
		exit(1);
	}
}

static void *producer(void *input)
{
	while (true)
		syscall(__NR_getpgid);

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

	ctx.skel = kptr_xchg_bench__open_and_load();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	ctx.skel->data->nr_loops = args.nr_loops;

	link = bpf_program__attach(ctx.skel->progs.benchmark);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

const struct bench bench_kptr_xchg = {
	.name = "kptr-xchg",
	.argp = &bench_kptr_xchg_argp,
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
