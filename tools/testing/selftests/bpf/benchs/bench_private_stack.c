// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <argp.h>
#include "bench.h"
#include "private_stack.skel.h"

static struct ctx {
	struct private_stack *skel;
} ctx;

static struct {
	bool disable_private_stack;
} args = {
	.disable_private_stack = 0,
};

enum {
	ARG_DISABLE_PRIVATE_STACK = 3000,
};

static const struct argp_option opts[] = {
        { "disable-private-stack", ARG_DISABLE_PRIVATE_STACK, "DISABLE_PRIVATE_STACK",
		0, "Disable private stack" },
        {},
};

static error_t private_stack_parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

        switch (key) {
        case ARG_DISABLE_PRIVATE_STACK:
                ret = strtoul(arg, NULL, 10);
		if (ret != 1)
			argp_usage(state);
		args.disable_private_stack = 1;
                break;
        default:
                return ARGP_ERR_UNKNOWN;
        }

        return 0;
}

const struct argp bench_private_stack_argp = {
        .options = opts,
        .parser = private_stack_parse_arg,
};

static void private_stack_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr,
			"The private stack benchmarks do not support consumer\n");
		exit(1);
	}
}

static void common_setup(bool disable_private_stack)
{
	struct private_stack *skel;
	struct bpf_link *link;
	__u32 old_flags;
	int err;

	skel = private_stack__open();
	if(!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}
	ctx.skel = skel;

	if (disable_private_stack) {
		old_flags = bpf_program__flags(skel->progs.stack0);
		bpf_program__set_flags(skel->progs.stack0, old_flags | BPF_F_DISABLE_PRIVATE_STACK);
	}

	err = private_stack__load(skel);
	if (err) {
		fprintf(stderr, "failed to load program\n");
		exit(1);
	}

	link = bpf_program__attach(skel->progs.stack0);
	if (!link) {
		fprintf(stderr, "failed to attach program\n");
		exit(1);
	}
}

static void no_private_stack_setup(void)
{
	common_setup(true);
}

static void private_stack_setup(void)
{
	common_setup(false);
}

static void private_stack_measure(struct bench_res *res)
{
	struct private_stack *skel = ctx.skel;
	unsigned long total_hits = 0;
	static unsigned long last_hits;

	total_hits = skel->bss->hits;
	res->hits = total_hits - last_hits;
	res->drops = 0;
	res->false_hits = 0;
	last_hits = total_hits;
}

static void *private_stack_producer(void *unused)
{
	while (true)
		syscall(__NR_getpgid);
	return NULL;
}

const struct bench bench_no_private_stack = {
	.name = "no-private-stack",
	.argp = &bench_private_stack_argp,
	.validate = private_stack_validate,
	.setup = no_private_stack_setup,
	.producer_thread = private_stack_producer,
	.measure = private_stack_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_private_stack = {
	.name = "private-stack",
	.argp = &bench_private_stack_argp,
	.validate = private_stack_validate,
	.setup = private_stack_setup,
	.producer_thread = private_stack_producer,
	.measure = private_stack_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
