// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Bytedadnce */

#include <argp.h>
#include "bench.h"
#include "bpf_map_bench.skel.h"

/* BPF triggering benchmarks */
static struct ctx {
	struct bpf_map_bench *skel;
	struct counter hits;
} ctx;

static void validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-consumer!\n");
		exit(1);
	}
}

static void *producer(void *input)
{
	while (true) {
		/* trigger the bpf program */
		syscall(__NR_getpgid);
		atomic_inc(&ctx.hits.value);
	}

	return NULL;
}

static void *consumer(void *input)
{
	return NULL;
}

static void measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.hits.value, 0);
}

static void setup(void)
{
	struct bpf_link *link;
	int map_fd, i, max_entries;

	setup_libbpf();

	ctx.skel = bpf_map_bench__open_and_load();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	link = bpf_program__attach(ctx.skel->progs.benchmark);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}

	//fill hash_map
	map_fd = bpf_map__fd(ctx.skel->maps.hash_map_bench);
	max_entries = bpf_map__max_entries(ctx.skel->maps.hash_map_bench);
	for (i = 0; i < max_entries; i++)
		bpf_map_update_elem(map_fd, &i, &i, BPF_ANY);
}

const struct bench bench_bpf_map = {
	.name = "bpf-map",
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
