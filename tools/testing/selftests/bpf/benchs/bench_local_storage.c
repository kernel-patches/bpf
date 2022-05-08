// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <argp.h>
#include "local_storage_bench__create_map.skel.h"
#include "local_storage_bench__get10.skel.h"
#include "local_storage_bench__get100.skel.h"
#include "local_storage_bench__get1000.skel.h"
#include "local_storage_bench__get10_interleaved.skel.h"
#include "local_storage_bench__get100_interleaved.skel.h"
#include "local_storage_bench__get1000_interleaved.skel.h"
#include "bench.h"

static struct {
	__u32 nr_maps;
} args = {
	.nr_maps = 100,
};

enum {
	ARG_NR_MAPS = 6000,
};

static const struct argp_option opts[] = {
	{ "nr_maps", ARG_NR_MAPS, "NR_MAPS", 0,
		"Set number of local_storage maps"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

	switch (key) {
	case ARG_NR_MAPS:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > UINT_MAX) {
			fprintf(stderr, "invalid nr_maps");
			argp_usage(state);
		}
		args.nr_maps = ret;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_local_storage_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.producer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-producer!\n");
		exit(1);
	}
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-consumer!\n");
		exit(1);
	}

	if (!(args.nr_maps == 10 || args.nr_maps == 100 || args.nr_maps == 1000)) {
		fprintf(stderr, "nr_maps must be 10, 100, or 1000\n");
		exit(1);
	}
}

/* Map name in _get10, _get100, etc progs must match this pattern for
 * PIN_BY_NAME to reuse existing map
 */
#define MAP_PIN_PATTERN "/sys/fs/bpf/local_storage_bench_pinned"

void (*destroy_skel)(void *obj);
long *skel_bss_important_hits;
long *skel_bss_hits;
void *test_skel;

static void teardown(void);

static void local_storage_cache_get_setup(void)
{
	struct local_storage_bench__get1000 *get1000_skel;
	struct local_storage_bench__get100 *get100_skel;
	struct local_storage_bench__get10 *get10_skel;
	struct local_storage_bench__create_map *skel;
	char path[100];
	int i;

	setup_libbpf();

	for (i = 0; i < args.nr_maps; i++) {
		skel = local_storage_bench__create_map__open_and_load();

		sprintf(path, MAP_PIN_PATTERN "_%04d", i);
		bpf_map__pin(skel->maps.map_to_pin, path);

		local_storage_bench__create_map__destroy(skel);
	}

	switch (args.nr_maps) {
	case 10:
		get10_skel = local_storage_bench__get10__open_and_load();
		local_storage_bench__get10__attach(get10_skel);
		destroy_skel = (void(*)(void *))local_storage_bench__get10__destroy;
		test_skel = (void *)get10_skel;
		skel_bss_hits = &get10_skel->bss->hits;
		skel_bss_important_hits = &get10_skel->bss->important_hits;
		break;
	case 100:
		get100_skel = local_storage_bench__get100__open_and_load();
		local_storage_bench__get100__attach(get100_skel);
		destroy_skel = (void(*)(void *))local_storage_bench__get100__destroy;
		test_skel = (void *)get100_skel;
		skel_bss_hits = &get100_skel->bss->hits;
		skel_bss_important_hits = &get100_skel->bss->important_hits;
		break;
	case 1000:
		get1000_skel = local_storage_bench__get1000__open_and_load();
		local_storage_bench__get1000__attach(get1000_skel);
		destroy_skel = (void(*)(void *))local_storage_bench__get1000__destroy;
		test_skel = (void *)get1000_skel;
		skel_bss_hits = &get1000_skel->bss->hits;
		skel_bss_important_hits = &get1000_skel->bss->important_hits;
		break;
	default:
		fprintf(stderr,
			"got an invalid nr_maps in setup, does validate() need update?");
		teardown();
		exit(1);
		break;
	}
}

static void local_storage_cache_get_interleaved_setup(void)
{
	struct local_storage_bench__get1000_interleaved *get1000_skel;
	struct local_storage_bench__get100_interleaved *get100_skel;
	struct local_storage_bench__get10_interleaved *get10_skel;
	struct local_storage_bench__create_map *skel;
	char path[100];
	int i;

	setup_libbpf();

	for (i = 0; i < args.nr_maps; i++) {
		skel = local_storage_bench__create_map__open_and_load();

		sprintf(path, MAP_PIN_PATTERN "_%04d", i);
		bpf_map__pin(skel->maps.map_to_pin, path);

		local_storage_bench__create_map__destroy(skel);
	}

	switch (args.nr_maps) {
	case 10:
		get10_skel = local_storage_bench__get10_interleaved__open_and_load();
		local_storage_bench__get10_interleaved__attach(get10_skel);
		destroy_skel = (void(*)(void *))local_storage_bench__get10_interleaved__destroy;
		test_skel = (void *)get10_skel;
		skel_bss_hits = &get10_skel->bss->hits;
		skel_bss_important_hits = &get10_skel->bss->important_hits;
		break;
	case 100:
		get100_skel = local_storage_bench__get100_interleaved__open_and_load();
		local_storage_bench__get100_interleaved__attach(get100_skel);
		destroy_skel = (void(*)(void *))local_storage_bench__get100_interleaved__destroy;
		test_skel = (void *)get100_skel;
		skel_bss_hits = &get100_skel->bss->hits;
		skel_bss_important_hits = &get100_skel->bss->important_hits;
		break;
	case 1000:
		get1000_skel = local_storage_bench__get1000_interleaved__open_and_load();
		local_storage_bench__get1000_interleaved__attach(get1000_skel);
		destroy_skel = (void(*)(void *))local_storage_bench__get1000_interleaved__destroy;
		test_skel = (void *)get1000_skel;
		skel_bss_hits = &get1000_skel->bss->hits;
		skel_bss_important_hits = &get1000_skel->bss->important_hits;
		break;
	default:
		fprintf(stderr,
			"got an invalid nr_maps in setup, does validate() need update?");
		teardown();
		exit(1);
		break;
	}
}

static void teardown(void)
{
	char path[100];
	int i;

	for (i = 0; i < args.nr_maps; i++) {
		sprintf(path, MAP_PIN_PATTERN "_%04d", i);
		unlink(path);
	}

	if (destroy_skel && test_skel)
		destroy_skel(test_skel);
}

static void measure(struct bench_res *res)
{
	if (skel_bss_hits)
		res->hits = atomic_swap(skel_bss_hits, 0);
	if (skel_bss_important_hits)
		res->important_hits = atomic_swap(skel_bss_important_hits, 0);
}

static inline void trigger_bpf_program(void)
{
	syscall(__NR_getpgid);
}

static void *consumer(void *input)
{
	return NULL;
}

static void *producer(void *input)
{
	while (true)
		trigger_bpf_program();

	return NULL;
}

/* cache sequential and interleaved get benchs test local_storage get
 * performance, specifically they demonstrate performance cliff of
 * current list-plus-cache local_storage model.
 *
 * cache sequential get: call bpf_task_storage_get on n maps in order
 * cache interleaved get: like "sequential get", but interleave 4 calls to the
 *	'important' map (local_storage_bench_pinned_0000) for every 10 calls. Goal
 *	is to mimic environment where many progs are accessing their local_storage
 *	maps, with 'our' prog needing to access its map more often than others
 */
const struct bench bench_local_storage_cache_seq_get = {
	.name = "local-storage-cache-seq-get",
	.validate = validate,
	.setup = local_storage_cache_get_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = local_storage_report_progress,
	.report_final = local_storage_report_final,
	.teardown = teardown,
};

const struct bench bench_local_storage_cache_interleaved_get = {
	.name = "local-storage-cache-interleaved-get",
	.validate = validate,
	.setup = local_storage_cache_get_interleaved_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = local_storage_report_progress,
	.report_final = local_storage_report_final,
	.teardown = teardown,
};
