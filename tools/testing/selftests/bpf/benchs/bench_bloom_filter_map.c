// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <argp.h>
#include <linux/log2.h>
#include <pthread.h>
#include "bench.h"
#include "bloom_filter_bench.skel.h"
#include "bpf_util.h"

static struct ctx {
	struct bloom_filter_bench *skel;

	int bloom_filter_fd;
	int hashmap_fd;
	int array_map_fd;

	pthread_mutex_t map_done_mtx;
	pthread_cond_t map_done;
	bool map_prepare_err;

	__u32 next_map_idx;

} ctx = {
	.map_done_mtx = PTHREAD_MUTEX_INITIALIZER,
	.map_done = PTHREAD_COND_INITIALIZER,
};

struct stat {
	__u32 stats[3];
};

static struct {
	__u32 nr_entries;
	__u8 nr_hash_funcs;
	__u32 value_size;
} args = {
	.nr_entries = 1000,
	.nr_hash_funcs = 3,
	.value_size = 8,
};

enum {
	ARG_NR_ENTRIES = 3000,
	ARG_NR_HASH_FUNCS = 3001,
	ARG_VALUE_SIZE = 3002,
};

static const struct argp_option opts[] = {
	{ "nr_entries", ARG_NR_ENTRIES, "NR_ENTRIES", 0,
		"Set number of expected unique entries in the bloom filter"},
	{ "nr_hash_funcs", ARG_NR_HASH_FUNCS, "NR_HASH_FUNCS", 0,
		"Set number of hash functions in the bloom filter"},
	{ "value_size", ARG_VALUE_SIZE, "VALUE_SIZE", 0,
		"Set value size (in bytes) of bloom filter entries"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_NR_ENTRIES:
		args.nr_entries = strtol(arg, NULL, 10);
		if (args.nr_entries == 0) {
			fprintf(stderr, "Invalid nr_entries count.");
			argp_usage(state);
		}
		break;
	case ARG_NR_HASH_FUNCS:
		args.nr_hash_funcs = strtol(arg, NULL, 10);
		if (args.nr_hash_funcs == 0 || args.nr_hash_funcs > 15) {
			fprintf(stderr,
				"The bloom filter must use 1 to 15 hash functions.");
			argp_usage(state);
		}
		break;
	case ARG_VALUE_SIZE:
		args.value_size = strtol(arg, NULL, 10);
		if (args.value_size < 2 || args.value_size > 256) {
			fprintf(stderr,
				"Invalid value size. Must be between 2 and 256 bytes");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/* exported into benchmark runner */
const struct argp bench_bloom_filter_map_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr,
			"The bloom filter benchmarks do not support multi-consumer use\n");
		exit(1);
	}
}

static inline void trigger_bpf_program(void)
{
	syscall(__NR_getpgid);
}

static void *producer(void *input)
{
	while (true)
		trigger_bpf_program();

	return NULL;
}

static void *map_prepare_thread(void *arg)
{
	__u32 val_size, i;
	void *val = NULL;
	int err;

	val_size = args.value_size;
	val = malloc(val_size);
	if (!val) {
		ctx.map_prepare_err = true;
		goto done;
	}

	while (true) {
		i = __atomic_add_fetch(&ctx.next_map_idx, 1, __ATOMIC_RELAXED);
		if (i > args.nr_entries)
			break;

again:
		/* Populate hashmap, bloom filter map, and array map with the same
		 * random values
		 */
		err = syscall(__NR_getrandom, val, val_size, 0);
		if (err != val_size) {
			ctx.map_prepare_err = true;
			fprintf(stderr, "failed to get random value: %d\n", -errno);
			break;
		}

		err = bpf_map_update_elem(ctx.hashmap_fd, val, val, BPF_NOEXIST);
		if (err) {
			if (err != -EEXIST) {
				ctx.map_prepare_err = true;
				fprintf(stderr, "failed to add elem to hashmap: %d\n",
					-errno);
				break;
			}
			goto again;
		}

		i--;

		err = bpf_map_update_elem(ctx.array_map_fd, &i, val, 0);
		if (err) {
			ctx.map_prepare_err = true;
			fprintf(stderr, "failed to add elem to array map: %d\n", -errno);
			break;
		}

		err = bpf_map_update_elem(ctx.bloom_filter_fd, NULL, val, 0);
		if (err) {
			ctx.map_prepare_err = true;
			fprintf(stderr,
				"failed to add elem to bloom filter map: %d\n", -errno);
			break;
		}
	}
done:
	pthread_mutex_lock(&ctx.map_done_mtx);
	pthread_cond_signal(&ctx.map_done);
	pthread_mutex_unlock(&ctx.map_done_mtx);

	if (val)
		free(val);

	return NULL;
}

static void populate_maps(void)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	pthread_t map_thread;
	int i, err;

	ctx.bloom_filter_fd = bpf_map__fd(ctx.skel->maps.bloom_filter_map);
	ctx.hashmap_fd = bpf_map__fd(ctx.skel->maps.hashmap);
	ctx.array_map_fd = bpf_map__fd(ctx.skel->maps.array_map);

	for (i = 0; i < nr_cpus; i++) {
		err = pthread_create(&map_thread, NULL, map_prepare_thread,
				     NULL);
		if (err) {
			fprintf(stderr, "failed to create pthread: %d\n", -errno);
			exit(1);
		}
	}

	pthread_mutex_lock(&ctx.map_done_mtx);
	pthread_cond_wait(&ctx.map_done, &ctx.map_done_mtx);
	pthread_mutex_unlock(&ctx.map_done_mtx);

	if (ctx.map_prepare_err)
		exit(1);
}

static struct bloom_filter_bench *setup_skeleton(bool hashmap_use_bloom_filter)
{
	struct bloom_filter_bench *skel;
	int err;

	setup_libbpf();

	skel = bloom_filter_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	skel->rodata->hashmap_use_bloom_filter = hashmap_use_bloom_filter;

	/* Resize number of entries */
	err = bpf_map__resize(skel->maps.hashmap, args.nr_entries);
	if (err) {
		fprintf(stderr, "failed to resize hashmap\n");
		exit(1);
	}

	err = bpf_map__resize(skel->maps.array_map, args.nr_entries);
	if (err) {
		fprintf(stderr, "failed to resize array map\n");
		exit(1);
	}

	err = bpf_map__resize(skel->maps.bloom_filter_map,
			      BPF_BLOOM_FILTER_BITSET_SZ(args.nr_entries,
							 args.nr_hash_funcs));
	if (err) {
		fprintf(stderr, "failed to resize bloom filter\n");
		exit(1);
	}

	/* Set value size */
	err = bpf_map__set_value_size(skel->maps.array_map, args.value_size);
	if (err) {
		fprintf(stderr, "failed to set array map value size\n");
		exit(1);
	}

	err = bpf_map__set_value_size(skel->maps.bloom_filter_map, args.value_size);
	if (err) {
		fprintf(stderr, "failed to set bloom filter map value size\n");
		exit(1);
	}

	err = bpf_map__set_value_size(skel->maps.hashmap, args.value_size);
	if (err) {
		fprintf(stderr, "failed to set hashmap value size\n");
		exit(1);
	}
	/* For the hashmap, we use the value as the key as well */
	err = bpf_map__set_key_size(skel->maps.hashmap, args.value_size);
	if (err) {
		fprintf(stderr, "failed to set hashmap value size\n");
		exit(1);
	}

	skel->bss->value_sz_nr_u32s = (args.value_size + sizeof(__u32) - 1)
		/ sizeof(__u32);

	/* Set number of hash functions */
	err = bpf_map__set_map_extra(skel->maps.bloom_filter_map,
				     args.nr_hash_funcs);
	if (err) {
		fprintf(stderr, "failed to set bloom filter nr_hash_funcs\n");
		exit(1);
	}

	if (bloom_filter_bench__load(skel)) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	return skel;
}

static void bench_setup_lookup(void)
{
	struct bpf_link *link;

	ctx.skel = setup_skeleton(true);

	populate_maps();

	link = bpf_program__attach(ctx.skel->progs.prog_bloom_filter_lookup);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void bench_setup_update(void)
{
	struct bpf_link *link;

	ctx.skel = setup_skeleton(true);

	populate_maps();

	link = bpf_program__attach(ctx.skel->progs.prog_bloom_filter_update);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void hashmap_lookup_setup(void)
{
	struct bpf_link *link;

	ctx.skel = setup_skeleton(true);

	populate_maps();

	link = bpf_program__attach(ctx.skel->progs.prog_bloom_filter_hashmap_lookup);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void measure(struct bench_res *res)
{
	long total_hits = 0, total_drops = 0, total_false_hits = 0;
	static long last_hits, last_drops, last_false_hits;
	unsigned int nr_cpus = bpf_num_possible_cpus();
	int hit_key, drop_key, false_hit_key;
	int i;

	hit_key = ctx.skel->rodata->hit_key;
	drop_key = ctx.skel->rodata->drop_key;
	false_hit_key = ctx.skel->rodata->false_hit_key;

	if (ctx.skel->bss->error != 0) {
		fprintf(stderr, "error (%d) when searching the bitset\n",
			ctx.skel->bss->error);
		exit(1);
	}

	for (i = 0; i < nr_cpus; i++) {
		struct stat *s = (void *)&ctx.skel->bss->percpu_stats[i];

		total_hits += s->stats[hit_key];
		total_drops += s->stats[drop_key];
		total_false_hits += s->stats[false_hit_key];
	}

	res->hits = total_hits - last_hits;
	res->drops = total_drops - last_drops;
	res->false_hits = total_false_hits - last_false_hits;

	last_hits = total_hits;
	last_drops = total_drops;
	last_false_hits = total_false_hits;
}

static void *consumer(void *input)
{
	return NULL;
}

const struct bench bench_bloom_filter_lookup = {
	.name = "bloom-filter-lookup",
	.validate = validate,
	.setup = bench_setup_lookup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_bloom_filter_update = {
	.name = "bloom-filter-update",
	.validate = validate,
	.setup = bench_setup_update,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_bloom_filter_false_positive = {
	.name = "bloom-filter-false-positive",
	.validate = validate,
	.setup = hashmap_lookup_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = false_hits_report_progress,
	.report_final = false_hits_report_final,
};
