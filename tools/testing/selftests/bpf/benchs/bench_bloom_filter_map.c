// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */

#include <argp.h>
#include <linux/log2.h>
#include <pthread.h>
#include "bench.h"
#include "bloom_filter_map.skel.h"
#include "bpf_util.h"

static struct ctx {
	struct bloom_filter_map *skel;
	pthread_mutex_t map_done_mtx;
	pthread_cond_t map_done;
	bool map_prepare_err;
	__u32 next_map_idx;
} ctx = {
	.map_done_mtx = PTHREAD_MUTEX_INITIALIZER,
	.map_done = PTHREAD_COND_INITIALIZER,
};

static struct {
	__u32 nr_entries;
	__u8 nr_hash_funcs;
} args = {
	.nr_entries = 1000,
	.nr_hash_funcs = 3,
};

enum {
	ARG_NR_ENTRIES = 3000,
	ARG_NR_HASH_FUNCS = 3001,
};

static const struct argp_option opts[] = {
	{ "nr_entries", ARG_NR_ENTRIES, "NR_ENTRIES", 0,
		"Set number of entries in the bloom filter map"},
	{ "nr_hash_funcs", ARG_NR_HASH_FUNCS, "NR_HASH_FUNCS", 0,
		"Set number of hashes in the bloom filter map"},
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
		if (args.nr_hash_funcs == 0) {
			fprintf(stderr, "Cannot specify a bloom filter map with 0 hashes.");
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
		fprintf(stderr, "bloom filter map benchmark doesn't support multi-consumer!\n");
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
	int err, random_data_fd, bloom_filter_fd, hashmap_fd;
	__u64 i, val;

	bloom_filter_fd = bpf_map__fd(ctx.skel->maps.map_bloom_filter);
	random_data_fd = bpf_map__fd(ctx.skel->maps.map_random_data);
	hashmap_fd = bpf_map__fd(ctx.skel->maps.hashmap);

	while (true) {
		i = __atomic_add_fetch(&ctx.next_map_idx, 1, __ATOMIC_RELAXED);
		if (i > args.nr_entries)
			break;
again:
		err = syscall(__NR_getrandom, &val, sizeof(val), 0);
		if (err != sizeof(val)) {
			ctx.map_prepare_err = true;
			fprintf(stderr, "failed to get random value\n");
			break;
		}
		err = bpf_map_update_elem(hashmap_fd, &val, &val, BPF_NOEXIST);
		if (err) {
			if (err != -EEXIST) {
				ctx.map_prepare_err = true;
				fprintf(stderr, "failed to add elem to hashmap: %d\n", -errno);
				break;
			}
			goto again;
		}

		i--;
		err = bpf_map_update_elem(random_data_fd, &i, &val, 0);
		if (err) {
			ctx.map_prepare_err = true;
			fprintf(stderr, "failed to add elem to array: %d\n", -errno);
			break;
		}

		err = bpf_map_update_elem(bloom_filter_fd, NULL, &val, 0);
		if (err) {
			ctx.map_prepare_err = true;
			fprintf(stderr, "failed to add elem to bloom_filter: %d\n", -errno);
			break;
		}
	}

	pthread_mutex_lock(&ctx.map_done_mtx);
	pthread_cond_signal(&ctx.map_done);
	pthread_mutex_unlock(&ctx.map_done_mtx);

	return NULL;
}

static void populate_maps(void)
{
	unsigned int nr_cpus = bpf_num_possible_cpus();
	pthread_t map_thread;
	int i, err;

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

static struct bloom_filter_map *setup_skeleton(void)
{
	struct bloom_filter_map *skel;
	int err;

	setup_libbpf();

	skel = bloom_filter_map__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	err = bpf_map__resize(skel->maps.map_random_data, args.nr_entries);
	if (err) {
		fprintf(stderr, "failed to resize map_random_data\n");
		exit(1);
	}

	err = bpf_map__resize(skel->maps.hashmap, args.nr_entries);
	if (err) {
		fprintf(stderr, "failed to resize hashmap\n");
		exit(1);
	}

	err = bpf_map__resize(skel->maps.map_bloom_filter, args.nr_entries);
	if (err) {
		fprintf(stderr, "failed to resize bloom filter\n");
		exit(1);
	}

	err = bpf_map__set_nr_hash_funcs(skel->maps.map_bloom_filter, args.nr_hash_funcs);
	if (err) {
		fprintf(stderr, "failed to set %u hashes\n", args.nr_hash_funcs);
		exit(1);
	}

	if (bloom_filter_map__load(skel)) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	return skel;
}

static void bloom_filter_map_setup(void)
{
	struct bpf_link *link;

	ctx.skel = setup_skeleton();

	populate_maps();

	link = bpf_program__attach(ctx.skel->progs.prog_bloom_filter);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void hashmap_lookup_setup(void)
{
	struct bpf_link *link;

	ctx.skel = setup_skeleton();

	populate_maps();

	link = bpf_program__attach(ctx.skel->progs.prog_bloom_filter_hashmap_lookup);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void hashmap_no_bloom_filter_setup(void)
{
	struct bpf_link *link;

	ctx.skel = setup_skeleton();

	ctx.skel->data->hashmap_use_bloom_filter = false;

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
	unsigned int nr_cpus = bpf_num_possible_cpus();
	BPF_DECLARE_PERCPU(__u64, zeroed_values);
	BPF_DECLARE_PERCPU(__u64, false_hits);
	BPF_DECLARE_PERCPU(__u64, drops);
	BPF_DECLARE_PERCPU(__u64, hits);
	int err, i, percpu_array_fd;
	__u32 key;

	if (ctx.skel->bss->error != 0) {
		fprintf(stderr, "error (%d) when searching the bloom filter\n",
			ctx.skel->bss->error);
		exit(1);
	}

	key = ctx.skel->rodata->hit_key;
	percpu_array_fd = bpf_map__fd(ctx.skel->maps.percpu_array);
	err = bpf_map_lookup_elem(percpu_array_fd, &key, hits);
	if (err) {
		fprintf(stderr, "lookup in the percpu array  for 'hits' failed: %d\n",
			-errno);
		exit(1);
	}

	key = ctx.skel->rodata->drop_key;
	err = bpf_map_lookup_elem(percpu_array_fd, &key, drops);
	if (err) {
		fprintf(stderr, "lookup in the percpu array for 'drops' failed: %d\n",
			-errno);
		exit(1);
	}

	key = ctx.skel->rodata->false_hit_key;
	err = bpf_map_lookup_elem(percpu_array_fd, &key, false_hits);
	if (err) {
		fprintf(stderr, "lookup in the percpu array for 'false hits' failed: %d\n",
			-errno);
		exit(1);
	}

	for (i = 0; i < nr_cpus; i++) {
		total_hits += bpf_percpu(hits, i);
		total_drops += bpf_percpu(drops, i);
		total_false_hits += bpf_percpu(false_hits, i);
	}

	res->hits = total_hits;
	res->drops = total_drops;
	res->false_hits = total_false_hits;

	memset(zeroed_values, 0, sizeof(zeroed_values));

	/* zero out the percpu array */
	key = ctx.skel->rodata->hit_key;
	err = bpf_map_update_elem(percpu_array_fd, &key, zeroed_values, BPF_ANY);
	if (err) {
		fprintf(stderr, "zeroing the percpu array failed: %d\n", -errno);
		exit(1);
	}
	key = ctx.skel->rodata->drop_key;
	err = bpf_map_update_elem(percpu_array_fd, &key, zeroed_values, BPF_ANY);
	if (err) {
		fprintf(stderr, "zeroing the percpu array failed: %d\n", -errno);
		exit(1);
	}
	key = ctx.skel->rodata->false_hit_key;
	err = bpf_map_update_elem(percpu_array_fd, &key, zeroed_values, BPF_ANY);
	if (err) {
		fprintf(stderr, "zeroing the percpu array failed: %d\n", -errno);
		exit(1);
	}
}

static void *consumer(void *input)
{
	return NULL;
}

const struct bench bench_bloom_filter_map = {
	.name = "bloom-filter-map",
	.validate = validate,
	.setup = bloom_filter_map_setup,
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

const struct bench bench_hashmap_without_bloom_filter = {
	.name = "hashmap-without-bloom-filter",
	.validate = validate,
	.setup = hashmap_no_bloom_filter_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_hashmap_with_bloom_filter = {
	.name = "hashmap-with-bloom-filter",
	.validate = validate,
	.setup = hashmap_lookup_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
