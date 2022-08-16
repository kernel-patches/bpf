// SPDX-License-Identifier: GPL-2.0

#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <argp.h>
#include "bench.h"
#include <bpf_util.h>

/* A hash table of the size DEFAULT_NUM_ENTRIES
 * makes evident the effect of optimizing
 * functions that iterate through the map
 */
#define DEFAULT_NUM_ENTRIES 40000
#define VALUE_SIZE 4

int map_fd, method_flag, hits;

static struct {
	__u32 capacity;
	__u32 num_entries;
} args = {
	.capacity = DEFAULT_NUM_ENTRIES,
	.num_entries = DEFAULT_NUM_ENTRIES,
};

enum {
	ARG_CAPACITY = 8000,
	ARG_NUM_ENTRIES = 8001,
};

static const struct argp_option opts[] = {
	{ "capacity", ARG_CAPACITY, "capacity", 0,
		"Set hashtable capacity"},
	{"num_entries", ARG_NUM_ENTRIES, "num_entries", 0,
		"Set number of entries in the hashtable"},
	{}
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_CAPACITY:
		args.capacity = strtol(arg, NULL, 10);
		break;
	case ARG_NUM_ENTRIES:
		args.num_entries = strtol(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_bpf_htab_batch_ops_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (args.num_entries > args.capacity) {
		fprintf(stderr, "num_entries must be less than hash table capacity");
		exit(1);
	}

	if (env.producer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-producer!\n");
		exit(1);
	}

	if (env.consumer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-consumer!\n");
		exit(1);
	}
}

static inline void loop_bpf_map_lookup_batch(void)
{
	int num_cpus = bpf_num_possible_cpus();
	typedef struct { int v[VALUE_SIZE]; /* padding */ } __bpf_percpu_val_align value[num_cpus];
	int offset = 0, out_batch = 0, in_batch = 0;
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, operts,
		.elem_flags = 0,
		.flags = 0,
	);
	value pcpu_values[args.num_entries];
	__u32 count = args.num_entries;
	double keys[args.num_entries];
	int *in_batch_ptr = NULL;
	int err;

	while (true) {
		err = bpf_map_lookup_batch(map_fd, in_batch_ptr, &out_batch,
			keys + offset, pcpu_values + offset, &count, &operts);

		if (err && errno != ENOENT) {
			fprintf(stderr, "Failed to lookup entries using bpf_map_lookup_batch\n");
			exit(1);
		}

		hits += count;

		if (count == args.num_entries) {
			count = args.num_entries;
			offset = out_batch = 0;
			in_batch_ptr = NULL;
		} else {
			offset = count;
			count = args.num_entries - count;
			in_batch = out_batch;
			in_batch_ptr = &in_batch;
		}
	}

}

static inline void loop_bpf_element_lookup(void)
{
	int num_cpus = bpf_num_possible_cpus();
	typedef struct { int v[VALUE_SIZE]; /* padding */ } __bpf_percpu_val_align value[num_cpus];
	double prev_key = -1, key;
	value value_of_key;
	int err;

	while (true) {

		while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
			err = bpf_map_lookup_elem(map_fd, &key, &value_of_key);
			if (err) {
				fprintf(stderr, "failed to lookup element using bpf_map_lookup_elem\n");
				exit(1);
			}
			hits += 1;
			prev_key = key;
		}
		prev_key = -1;

	}

}

static void *producer(void *input)
{
	switch (method_flag) {
	case 0:
		loop_bpf_map_lookup_batch();
		break;
	case 1:
		loop_bpf_element_lookup();
		break;
	}
	return NULL;
}

static void *consumer(void *input)
{
	return NULL;
}

static void measure(struct bench_res *res)
{
	res->hits = hits;
	hits = 0;
}


static void setup(void)
{

	typedef struct { int v[VALUE_SIZE]; /* padding */ } __bpf_percpu_val_align value[bpf_num_possible_cpus()];
	DECLARE_LIBBPF_OPTS(bpf_map_batch_opts, operts,
		.elem_flags = 0,
		.flags = 0,
	);
	value pcpu_values[args.num_entries];
	__u32 count = args.num_entries;
	double keys[args.num_entries];
	int err;

	map_fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_HASH, "hash_map", sizeof(double),
		(VALUE_SIZE*sizeof(int)), args.capacity, NULL);
	if (map_fd < 0) {
		fprintf(stderr, "error creating map using bpf_map_create\n");
		exit(1);
	}

	for (double i = 0; i < args.num_entries; i++) {
		keys[(int)i] = i + 1;
		for (int j = 0; j < bpf_num_possible_cpus(); j++) {
			for (int k = 0; k < VALUE_SIZE; k++)
				bpf_percpu(pcpu_values[(int)i], j)[k] = (int)i + j + k;
		}
	}

	err = bpf_map_update_batch(map_fd, keys, pcpu_values, &count, &operts);
	if (err < 0) {
		fprintf(stderr, "Failed to populate map using bpf_map_update_batch\n");
		exit(1);
	}

}

static void bench_bpf_map_lookup_batch_setup(void)
{
	setup();
	method_flag = 0;
}

static void bench_element_lookup_setup(void)
{
	setup();
	method_flag = 1;
}

const struct bench bench_bpf_htab_batch_ops = {
	.name = "htab-batch-ops",
	.validate = validate,
	.setup = bench_bpf_map_lookup_batch_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};

const struct bench bench_bpf_htab_element_ops = {
	.name = "htab-element-ops",
	.validate = validate,
	.setup = bench_element_lookup_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
