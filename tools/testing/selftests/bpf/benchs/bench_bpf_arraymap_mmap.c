// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <argp.h>
#include <sys/mman.h>
#include "bench.h"

/*
 * Benchmark mmap()/munmap() from N threads of either an mmap-able BPF array
 * map ("bpf-arraymap-mmap") or a plain file in /tmp ("file-mmap"), the latter
 * serving as a baseline for comparison.
 */

static struct ctx {
	int map_fd;
	size_t mmap_sz;
} ctx;

static struct {
	__u32 nr_threads;
	__u64 map_size;
} args = {
	.nr_threads = 16,
	.map_size = 8 * 1024 * 1024, /* 8 MiB */
};

enum {
	ARG_NR_THREADS = 5000,
	ARG_MAP_SIZE = 5001,
};

static const struct argp_option opts[] = {
	{ "nr-threads", ARG_NR_THREADS, "NR_THREADS", 0,
		"Number of threads that mmap/munmap the map (default 16)" },
	{ "map-size", ARG_MAP_SIZE, "BYTES", 0,
		"Size of the BPF array map in bytes (default 8388608)" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_NR_THREADS:
		args.nr_threads = strtoul(arg, NULL, 0);
		if (args.nr_threads == 0) {
			fprintf(stderr, "Invalid nr-threads: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_MAP_SIZE:
		args.map_size = strtoull(arg, NULL, 0);
		if (args.map_size == 0) {
			fprintf(stderr, "Invalid map-size: %s\n", arg);
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/* exported into benchmark runner; shared by both mmap benchmarks */
const struct argp bench_bpf_arraymap_mmap_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "benchmark doesn't support consumer!\n");
		exit(1);
	}

	/* The number of worker threads is controlled by --nr-threads and
	 * drives the framework's producer machinery, so per-producer stats
	 * are reported correctly.
	 */
	env.producer_cnt = args.nr_threads;
}

static long hits;

static void *producer(void *input)
{
	while (true) {
		void *addr;

		addr = mmap(NULL, ctx.mmap_sz, PROT_READ | PROT_WRITE,
			    MAP_SHARED, ctx.map_fd, 0);
		if (addr == MAP_FAILED) {
			fprintf(stderr, "mmap failed: %d\n", -errno);
			exit(1);
		}
		if (munmap(addr, ctx.mmap_sz)) {
			fprintf(stderr, "munmap failed: %d\n", -errno);
			exit(1);
		}
		atomic_inc(&hits);
	}

	return NULL;
}

static void measure(struct bench_res *res)
{
	res->hits = atomic_swap(&hits, 0);
}

static void setup(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_MMAPABLE);
	long page_sz = sysconf(_SC_PAGESIZE);
	__u32 value_size = sizeof(__u64);
	__u32 max_entries;

	setup_libbpf();

	/* mmap-able array maps round the value size up to 8 bytes and expose
	 * PAGE_ALIGN(max_entries * elem_size) bytes to user space.
	 */
	max_entries = (args.map_size + value_size - 1) / value_size;
	ctx.mmap_sz = ((__u64)max_entries * value_size + page_sz - 1) &
		      ~(page_sz - 1);

	ctx.map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mmap_array",
				    sizeof(__u32), value_size, max_entries,
				    &opts);
	if (ctx.map_fd < 0) {
		fprintf(stderr, "failed to create map: %d\n", -errno);
		exit(1);
	}

	printf("array map: %u entries, mmap size %zu bytes, %u threads\n",
	       max_entries, ctx.mmap_sz, args.nr_threads);
}

const struct bench bench_bpf_arraymap_mmap = {
	.name = "bpf-arraymap-mmap",
	.argp = &bench_bpf_arraymap_mmap_argp,
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};

static void file_setup(void)
{
	long page_sz = sysconf(_SC_PAGESIZE);
	char path[] = "/tmp/bench_mmap_XXXXXX";
	int fd;

	ctx.mmap_sz = (args.map_size + page_sz - 1) & ~(page_sz - 1);

	fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "failed to create temp file: %d\n", -errno);
		exit(1);
	}
	/* Unlink now; the file stays alive via the open fd and is reclaimed
	 * automatically when the benchmark exits.
	 */
	unlink(path);

	if (ftruncate(fd, ctx.mmap_sz)) {
		fprintf(stderr, "failed to size temp file: %d\n", -errno);
		exit(1);
	}
	ctx.map_fd = fd;

	printf("file %s: mmap size %zu bytes, %u threads\n",
	       path, ctx.mmap_sz, args.nr_threads);
}

const struct bench bench_file_mmap = {
	.name = "file-mmap",
	.argp = &bench_bpf_arraymap_mmap_argp,
	.validate = validate,
	.setup = file_setup,
	.producer_thread = producer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
