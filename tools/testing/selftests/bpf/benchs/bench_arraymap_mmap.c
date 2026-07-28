// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. */
#include <argp.h>
#include <sys/mman.h>
#include "bench.h"

/* Benchmark mmap()/munmap() of an mmap-able BPF array map from N threads. */

static struct ctx {
	int map_fd;
	size_t mmap_sz;
	long page_sz;
} ctx;

static struct {
	__u64 map_size;
	bool populate;
	bool touch;
} args = {
	.map_size = 8 * 1024 * 1024, /* 8 MiB */
};

enum {
	ARG_MAP_SIZE = 5000,
	ARG_POPULATE = 5001,
	ARG_TOUCH = 5002,
};

static const struct argp_option opts[] = {
	{ "map-size", ARG_MAP_SIZE, "BYTES", 0,
		"Size of the BPF array map in bytes (default 8388608)" },
	{ "populate", ARG_POPULATE, NULL, 0,
		"Pass MAP_POPULATE to mmap()" },
	{ "touch", ARG_TOUCH, NULL, 0,
		"Access one byte in every page of the mapping" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_MAP_SIZE:
		args.map_size = strtoull(arg, NULL, 0);
		if (args.map_size == 0) {
			fprintf(stderr, "Invalid map-size: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARG_POPULATE:
		args.populate = true;
		break;
	case ARG_TOUCH:
		args.touch = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

/* exported into benchmark runner */
const struct argp bench_arraymap_mmap_argp = {
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

static long hits;

static void *producer(void *input)
{
	int flags = MAP_SHARED | (args.populate ? MAP_POPULATE : 0);

	while (true) {
		size_t off;
		void *addr;

		addr = mmap(NULL, ctx.mmap_sz, PROT_READ | PROT_WRITE, flags,
			    ctx.map_fd, 0);
		if (addr == MAP_FAILED) {
			fprintf(stderr, "mmap failed: %d\n", -errno);
			exit(1);
		}
		/*
		 * Optionally access one byte in every page, so the measured
		 * cost includes faulting in the whole mapping. The volatile
		 * access keeps the compiler from optimizing the read away.
		 */
		if (args.touch)
			for (off = 0; off < ctx.mmap_sz; off += ctx.page_sz)
				(void)*(volatile char *)(addr + off);
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

	/*
	 * mmap-able array maps round the value size up to 8 bytes and expose
	 * PAGE_ALIGN(max_entries * elem_size) bytes to user space.
	 */
	max_entries = (args.map_size + value_size - 1) / value_size;
	ctx.mmap_sz = ((__u64)max_entries * value_size + page_sz - 1) &
		      ~(page_sz - 1);
	ctx.page_sz = page_sz;

	ctx.map_fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "mmap_array",
				    sizeof(__u32), value_size, max_entries,
				    &opts);
	if (ctx.map_fd < 0) {
		fprintf(stderr, "failed to create map: %d\n", -errno);
		exit(1);
	}

	printf("array map: %u entries, mmap size %zu bytes, %d threads, %s, %s\n",
	       max_entries, ctx.mmap_sz, env.producer_cnt,
	       args.populate ? "MAP_POPULATE" : "no MAP_POPULATE",
	       args.touch ? "access all pages" : "no access");
}

const struct bench bench_arraymap_mmap = {
	.name = "arraymap-mmap",
	.argp = &bench_arraymap_mmap_argp,
	.validate = validate,
	.setup = setup,
	.producer_thread = producer,
	.measure = measure,
	.report_progress = ops_report_progress,
	.report_final = ops_report_final,
};
