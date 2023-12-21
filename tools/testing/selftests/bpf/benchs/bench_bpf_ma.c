// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <argp.h>
#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>

#include "bench.h"
#include "bpf_util.h"
#include "bench_bpf_ma.skel.h"

static struct bpf_ma_ctx {
	struct bench_bpf_ma *skel;
	u64 base_bytes;
} ctx;

static struct bpf_ma_args {
	bool percpu;
} args = {
	.percpu = false,
};

enum {
	ARG_PERCPU = 20000,
};

static const struct argp_option opts[] = {
	{ "percpu", ARG_PERCPU, NULL, 0, "percpu alloc/free" },
	{},
};

static error_t bpf_ma_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_PERCPU:
		args.percpu = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_bpf_mem_alloc_argp = {
	.options = opts,
	.parser = bpf_ma_parse_arg,
};

static void read_field_in_mem_stat(const char *field, u64 *value)
{
	size_t field_len;
	char line[256];
	FILE *file;

	*value = 0;

	file = fopen("/sys/fs/cgroup/memory.stat", "r");
	if (!file) {
		/* cgroup v1 ? */
		return;
	}

	field_len = strlen(field);
	while (fgets(line, sizeof(line), file)) {
		if (!strncmp(line, field, field_len)) {
			*value = strtoull(line + field_len, NULL, 0);
			break;
		}
	}

	fclose(file);
}

static void bpf_ma_validate(void)
{
}

static int bpf_ma_update_outer_map(void)
{
	LIBBPF_OPTS(bpf_map_create_opts, opts);
	struct bpf_map *outer_map, *inner_map;
	unsigned int i, ksize, vsize, max_nr;
	int fd, err;

	if (env.nr_cpus <= 1)
		return 0;

	fd = bpf_object__btf_fd(ctx.skel->obj);
	if (fd < 0) {
		fprintf(stderr, "no btf_fd error %d\n", fd);
		return -1;
	}
	opts.btf_fd = fd;

	inner_map = args.percpu ? ctx.skel->maps.percpu_inner_array : ctx.skel->maps.inner_array;
	opts.btf_key_type_id = bpf_map__btf_key_type_id(inner_map);
	opts.btf_value_type_id = bpf_map__btf_value_type_id(inner_map);

	ksize = bpf_map__key_size(inner_map);
	vsize = bpf_map__value_size(inner_map);
	max_nr = bpf_map__max_entries(inner_map);

	outer_map = args.percpu ? ctx.skel->maps.percpu_outer_array : ctx.skel->maps.outer_array;
	for (i = 1; i < env.nr_cpus; i++) {
		char name[32];

		snprintf(name, sizeof(name), "inner_array_%u", i);
		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, name, ksize, vsize, max_nr, &opts);
		if (fd < 0) {
			fprintf(stderr, "create #%d array error %d\n", i, fd);
			return -1;
		}

		err = bpf_map_update_elem(bpf_map__fd(outer_map), &i, &fd, 0);
		if (err) {
			fprintf(stderr, "add #%d array error %d\n", i, err);
			close(fd);
			return -1;
		}
		close(fd);
	}

	return 0;
}

static void bpf_ma_setup(void)
{
	struct bpf_program *prog;
	struct bpf_map *outer_map;
	int err;

	setup_libbpf();

	ctx.skel = bench_bpf_ma__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		goto cleanup;
	}

	outer_map = args.percpu ? ctx.skel->maps.percpu_outer_array : ctx.skel->maps.outer_array;
	bpf_map__set_max_entries(outer_map, env.nr_cpus);

	prog = args.percpu ? ctx.skel->progs.bench_batch_percpu_alloc_free :
			     ctx.skel->progs.bench_batch_alloc_free;
	bpf_program__set_autoload(prog, true);

	err = bench_bpf_ma__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		goto cleanup;
	}

	if (bpf_ma_update_outer_map())
		goto cleanup;

	err = bench_bpf_ma__attach(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to attach skeleton\n");
		goto cleanup;
	}

	read_field_in_mem_stat(args.percpu ? "percpu " : "slab ", &ctx.base_bytes);
	return;

cleanup:
	bench_bpf_ma__destroy(ctx.skel);
	exit(1);
}

static void *bpf_ma_producer(void *arg)
{
	while (true)
		(void)syscall(__NR_getpgid, 0);
	return NULL;
}

static void bpf_ma_measure(struct bench_res *res)
{
	u64 bytes;

	res->ma.alloc = atomic_swap(&ctx.skel->bss->alloc_cnt, 0);
	res->ma.alloc_ns = atomic_swap(&ctx.skel->bss->alloc_ns, 0);
	res->ma.free = atomic_swap(&ctx.skel->bss->free_cnt, 0);
	res->ma.free_ns = atomic_swap(&ctx.skel->bss->free_ns, 0);

	if (args.percpu)
		read_field_in_mem_stat("percpu ", &bytes);
	else
		read_field_in_mem_stat("slab ", &bytes);
	/* Is memory reclamation in-progress ? */
	if (bytes < ctx.base_bytes)
		ctx.base_bytes = bytes;
	res->ma.mem_bytes = bytes - ctx.base_bytes;
}

static void bpf_ma_report_progress(int iter, struct bench_res *res, long delta_ns)
{
	double alloc = 0.0, free = 0.0, mem;

	if (res->ma.alloc_ns)
		alloc = res->ma.alloc * 1000.0 / res->ma.alloc_ns;
	if (res->ma.free_ns)
		free = res->ma.free * 1000.0 / res->ma.free_ns;
	mem = res->ma.mem_bytes / 1048576.0;

	printf("Iter %3d (%7.3lfus): ", iter, (delta_ns - 1000000000) / 1000.0);
	printf("per-prod alloc %7.2lfM/s free %7.2lfM/s, total memory usage %7.2lfMiB\n",
	       alloc, free, mem);
}

static void bpf_ma_report_final(struct bench_res res[], int res_cnt)
{
	double mem_mean = 0.0, mem_stddev = 0.0;
	double alloc_mean = 0.0, alloc_stddev = 0.0;
	double free_mean = 0.0, free_stddev = 0.0;
	double alloc_ns = 0.0, free_ns = 0.0;
	int i;

	for (i = 0; i < res_cnt; i++) {
		alloc_ns += res[i].ma.alloc_ns;
		free_ns += res[i].ma.free_ns;
	}
	for (i = 0; i < res_cnt; i++) {
		if (alloc_ns)
			alloc_mean += res[i].ma.alloc * 1000.0 / alloc_ns;
		if (free_ns)
			free_mean += res[i].ma.free * 1000.0 / free_ns;
		mem_mean += res[i].ma.mem_bytes / 1048576.0 / (0.0 + res_cnt);
	}
	if (res_cnt > 1) {
		for (i = 0; i < res_cnt; i++) {
			double sample;

			sample = res[i].ma.alloc_ns ? res[i].ma.alloc * 1000.0 /
						      res[i].ma.alloc_ns : 0.0;
			alloc_stddev += (alloc_mean - sample) * (alloc_mean - sample) /
					(res_cnt - 1.0);

			sample = res[i].ma.free_ns ? res[i].ma.free * 1000.0 /
						     res[i].ma.free_ns : 0.0;
			free_stddev += (free_mean - sample) * (free_mean - sample) /
				       (res_cnt - 1.0);

			sample = res[i].ma.mem_bytes / 1048576.0;
			mem_stddev += (mem_mean - sample) * (mem_mean - sample) /
				      (res_cnt - 1.0);
		}
		alloc_stddev = sqrt(alloc_stddev);
		free_stddev = sqrt(free_stddev);
		mem_stddev = sqrt(mem_stddev);
	}

	printf("Summary: per-prod alloc %7.2lf \u00B1 %3.2lfM/s free %7.2lf \u00B1 %3.2lfM/s, "
	       "total memory usage %7.2lf \u00B1 %3.2lfMiB\n",
	       alloc_mean, alloc_stddev, free_mean, free_stddev,
	       mem_mean, mem_stddev);
}

const struct bench bench_bpf_mem_alloc = {
	.name = "bpf_ma",
	.argp = &bench_bpf_mem_alloc_argp,
	.validate = bpf_ma_validate,
	.setup = bpf_ma_setup,
	.producer_thread = bpf_ma_producer,
	.measure = bpf_ma_measure,
	.report_progress = bpf_ma_report_progress,
	.report_final = bpf_ma_report_final,
};
