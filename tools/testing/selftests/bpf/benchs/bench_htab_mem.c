// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <argp.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "bench.h"
#include "cgroup_helpers.h"
#include "htab_mem_bench.skel.h"

static struct htab_mem_ctx {
	struct htab_mem_bench *skel;
	pthread_barrier_t *notify;
	int fd;
	bool do_notify_wait;
} ctx;

static struct htab_mem_args {
	u32 max_entries;
	u32 value_size;
	u32 full;
	const char *use_case;
	bool preallocated;
} args = {
	.max_entries = 16384,
	.full = 50,
	.value_size = 8,
	.use_case = "overwrite",
	.preallocated = false,
};

enum {
	ARG_MAX_ENTRIES = 10000,
	ARG_FULL_PERCENT = 10001,
	ARG_VALUE_SIZE = 10002,
	ARG_USE_CASE = 10003,
	ARG_PREALLOCATED = 10004,
};

static const struct argp_option opts[] = {
	{ "max-entries", ARG_MAX_ENTRIES, "MAX_ENTRIES", 0,
	  "Set the max entries of hash map (default 16384)" },
	{ "full", ARG_FULL_PERCENT, "FULL", 0,
	  "Set the full percent of hash map (default 50)" },
	{ "value-size", ARG_VALUE_SIZE, "VALUE_SIZE", 0,
	  "Set the value size of hash map (default 8)" },
	{ "use-case", ARG_USE_CASE, "USE_CASE", 0,
	  "Set the use case of hash map: no_op|overwrite|batch_add_batch_del|add_del_on_diff_cpu" },
	{ "preallocated", ARG_PREALLOCATED, NULL, 0, "use preallocated hash map" },
	{},
};

static error_t htab_mem_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_MAX_ENTRIES:
		args.max_entries = strtoul(arg, NULL, 10);
		break;
	case ARG_FULL_PERCENT:
		args.full = strtoul(arg, NULL, 10);
		if (!args.full || args.full > 100) {
			fprintf(stderr, "invalid full percent %u\n", args.full);
			argp_usage(state);
		}
		break;
	case ARG_VALUE_SIZE:
		args.value_size = strtoul(arg, NULL, 10);
		if (args.value_size > 4096) {
			fprintf(stderr, "too big value size %u\n", args.value_size);
			argp_usage(state);
		}
		break;
	case ARG_USE_CASE:
		args.use_case = strdup(arg);
		break;
	case ARG_PREALLOCATED:
		args.preallocated = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_htab_mem_argp = {
	.options = opts,
	.parser = htab_mem_parse_arg,
};

static void htab_mem_validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "htab mem benchmark doesn't support multi-consumer!\n");
		exit(1);
	}
}

static int setup_and_join_cgroup(const char *path)
{
	int err, fd;

	err = setup_cgroup_environment();
	if (err) {
		fprintf(stderr, "setup cgroup env failed\n");
		return -1;
	}

	err = create_and_get_cgroup(path);
	if (err < 0) {
		fprintf(stderr, "create cgroup %s failed\n", path);
		goto out;
	}
	fd = err;

	err = join_cgroup(path);
	if (err) {
		fprintf(stderr, "join cgroup %s failed\n", path);
		close(fd);
		goto out;
	}

	return fd;
out:
	cleanup_cgroup_environment();
	return -1;
}

static int htab_mem_bench_init_barriers(void)
{
	unsigned int i, nr = (env.producer_cnt + 1) / 2;
	pthread_barrier_t *barriers;

	barriers = calloc(nr, sizeof(*barriers));
	if (!barriers)
		return -1;

	/* Used for synchronization between two threads */
	for (i = 0; i < nr; i++)
		pthread_barrier_init(&barriers[i], NULL, 2);

	ctx.notify = barriers;
	return 0;
}

static void htab_mem_bench_exit_barriers(void)
{
	unsigned int i, nr;

	if (!ctx.notify)
		return;

	nr = (env.producer_cnt + 1) / 2;
	for (i = 0; i < nr; i++)
		pthread_barrier_destroy(&ctx.notify[i]);
	free(ctx.notify);
}

static void htab_mem_setup(void)
{
	struct bpf_program *prog;
	struct bpf_map *map;
	int err;

	setup_libbpf();

	err = setup_and_join_cgroup("/htab_mem");
	if (err < 0)
		exit(1);
	ctx.fd = err;

	ctx.skel = htab_mem_bench__open();
	if (!ctx.skel) {
		fprintf(stderr, "failed to open skeleton\n");
		goto cleanup;
	}

	err = htab_mem_bench_init_barriers();
	if (err) {
		fprintf(stderr, "failed to init barrier\n");
		goto cleanup;
	}

	map = ctx.skel->maps.htab;
	bpf_map__set_max_entries(map, args.max_entries);
	bpf_map__set_value_size(map, args.value_size);
	if (args.preallocated)
		bpf_map__set_map_flags(map, bpf_map__map_flags(map) & ~BPF_F_NO_PREALLOC);

	/* Do synchronization between addition thread and deletion thread */
	if (!strcmp("add_del_on_diff_cpu", args.use_case))
		ctx.do_notify_wait = true;

	prog = bpf_object__find_program_by_name(ctx.skel->obj, args.use_case);
	if (!prog) {
		fprintf(stderr, "no such use-case: %s\n", args.use_case);
		fprintf(stderr, "available use case:");
		bpf_object__for_each_program(prog, ctx.skel->obj)
			fprintf(stderr, " %s", bpf_program__name(prog));
		fprintf(stderr, "\n");
		goto cleanup;
	}
	bpf_program__set_autoload(prog, true);

	ctx.skel->bss->nr_thread = env.producer_cnt;
	ctx.skel->bss->nr_entries = (uint64_t)args.max_entries * args.full / 100;

	err = htab_mem_bench__load(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		goto cleanup;
	}
	err = htab_mem_bench__attach(ctx.skel);
	if (err) {
		fprintf(stderr, "failed to attach skeleton\n");
		goto cleanup;
	}
	return;
cleanup:
	close(ctx.fd);
	cleanup_cgroup_environment();
	htab_mem_bench_exit_barriers();
	htab_mem_bench__destroy(ctx.skel);
	exit(1);
}

static void htab_mem_notify_wait_producer(pthread_barrier_t *notify)
{
	while (true) {
		(void)syscall(__NR_getpgid);
		/* Notify for start */
		pthread_barrier_wait(notify);
		/* Wait for completion */
		pthread_barrier_wait(notify);
	}
}

static void htab_mem_wait_notify_producer(pthread_barrier_t *notify)
{
	while (true) {
		/* Wait for start */
		pthread_barrier_wait(notify);
		(void)syscall(__NR_getpgid);
		/* Notify for completion */
		pthread_barrier_wait(notify);
	}
}

static void *htab_mem_producer(void *arg)
{
	pthread_barrier_t *notify;
	int seq;

	if (!ctx.do_notify_wait) {
		while (true)
			(void)syscall(__NR_getpgid);
		return NULL;
	}

	seq = (long)arg;
	notify = &ctx.notify[seq / 2];
	if (seq & 1)
		htab_mem_notify_wait_producer(notify);
	else
		htab_mem_wait_notify_producer(notify);
	return NULL;
}

static void *htab_mem_consumer(void *arg)
{
	return NULL;
}

static void htab_mem_read_mem_cgrp_file(const char *name, unsigned long *value)
{
	char buf[32];
	int fd;

	fd = openat(ctx.fd, name, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "no %s\n", name);
		*value = 0;
		return;
	}

	buf[sizeof(buf) - 1] = 0;
	read(fd, buf, sizeof(buf) - 1);
	*value = strtoull(buf, NULL, 0);

	close(fd);
}

static void htab_mem_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->loop_cnt, 0);
	htab_mem_read_mem_cgrp_file("memory.current", &res->gp_ct);
}

static void htab_mem_report_progress(int iter, struct bench_res *res, long delta_ns)
{
	double loop, mem;

	loop = res->hits / 1000.0 / (delta_ns / 1000000000.0);
	mem = res->gp_ct / 1048576.0;
	printf("Iter %3d (%7.3lfus): ", iter, (delta_ns - 1000000000) / 1000.0);
	printf("loop %7.2lfk/s, memory usage %7.2lfMiB\n", loop, mem);
}

static void htab_mem_report_final(struct bench_res res[], int res_cnt)
{
	double mem_mean = 0.0, mem_stddev = 0.0;
	double loop_mean = 0.0, loop_stddev = 0.0;
	unsigned long peak_mem;
	int i;

	for (i = 0; i < res_cnt; i++) {
		loop_mean += res[i].hits / 1000.0 / (0.0 + res_cnt);
		mem_mean += res[i].gp_ct / 1048576.0 / (0.0 + res_cnt);
	}
	if (res_cnt > 1)  {
		for (i = 0; i < res_cnt; i++) {
			loop_stddev += (loop_mean - res[i].hits / 1000.0) *
				       (loop_mean - res[i].hits / 1000.0) /
				       (res_cnt - 1.0);
			mem_stddev += (mem_mean - res[i].gp_ct / 1048576.0) *
				      (mem_mean - res[i].gp_ct / 1048576.0) /
				      (res_cnt - 1.0);
		}
		loop_stddev = sqrt(loop_stddev);
		mem_stddev = sqrt(mem_stddev);
	}

	htab_mem_read_mem_cgrp_file("memory.peak", &peak_mem);
	printf("Summary: loop %7.2lf \u00B1 %7.2lfk/s, memory usage %7.2lf \u00B1 %7.2lfMiB, "
	       "peak memory usage %7.2lfMiB\n",
	       loop_mean, loop_stddev, mem_mean, mem_stddev, peak_mem / 1048576.0);
}

const struct bench bench_htab_mem = {
	.name = "htab-mem",
	.argp = &bench_htab_mem_argp,
	.validate = htab_mem_validate,
	.setup = htab_mem_setup,
	.producer_thread = htab_mem_producer,
	.consumer_thread = htab_mem_consumer,
	.measure = htab_mem_measure,
	.report_progress = htab_mem_report_progress,
	.report_final = htab_mem_report_final,
};
