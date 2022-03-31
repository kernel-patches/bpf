// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "bench.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"

#include "tst_bench.skel.h"

#define MAX_KEY_SIZE 256

#define PATH_LEAF_NR 1000
#define PATH_MID_LVL_NR 10

struct tst_key_component_desc {
	unsigned int nr;
	unsigned int len;
};

static struct tst_ctx {
	struct tst_bench *skel;
	struct tst_key_component_desc *desc;
	unsigned int nr_desc;
	char (*keys)[MAX_KEY_SIZE];
	char tmp[MAX_KEY_SIZE];
	unsigned int cursor;
	int cgrp_dfd;
	unsigned long long map_mem;
} ctx;

static struct {
	bool flat_key;
	bool same_len;
	__u32 max_entries;
} args = {
	.flat_key = false,
	.same_len = false,
	.max_entries = 1000,
};

enum {
	ARG_TST_ENTRIES = 7001,
	ARG_FLAT_KEY = 7002,
	ARG_SAME_LEN = 7003,
};

static const struct argp_option opts[] = {
	{ "tst-entries", ARG_TST_ENTRIES, "TST_ENTRIES", 0,
	  "Set the max entries" },
	{ "flat-key", ARG_FLAT_KEY, NULL, 0,
	  "Do not generate hierarchical key" },
	{ "same-len", ARG_SAME_LEN, NULL, 0,
	  "Generate the key with the same len" },
	{},
};

static error_t tst_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_TST_ENTRIES:
		args.max_entries = strtoul(arg, NULL, 10);
		if (args.max_entries < PATH_LEAF_NR) {
			fprintf(stderr, "invalid max entries %u (min %u)\n",
				args.max_entries, PATH_LEAF_NR);
			argp_usage(state);
		}
		break;
	case ARG_FLAT_KEY:
		args.flat_key = true;
		break;
	case ARG_SAME_LEN:
		args.same_len = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_tst_argp = {
	.options = opts,
	.parser = tst_parse_arg,
};

static void tst_validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "tst_map benchmark doesn't support multi-consumer!\n");
		exit(1);
	}
}

static char tst_random_c(void)
{
	static const char tbl[] = "0123456789abcdefghijklmnopqrstuvwxyz._";
	return tbl[random() % (sizeof(tbl) - 1)];
}

static unsigned int tst_calc_hierarchy(unsigned int nr)
{
	struct tst_key_component_desc *desc;
	unsigned int left;
	unsigned int total;
	unsigned int depth;

	/* Calculate the depth of hierarchical key */
	depth = 1;
	total = PATH_LEAF_NR;
	left = nr / PATH_LEAF_NR;
	while (left >= PATH_MID_LVL_NR) {
		left /= PATH_MID_LVL_NR;
		total *= PATH_MID_LVL_NR;
		depth++;
	}
	depth++;
	total *= left;

	desc = calloc(depth, sizeof(*desc));
	if (!desc) {
		fprintf(stderr, "failed to alloc mem for desc\n");
		exit(1);
	}

	/* Assign number and length for each component */
	desc[depth - 1].nr = PATH_LEAF_NR;
	desc[depth - 1].len = MAX_KEY_SIZE / 4;

	desc[0].nr = left;
	if (depth > 2) {
		unsigned int avg;
		unsigned int rem;
		unsigned int i;

		desc[0].len = MAX_KEY_SIZE / 32;

		/* -1 for the trailing null byte */
		left = MAX_KEY_SIZE - desc[0].len - desc[depth - 1].len - 1;
		avg = left / (depth - 2);
		rem = left - avg * (depth - 2);
		for (i = 1; i <= depth - 2; i++) {
			desc[i].nr = PATH_MID_LVL_NR;
			desc[i].len = avg;
			if (rem) {
				desc[i].len += 1;
				rem--;
			}
		}
	} else {
		desc[0].len = MAX_KEY_SIZE - desc[depth - 1].len - 1;
	}

	ctx.desc = desc;
	ctx.nr_desc = depth;

	return total;
}

static void tst_init_map_opts(struct tst_bench *skel)
{
	bpf_map__set_value_size(skel->maps.array, MAX_KEY_SIZE);
	bpf_map__set_max_entries(skel->maps.array, args.max_entries);

	bpf_map__set_key_size(skel->maps.htab, MAX_KEY_SIZE);
	bpf_map__set_max_entries(skel->maps.htab, args.max_entries);

	bpf_map__set_key_size(skel->maps.tst, MAX_KEY_SIZE);
	bpf_map__set_max_entries(skel->maps.tst, args.max_entries);
}

static inline unsigned int tst_key_len(unsigned int max_len)
{
	unsigned int len;

	if (args.same_len)
		return max_len;

	/* Make the differences between string length bigger */
	len = random() % (max_len * 15 / 16 + 1) + max_len / 16;
	if (len < 2)
		len = 2;
	return len;
}

static void tst_gen_hierarchical_key(unsigned int depth, unsigned int pos)
{
	unsigned int i, j, len;

	if (depth >= ctx.nr_desc) {
		memcpy(ctx.keys[ctx.cursor++], ctx.tmp, pos);
		return;
	}

	for (i = 0; i < ctx.desc[depth].nr; i++) {
		len = tst_key_len(ctx.desc[depth].len);

		ctx.tmp[pos] = '/';
		for (j = 1; j < len; j++)
			ctx.tmp[pos + j] = tst_random_c();
		tst_gen_hierarchical_key(depth + 1, pos + j);
	}
}

static void tst_gen_flat_key(void)
{
	unsigned int i, j, len;

	for (i = 0; i < args.max_entries; i++) {
		len = tst_key_len(MAX_KEY_SIZE - 1);
		for (j = 0; j < len; j++)
			ctx.keys[i][j] = tst_random_c();
	}
}

static void tst_alloc_and_fill_keys(void)
{
	ctx.keys = calloc(args.max_entries, sizeof(*ctx.keys));
	if (!ctx.keys) {
		fprintf(stderr, "failed to alloc mem for keys\n");
		exit(1);
	}

	if (args.flat_key)
		tst_gen_flat_key();
	else
		tst_gen_hierarchical_key(0, 0);
}

static void tst_setup_key_map(struct bpf_map *map)
{
	int fd = bpf_map__fd(map);
	unsigned int i;

	for (i = 0; i < args.max_entries; i++) {
		int err;

		err = bpf_map_update_elem(fd, &i, ctx.keys[i], 0);
		if (err) {
			fprintf(stderr, "add #%u key (%s) on %s error %d\n",
				i, ctx.keys[i], bpf_map__name(map), err);
			exit(1);
		}
	}
}

static unsigned long long tst_get_slab_mem(int dfd)
{
	const char *magic = "slab ";
	const char *name = "memory.stat";
	int fd;
	ssize_t nr;
	char buf[4096];
	char *from;

	fd = openat(dfd, name, 0);
	if (fd < 0) {
		fprintf(stderr, "no %s\n", name);
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	nr = read(fd, buf, sizeof(buf));
	if (nr <= 0) {
		fprintf(stderr, "empty %s ?\n", name);
		exit(1);
	}

	close(fd);

	from = strstr(buf, magic);
	if (!from) {
		fprintf(stderr, "no slab in %s\n", name);
		exit(1);
	}

	return strtoull(from + strlen(magic), NULL, 10);
}

static void tst_setup_lookup_map(struct bpf_map *map)
{
	int fd = bpf_map__fd(map);
	unsigned int i;
	unsigned long long before, after;

	before = tst_get_slab_mem(ctx.cgrp_dfd);
	for (i = 0; i < args.max_entries; i++) {
		int err;

		err = bpf_map_update_elem(fd, ctx.keys[i], &i, 0);
		if (err) {
			fprintf(stderr, "add #%u key (%s) on %s error %d\n",
				i, ctx.keys[i], bpf_map__name(map), err);
			exit(1);
		}
	}
	after = tst_get_slab_mem(ctx.cgrp_dfd);
	ctx.map_mem = after - before;
}

static void tst_common_setup(void)
{
	struct tst_bench *skel;
	int dfd;
	int err;

	srandom(time(NULL));

	dfd = cgroup_setup_and_join("/tst");
	if (dfd < 0) {
		fprintf(stderr, "failed to setup cgroup env\n");
		exit(1);
	}
	ctx.cgrp_dfd = dfd;

	if (!args.flat_key)
		args.max_entries = tst_calc_hierarchy(args.max_entries);

	setup_libbpf();

	skel = tst_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	tst_init_map_opts(skel);

	err = tst_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	tst_alloc_and_fill_keys();
	tst_setup_key_map(skel->maps.array);

	ctx.skel = skel;
}

static void tst_attach_prog(struct bpf_program *prog)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void htab_lookup_setup(void)
{
	tst_common_setup();
	tst_setup_lookup_map(ctx.skel->maps.htab);
	tst_attach_prog(ctx.skel->progs.htab_lookup);
}

static void tst_lookup_setup(void)
{
	tst_common_setup();
	tst_setup_lookup_map(ctx.skel->maps.tst);
	tst_attach_prog(ctx.skel->progs.tst_lookup);
}

static void *tst_producer(void *ctx)
{
	while (true)
		(void)syscall(__NR_getpgid);
	return NULL;
}

static void *tst_consumer(void *ctx)
{
	return NULL;
}

static void tst_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
	res->drops = atomic_swap(&ctx.skel->bss->drops, 0);
}

static void tst_report_final(struct bench_res res[], int res_cnt)
{
	close(ctx.cgrp_dfd);
	cleanup_cgroup_environment();

	fprintf(stdout, "Memory: %.3f MiB\n", (float)ctx.map_mem / 1024 / 1024);
	hits_drops_report_final(res, res_cnt);
}

const struct bench bench_htab_lookup = {
	.name = "htab-lookup",
	.validate = tst_validate,
	.setup = htab_lookup_setup,
	.producer_thread = tst_producer,
	.consumer_thread = tst_consumer,
	.measure = tst_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = tst_report_final,
};

const struct bench bench_tst_lookup = {
	.name = "tst-lookup",
	.validate = tst_validate,
	.setup = tst_lookup_setup,
	.producer_thread = tst_producer,
	.consumer_thread = tst_consumer,
	.measure = tst_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = tst_report_final,
};
