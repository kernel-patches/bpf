// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "bench.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"

#include "qp_trie_bench.skel.h"

enum {
	FOR_HTAB = 0,
	FOR_TRIE,
};

static struct qp_trie_ctx {
	struct qp_trie_bench *skel;
	int cgrp_dfd;
	u64 map_slab_mem;
} ctx;

static struct {
	const char *file;
	__u32 entries;
} args;

struct run_stat {
	__u64 stats[2];
};

enum {
	ARG_DATA_FILE = 8001,
	ARG_DATA_ENTRIES = 8002,
};

static const struct argp_option opts[] = {
	{ "file", ARG_DATA_FILE, "DATA-FILE", 0, "Set data file" },
	{ "entries", ARG_DATA_ENTRIES, "DATA-ENTRIES", 0, "Set data entries" },
	{},
};

static error_t qp_trie_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_DATA_FILE:
		args.file = strdup(arg);
		break;
	case ARG_DATA_ENTRIES:
		args.entries = strtoul(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_qp_trie_argp = {
	.options = opts,
	.parser = qp_trie_parse_arg,
};

static int parse_data_set(const char *name, struct bpf_qp_trie_key ***set, unsigned int *nr,
			  unsigned int *max_len)
{
#define INT_MAX_DATA_SIZE 1024
	unsigned int i, nr_items, item_max_len;
	char line[INT_MAX_DATA_SIZE + 1];
	struct bpf_qp_trie_key **items;
	struct bpf_qp_trie_key *cur;
	int err = 0;
	FILE *file;
	char *got;

	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "open %s err %s\n", name, strerror(errno));
		return -1;
	}

	got = fgets(line, sizeof(line), file);
	if (!got) {
		fprintf(stderr, "empty file ?\n");
		err = -1;
		goto out;
	}
	if (sscanf(line, "%u", &nr_items) != 1) {
		fprintf(stderr, "the first line must be the number of items\n");
		err = -1;
		goto out;
	}

	fprintf(stdout, "item %u\n", nr_items);

	items = (struct bpf_qp_trie_key **)calloc(nr_items, sizeof(*items) + INT_MAX_DATA_SIZE);
	if (!items) {
		fprintf(stderr, "no mem for items\n");
		err = -1;
		goto out;
	}

	i = 0;
	item_max_len = 0;
	cur = (void *)items + sizeof(*items) * nr_items;
	while (true) {
		unsigned int len;

		got = fgets(line, sizeof(line), file);
		if (!got) {
			if (!feof(file)) {
				fprintf(stderr, "read file %s error\n", name);
				err = -1;
			}
			break;
		}

		len = strlen(got);
		if (len && got[len - 1] == '\n') {
			got[len - 1] = 0;
			len -= 1;
		}
		if (!len) {
			fprintf(stdout, "#%u empty line\n", i + 2);
			continue;
		}

		if (i >= nr_items) {
			fprintf(stderr, "too many line in %s\n", name);
			break;
		}

		if (len > item_max_len)
			item_max_len = len;
		cur->len = len;
		memcpy(cur->data, got, len);
		items[i++] = cur;
		cur = (void *)cur + INT_MAX_DATA_SIZE;
	}

	if (!err) {
		if (i != nr_items)
			fprintf(stdout, "few lines in %s (exp %u got %u)\n", name, nr_items, i);
		*nr = i;
		*set = items;
		*max_len = item_max_len;
	} else {
		free(items);
	}

out:
	fclose(file);
	return err;
}

static int gen_data_set(struct bpf_qp_trie_key ***set, unsigned int *nr, unsigned int *max_len)
{
#define RND_MAX_DATA_SIZE 256
	struct bpf_qp_trie_key **items;
	struct bpf_qp_trie_key *cur;
	size_t ptr_size, data_size;
	unsigned int i, nr_items;
	ssize_t got;
	int err = 0;

	ptr_size = *nr * sizeof(*items);
	data_size = *nr * (sizeof(*cur) + RND_MAX_DATA_SIZE);
	items = (struct bpf_qp_trie_key **)malloc(ptr_size + data_size);
	if (!items) {
		fprintf(stderr, "no mem for items\n");
		err = -1;
		goto out;
	}

	cur = (void *)items + ptr_size;
	got = syscall(__NR_getrandom, cur, data_size, 0);
	if (got != data_size) {
		fprintf(stderr, "getrandom error %s\n", strerror(errno));
		err = -1;
		goto out;
	}

	nr_items = 0;
	for (i = 0; i < *nr; i++) {
		cur->len &= 0xff;
		if (cur->len) {
			items[nr_items++] = cur;
			memset(cur->data + cur->len, 0, RND_MAX_DATA_SIZE - cur->len);
		}
		cur = (void *)cur + (sizeof(*cur) + RND_MAX_DATA_SIZE);
	}
	if (!nr_items) {
		fprintf(stderr, "no valid key in random data\n");
		err = -1;
		goto out;
	}
	fprintf(stdout, "generate %u random keys\n", nr_items);

	*nr = nr_items;
	*set = items;
	*max_len = RND_MAX_DATA_SIZE;
out:
	if (err && items)
		free(items);
	return err;
}

static void qp_trie_validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "qp_trie_map benchmark doesn't support multi-consumer!\n");
		exit(1);
	}

	if (!args.file && !args.entries) {
		fprintf(stderr, "must specify entries when use random generated data set\n");
		exit(1);
	}

	if (args.file && access(args.file, R_OK)) {
		fprintf(stderr, "data file is un-accessible\n");
		exit(1);
	}
}

static void qp_trie_init_map_opts(struct qp_trie_bench *skel, unsigned int data_size,
				  unsigned int nr)
{
	unsigned int key_size = data_size + sizeof(struct bpf_qp_trie_key);

	bpf_map__set_value_size(skel->maps.htab_array, data_size);
	bpf_map__set_max_entries(skel->maps.htab_array, nr);

	bpf_map__set_key_size(skel->maps.htab, data_size);
	bpf_map__set_max_entries(skel->maps.htab, nr);

	bpf_map__set_value_size(skel->maps.trie_array, key_size);
	bpf_map__set_max_entries(skel->maps.trie_array, nr);

	bpf_map__set_key_size(skel->maps.qp_trie, key_size);
	bpf_map__set_max_entries(skel->maps.qp_trie, nr);
}

static void qp_trie_setup_key_map(struct bpf_map *map, unsigned int map_type,
				  struct bpf_qp_trie_key **set, unsigned int nr)
{
	int fd = bpf_map__fd(map);
	unsigned int i;

	for (i = 0; i < nr; i++) {
		void *value;
		int err;

		value = (map_type != FOR_HTAB) ? (void *)set[i] : (void *)set[i]->data;
		err = bpf_map_update_elem(fd, &i, value, 0);
		if (err) {
			fprintf(stderr, "add #%u key (%s) on %s error %d\n",
				i, set[i]->data, bpf_map__name(map), err);
			exit(1);
		}
	}
}

static u64 qp_trie_get_slab_mem(int dfd)
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

	nr = read(fd, buf, sizeof(buf));
	if (nr <= 0) {
		fprintf(stderr, "empty %s ?\n", name);
		exit(1);
	}
	buf[nr - 1] = 0;

	close(fd);

	from = strstr(buf, magic);
	if (!from) {
		fprintf(stderr, "no slab in %s\n", name);
		exit(1);
	}

	return strtoull(from + strlen(magic), NULL, 10);
}

static void qp_trie_setup_lookup_map(struct bpf_map *map, unsigned int map_type,
				     struct bpf_qp_trie_key **set, unsigned int nr)
{
	int fd = bpf_map__fd(map);
	unsigned int i;

	for (i = 0; i < nr; i++) {
		void *key;
		int err;

		key = (map_type != FOR_HTAB) ? (void *)set[i] : (void *)set[i]->data;
		err = bpf_map_update_elem(fd, key, &i, 0);
		if (err) {
			fprintf(stderr, "add #%u key (%s) on %s error %d\n",
				i, set[i]->data, bpf_map__name(map), err);
			exit(1);
		}
	}
}

static void qp_trie_setup(unsigned int map_type)
{
	struct bpf_qp_trie_key **set = NULL;
	struct qp_trie_bench *skel;
	unsigned int nr = 0, max_len = 0;
	struct bpf_map *map;
	u64 before, after;
	int dfd;
	int err;

	if (!args.file) {
		nr = args.entries;
		err = gen_data_set(&set, &nr, &max_len);
	} else {
		err = parse_data_set(args.file, &set, &nr, &max_len);
	}
	if (err < 0)
		exit(1);

	if (args.entries && args.entries < nr)
		nr = args.entries;

	dfd = cgroup_setup_and_join("/qp_trie");
	if (dfd < 0) {
		fprintf(stderr, "failed to setup cgroup env\n");
		exit(1);
	}

	setup_libbpf();

	before = qp_trie_get_slab_mem(dfd);

	skel = qp_trie_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	qp_trie_init_map_opts(skel, max_len, nr);

	skel->bss->update_nr = nr;
	skel->bss->update_chunk = nr / env.producer_cnt;

	err = qp_trie_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		exit(1);
	}

	map = (map_type == FOR_HTAB) ? skel->maps.htab_array : skel->maps.trie_array;
	qp_trie_setup_key_map(map, map_type, set, nr);

	map = (map_type == FOR_HTAB) ? skel->maps.htab : skel->maps.qp_trie;
	qp_trie_setup_lookup_map(map, map_type, set, nr);

	after = qp_trie_get_slab_mem(dfd);

	ctx.skel = skel;
	ctx.cgrp_dfd = dfd;
	ctx.map_slab_mem = after - before;
}

static void qp_trie_attach_prog(struct bpf_program *prog)
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
	qp_trie_setup(FOR_HTAB);
	qp_trie_attach_prog(ctx.skel->progs.htab_lookup);
}

static void qp_trie_lookup_setup(void)
{
	qp_trie_setup(FOR_TRIE);
	qp_trie_attach_prog(ctx.skel->progs.qp_trie_lookup);
}

static void htab_update_setup(void)
{
	qp_trie_setup(FOR_HTAB);
	qp_trie_attach_prog(ctx.skel->progs.htab_update);
}

static void qp_trie_update_setup(void)
{
	qp_trie_setup(FOR_TRIE);
	qp_trie_attach_prog(ctx.skel->progs.qp_trie_update);
}

static void *qp_trie_producer(void *ctx)
{
	while (true)
		(void)syscall(__NR_getpgid);
	return NULL;
}

static void *qp_trie_consumer(void *ctx)
{
	return NULL;
}

static void qp_trie_measure(struct bench_res *res)
{
	static __u64 last_hits, last_drops;
	__u64 total_hits = 0, total_drops = 0;
	unsigned int i, nr_cpus;

	nr_cpus = bpf_num_possible_cpus();
	for (i = 0; i < nr_cpus; i++) {
		struct run_stat *s = (void *)&ctx.skel->bss->percpu_stats[i & 255];

		total_hits += s->stats[0];
		total_drops += s->stats[1];
	}

	res->hits = total_hits - last_hits;
	res->drops = total_drops - last_drops;

	last_hits = total_hits;
	last_drops = total_drops;
}

static void qp_trie_report_final(struct bench_res res[], int res_cnt)
{
	close(ctx.cgrp_dfd);
	cleanup_cgroup_environment();

	fprintf(stdout, "Slab: %.3f MiB\n", (float)ctx.map_slab_mem / 1024 / 1024);
	hits_drops_report_final(res, res_cnt);
}

const struct bench bench_htab_lookup = {
	.name = "htab-lookup",
	.validate = qp_trie_validate,
	.setup = htab_lookup_setup,
	.producer_thread = qp_trie_producer,
	.consumer_thread = qp_trie_consumer,
	.measure = qp_trie_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = qp_trie_report_final,
};

const struct bench bench_qp_trie_lookup = {
	.name = "qp-trie-lookup",
	.validate = qp_trie_validate,
	.setup = qp_trie_lookup_setup,
	.producer_thread = qp_trie_producer,
	.consumer_thread = qp_trie_consumer,
	.measure = qp_trie_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = qp_trie_report_final,
};

const struct bench bench_htab_update = {
	.name = "htab-update",
	.validate = qp_trie_validate,
	.setup = htab_update_setup,
	.producer_thread = qp_trie_producer,
	.consumer_thread = qp_trie_consumer,
	.measure = qp_trie_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = qp_trie_report_final,
};

const struct bench bench_qp_trie_update = {
	.name = "qp-trie-update",
	.validate = qp_trie_validate,
	.setup = qp_trie_update_setup,
	.producer_thread = qp_trie_producer,
	.consumer_thread = qp_trie_consumer,
	.measure = qp_trie_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = qp_trie_report_final,
};
