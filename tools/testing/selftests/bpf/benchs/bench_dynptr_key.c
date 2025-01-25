// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2025. Huawei Technologies Co., Ltd */
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "bench.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"

#include "dynptr_key_bench.skel.h"

enum {
	NORM_HTAB = 0,
	DYNPTR_KEY_HTAB,
};

static struct dynptr_key_ctx {
	struct dynptr_key_bench *skel;
	int cgrp_dfd;
	u64 map_slab_mem;
} ctx;

static struct {
	const char *file;
	__u32 entries;
	__u32 max_size;
} args = {
	.max_size = 256,
};

struct run_stat {
	__u64 stats[2];
};

struct dynkey_key {
	/* prevent unnecessary hole */
	__u64 cookie;
	struct bpf_dynptr_user desc;
};

struct var_size_str {
	/* the same size as cookie */
	__u64 len;
	unsigned char data[];
};

enum {
	ARG_DATA_FILE = 11001,
	ARG_DATA_ENTRIES = 11002,
	ARG_MAX_SIZE = 11003,
};

static const struct argp_option opts[] = {
	{ "file", ARG_DATA_FILE, "DATA-FILE", 0, "Set data file" },
	{ "entries", ARG_DATA_ENTRIES, "DATA-ENTRIES", 0, "Set data entries" },
	{ "max_size", ARG_MAX_SIZE, "MAX-SIZE", 0, "Set data max size" },
	{},
};

static error_t dynptr_key_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_DATA_FILE:
		args.file = strdup(arg);
		if (!args.file) {
			fprintf(stderr, "no mem for file name\n");
			argp_usage(state);
		}
		break;
	case ARG_DATA_ENTRIES:
		args.entries = strtoul(arg, NULL, 10);
		break;
	case ARG_MAX_SIZE:
		args.max_size = strtoul(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_dynptr_key_argp = {
	.options = opts,
	.parser = dynptr_key_parse_arg,
};

static int count_nr_item(const char *name, char *buf, size_t size, unsigned int *nr_items)
{
	unsigned int i = 0;
	FILE *file;
	int err;

	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "open %s err %s\n", name, strerror(errno));
		return -1;
	}

	err = 0;
	while (true) {
		unsigned int len;
		char *got;

		got = fgets(buf, size, file);
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
		if (!len)
			continue;
		i++;
	}
	fclose(file);

	if (!err)
		*nr_items = i;

	return err;
}

static int parse_data_set(const char *name, struct var_size_str ***set, unsigned int *nr,
			  unsigned int *max_len)
{
#define FILE_DATA_MAX_SIZE 4095
	unsigned int i, nr_items, item_max_len;
	char line[FILE_DATA_MAX_SIZE + 1];
	struct var_size_str **items;
	struct var_size_str *cur;
	int err = 0;
	FILE *file;
	char *got;

	if (count_nr_item(name, line, sizeof(line), &nr_items))
		return -1;
	if (!nr_items) {
		fprintf(stderr, "empty file ?\n");
		return -1;
	}
	fprintf(stdout, "%u items in %s\n", nr_items, name);

	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "open %s err %s\n", name, strerror(errno));
		return -1;
	}

	items = (struct var_size_str **)calloc(nr_items, sizeof(*items) + FILE_DATA_MAX_SIZE);
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
		if (!len)
			continue;

		if (i >= nr_items) {
			fprintf(stderr, "too many line in %s\n", name);
			break;
		}

		if (len > item_max_len)
			item_max_len = len;
		cur->len = len;
		memcpy(cur->data, got, len);
		items[i++] = cur;
		cur = (void *)cur + FILE_DATA_MAX_SIZE;
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

static int gen_data_set(unsigned int max_size, struct var_size_str ***set, unsigned int *nr,
			unsigned int *max_len)
{
#define GEN_DATA_MAX_SIZE 4088
	struct var_size_str **items;
	size_t ptr_size, data_size;
	struct var_size_str *cur;
	unsigned int i, nr_items;
	size_t left;
	ssize_t got;
	int err = 0;
	void *dst;

	ptr_size = *nr * sizeof(*items);
	data_size = *nr * (sizeof(*cur) + max_size);
	items = (struct var_size_str **)malloc(ptr_size + data_size);
	if (!items) {
		fprintf(stderr, "no mem for items\n");
		err = -1;
		goto out;
	}

	cur = (void *)items + ptr_size;
	dst = cur;
	left = data_size;
	while (left > 0) {
		got = syscall(__NR_getrandom, dst, left, 0);
		if (got <= 0) {
			fprintf(stderr, "getrandom error %s got %zd\n", strerror(errno), got);
			err = -1;
			goto out;
		}
		left -= got;
		dst += got;
	}

	nr_items = 0;
	for (i = 0; i < *nr; i++) {
		cur->len &= (max_size - 1);
		cur->len += 1;
		if (cur->len > GEN_DATA_MAX_SIZE)
			cur->len = GEN_DATA_MAX_SIZE;
		items[nr_items++] = cur;
		memset(cur->data + cur->len, 0, max_size - cur->len);
		cur = (void *)cur + (sizeof(*cur) + max_size);
	}
	if (!nr_items) {
		fprintf(stderr, "no valid key in random data\n");
		err = -1;
		goto out;
	}
	fprintf(stdout, "generate %u random keys\n", nr_items);

	*nr = nr_items;
	*set = items;
	*max_len = max_size <= GEN_DATA_MAX_SIZE ? max_size : GEN_DATA_MAX_SIZE;
out:
	if (err && items)
		free(items);
	return err;
}

static inline bool is_pow_of_2(size_t x)
{
	return x && (x & (x - 1)) == 0;
}

static void dynptr_key_validate(void)
{
	if (env.consumer_cnt != 0) {
		fprintf(stderr, "dynptr_key benchmark doesn't support consumer!\n");
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

	if (args.entries && !is_pow_of_2(args.max_size)) {
		fprintf(stderr, "invalid max size %u (should be power-of-two)\n", args.max_size);
		exit(1);
	}
}

static void dynptr_key_init_map_opts(struct dynptr_key_bench *skel, unsigned int data_size,
				     unsigned int nr)
{
	/* The value will be used as the key for hash map */
	bpf_map__set_value_size(skel->maps.array,
				offsetof(struct dynkey_key, desc) + data_size);
	bpf_map__set_max_entries(skel->maps.array, nr);

	bpf_map__set_key_size(skel->maps.htab, offsetof(struct dynkey_key, desc) + data_size);
	bpf_map__set_max_entries(skel->maps.htab, nr);

	bpf_map__set_map_extra(skel->maps.dynkey_htab, data_size);
	bpf_map__set_max_entries(skel->maps.dynkey_htab, nr);
}

static void dynptr_key_setup_key_map(struct bpf_map *map, struct var_size_str **set,
				     unsigned int nr)
{
	int fd = bpf_map__fd(map);
	unsigned int i;

	for (i = 0; i < nr; i++) {
		void *value;
		int err;

		value = (void *)set[i];
		err = bpf_map_update_elem(fd, &i, value, 0);
		if (err) {
			fprintf(stderr, "add #%u key (%s) on %s error %d\n",
				i, set[i]->data, bpf_map__name(map), err);
			exit(1);
		}
	}
}

static u64 dynptr_key_get_slab_mem(int dfd)
{
	const char *magic = "slab ";
	const char *name = "memory.stat";
	int fd;
	ssize_t nr;
	char buf[4096];
	char *from;

	fd = openat(dfd, name, 0);
	if (fd < 0) {
		fprintf(stdout, "no %s (cgroup v1 ?)\n", name);
		return 0;
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

static void dynptr_key_setup_lookup_map(struct bpf_map *map, unsigned int map_type,
					struct var_size_str **set, unsigned int nr)
{
	int fd = bpf_map__fd(map);
	unsigned int i;

	for (i = 0; i < nr; i++) {
		struct dynkey_key dynkey;
		void *key;
		int err;

		if (map_type == NORM_HTAB) {
			key = set[i];
		} else {
			dynkey.cookie = set[i]->len;
			bpf_dynptr_user_init(set[i]->data, set[i]->len, &dynkey.desc);
			key = &dynkey;
		}
		/* May have duplicated keys */
		err = bpf_map_update_elem(fd, key, &i, 0);
		if (err) {
			fprintf(stderr, "add #%u key (%s) on %s error %d\n",
				i, set[i]->data, bpf_map__name(map), err);
			exit(1);
		}
	}
}

static void dump_data_set_metric(struct var_size_str **set, unsigned int nr)
{
	double mean = 0.0, stddev = 0.0;
	unsigned int max = 0;
	unsigned int i;

	for (i = 0; i < nr; i++) {
		if (set[i]->len > max)
			max = set[i]->len;
		mean += set[i]->len / (0.0 + nr);
	}

	if (nr > 1)  {
		for (i = 0; i < nr; i++)
			stddev += (mean - set[i]->len) * (mean - set[i]->len) / (nr - 1.0);
		stddev = sqrt(stddev);
	}

	fprintf(stdout, "str length: max %u mean %.0f stdev %.0f\n", max, mean, stddev);
}

static void dynptr_key_setup(unsigned int map_type, const char *prog_name)
{
	struct var_size_str **set = NULL;
	struct dynptr_key_bench *skel;
	unsigned int nr = 0, max_len = 0;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct bpf_map *map;
	u64 before, after;
	int dfd;
	int err;

	if (!args.file) {
		nr = args.entries;
		err = gen_data_set(args.max_size, &set, &nr, &max_len);
	} else {
		err = parse_data_set(args.file, &set, &nr, &max_len);
	}
	if (err < 0)
		exit(1);

	if (args.entries && args.entries < nr)
		nr = args.entries;

	dump_data_set_metric(set, nr);

	dfd = cgroup_setup_and_join("/dynptr_key");
	if (dfd < 0) {
		fprintf(stderr, "failed to setup cgroup env\n");
		goto free_str_set;
	}

	setup_libbpf();

	before = dynptr_key_get_slab_mem(dfd);

	skel = dynptr_key_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		goto leave_cgroup;
	}

	dynptr_key_init_map_opts(skel, max_len, nr);

	skel->rodata->max_dynkey_size = max_len;
	skel->bss->update_nr = nr;
	skel->bss->update_chunk = nr / env.producer_cnt;

	prog = bpf_object__find_program_by_name(skel->obj, prog_name);
	if (!prog) {
		fprintf(stderr, "no such prog %s\n", prog_name);
		goto destroy_skel;
	}
	bpf_program__set_autoload(prog, true);

	err = dynptr_key_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		goto destroy_skel;
	}

	dynptr_key_setup_key_map(skel->maps.array, set, nr);

	map = (map_type == NORM_HTAB) ? skel->maps.htab : skel->maps.dynkey_htab;
	dynptr_key_setup_lookup_map(map, map_type, set, nr);

	after = dynptr_key_get_slab_mem(dfd);

	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "failed to attach %s\n", prog_name);
		goto destroy_skel;
	}

	ctx.skel = skel;
	ctx.cgrp_dfd = dfd;
	ctx.map_slab_mem = after - before;
	free(set);
	return;

destroy_skel:
	dynptr_key_bench__destroy(skel);
leave_cgroup:
	close(dfd);
	cleanup_cgroup_environment();
free_str_set:
	free(set);
	exit(1);
}

static void dynkey_htab_lookup_setup(void)
{
	dynptr_key_setup(DYNPTR_KEY_HTAB, "dynkey_htab_lookup");
}

static void norm_htab_lookup_setup(void)
{
	dynptr_key_setup(NORM_HTAB, "htab_lookup");
}

static void dynkey_htab_update_setup(void)
{
	dynptr_key_setup(DYNPTR_KEY_HTAB, "dynkey_htab_update");
}

static void norm_htab_update_setup(void)
{
	dynptr_key_setup(NORM_HTAB, "htab_update");
}

static void *dynptr_key_producer(void *ctx)
{
	while (true)
		(void)syscall(__NR_getpgid);
	return NULL;
}

static void dynptr_key_measure(struct bench_res *res)
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

static void dynptr_key_report_final(struct bench_res res[], int res_cnt)
{
	close(ctx.cgrp_dfd);
	cleanup_cgroup_environment();

	fprintf(stdout, "Slab: %.3f MiB\n", (float)ctx.map_slab_mem / 1024 / 1024);
	hits_drops_report_final(res, res_cnt);
}

const struct bench bench_dynkey_htab_lookup = {
	.name = "dynkey-htab-lookup",
	.argp = &bench_dynptr_key_argp,
	.validate = dynptr_key_validate,
	.setup = dynkey_htab_lookup_setup,
	.producer_thread = dynptr_key_producer,
	.measure = dynptr_key_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = dynptr_key_report_final,
};

const struct bench bench_norm_htab_lookup = {
	.name = "norm-htab-lookup",
	.argp = &bench_dynptr_key_argp,
	.validate = dynptr_key_validate,
	.setup = norm_htab_lookup_setup,
	.producer_thread = dynptr_key_producer,
	.measure = dynptr_key_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = dynptr_key_report_final,
};

const struct bench bench_dynkey_htab_update = {
	.name = "dynkey-htab-update",
	.argp = &bench_dynptr_key_argp,
	.validate = dynptr_key_validate,
	.setup = dynkey_htab_update_setup,
	.producer_thread = dynptr_key_producer,
	.measure = dynptr_key_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = dynptr_key_report_final,
};

const struct bench bench_norm_htab_update = {
	.name = "norm-htab-update",
	.argp = &bench_dynptr_key_argp,
	.validate = dynptr_key_validate,
	.setup = norm_htab_update_setup,
	.producer_thread = dynptr_key_producer,
	.measure = dynptr_key_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = dynptr_key_report_final,
};
