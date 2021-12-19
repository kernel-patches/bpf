// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021. Huawei Technologies Co., Ltd */
#include <argp.h>
#include <sys/random.h>
#include "bench.h"
#include "bpf_util.h"
#include "str_htab_bench.skel.h"

static struct str_htab_ctx {
	struct str_htab_bench *skel;
} ctx;

static struct {
	bool same_len;
	__u32 key_size;
	__u32 max_entries;
} args = {
	.same_len = false,
	.key_size = 256,
	.max_entries = 1000,
};

enum {
	ARG_SAME_LEN = 6000,
	ARG_KEY_SIZE = 6001,
	ARG_MAX_ENTRIES = 6002,
};

static const struct argp_option opts[] = {
	{ "same-len", ARG_SAME_LEN, NULL, 0,
	  "Use the same length for string keys" },
	{ "key-size", ARG_KEY_SIZE, "KEY_SIZE", 0,
	  "Set the key size" },
	{ "max-entries", ARG_MAX_ENTRIES, "MAX_ENTRIES", 0,
	  "Set the max entries" },
	{},
};

static error_t str_htab_parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case ARG_SAME_LEN:
		args.same_len = true;
		break;
	case ARG_KEY_SIZE:
		args.key_size = strtoul(arg, NULL, 10);
		break;
	case ARG_MAX_ENTRIES:
		args.max_entries = strtoul(arg, NULL, 10);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_str_htab_argp = {
	.options = opts,
	.parser = str_htab_parse_arg,
};

static void str_htab_validate(void)
{
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "str_htab benchmark doesn't support multi-consumer!\n");
		exit(1);
	}

	if (args.key_size < 2 ||
	    args.key_size > sizeof(ctx.skel->rodata->keys[0])) {
		fprintf(stderr, "invalid key size (max %zu)\n",
			sizeof(ctx.skel->rodata->keys[0]));
		exit(1);
	}

	if (!args.max_entries ||
	    args.max_entries > ARRAY_SIZE(ctx.skel->rodata->keys)) {
		fprintf(stderr, "invalid max entries (max %zu)\n",
			ARRAY_SIZE(ctx.skel->rodata->keys));
		exit(1);
	}
}

static void str_htab_fill_map(struct str_htab_bench *skel, struct bpf_map *map,
			      unsigned int nr)
{
	int fd = bpf_map__fd(map);
	unsigned int value = 1;
	unsigned int i = 0;

	for (; i < nr; i++) {
		int err;

		err = bpf_map_update_elem(fd, skel->rodata->keys[i], &value, 0);
		if (err) {
			fprintf(stderr, "add #%u key on %s error %d\n",
				i, bpf_map__name(map), err);
			exit(1);
		}
	}
}

static void setup_keys(struct str_htab_bench *skel, u32 key_size)
{
	size_t i;

	/* Generate in byte-granularity to avoid zero byte */
	srandom(time(NULL));
	for (i = 0; i < ARRAY_SIZE(skel->rodata->keys); i++) {
		unsigned int len;
		unsigned int j;

		if (args.same_len)
			len = key_size - 1;
		else
			len = random() % (key_size - 1) + 1;
		for (j = 0; j < len; j++)
			skel->rodata->keys[i][j] = random() % 255 + 1;
		skel->rodata->keys[i][j] = 0;
	}
}

static void str_htab_setup(void)
{
	struct str_htab_bench *skel;
	int err;

	setup_libbpf();

	skel = str_htab_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	setup_keys(skel, args.key_size);

	bpf_map__set_key_size(skel->maps.bytes_htab, args.key_size);
	bpf_map__set_key_size(skel->maps.str_htab, args.key_size);

	bpf_map__set_max_entries(skel->maps.bytes_htab, args.max_entries);
	bpf_map__set_max_entries(skel->maps.str_htab, args.max_entries);

	skel->bss->loops = args.max_entries;

	err = str_htab_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		str_htab_bench__destroy(skel);
		exit(1);
	}

	str_htab_fill_map(skel, skel->maps.bytes_htab, args.max_entries);
	str_htab_fill_map(skel, skel->maps.str_htab, args.max_entries);

	ctx.skel = skel;
}

static void str_htab_attach_prog(struct bpf_program *prog)
{
	struct bpf_link *link;

	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "failed to attach program!\n");
		exit(1);
	}
}

static void str_htab_bytes_lookup_setup(void)
{
	str_htab_setup();
	str_htab_attach_prog(ctx.skel->progs.htab_bytes_lookup);
}

static void str_htab_str_lookup_setup(void)
{
	str_htab_setup();
	str_htab_attach_prog(ctx.skel->progs.htab_str_lookup);
}

static void str_htab_bytes_update_setup(void)
{
	str_htab_setup();
	str_htab_attach_prog(ctx.skel->progs.htab_bytes_update);
}

static void str_htab_str_update_setup(void)
{
	str_htab_setup();
	str_htab_attach_prog(ctx.skel->progs.htab_str_update);
}

static void *str_htab_producer(void *ctx)
{
	while (true)
		(void)syscall(__NR_getpgid);
	return NULL;
}

static void *str_htab_consumer(void *ctx)
{
	return NULL;
}

static void str_htab_measure(struct bench_res *res)
{
	res->hits = atomic_swap(&ctx.skel->bss->hits, 0);
	res->drops = atomic_swap(&ctx.skel->bss->drops, 0);
}

const struct bench bench_htab_bytes_lookup = {
	.name = "htab-bytes-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_bytes_lookup_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_htab_str_lookup = {
	.name = "htab-str-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_str_lookup_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_htab_bytes_update = {
	.name = "htab-bytes-update",
	.validate = str_htab_validate,
	.setup = str_htab_bytes_update_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_htab_str_update = {
	.name = "htab-str-update",
	.validate = str_htab_validate,
	.setup = str_htab_str_update_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
