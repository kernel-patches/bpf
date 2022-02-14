// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2022. Huawei Technologies Co., Ltd */
#include <argp.h>
#include "bench.h"
#include "bpf_util.h"

#define DFT_STR_KEY_SIZE 252

struct htab_byte_key {
	char name[DFT_STR_KEY_SIZE];
};

struct htab_str_key {
	struct bpf_str_key_stor name;
	char raw[DFT_STR_KEY_SIZE];
};

struct htab_int_byte_key {
        int cookie;
        char name[DFT_STR_KEY_SIZE];
};

struct htab_int_str_key {
        int cookie;
        struct bpf_str_key_stor name;
        char raw[DFT_STR_KEY_SIZE];
};

struct htab_int_bytes_key {
        int cookie;
        char name[DFT_STR_KEY_SIZE / 2];
        char addr[DFT_STR_KEY_SIZE / 2];
};

struct htab_int_strs_key {
        int cookie;
        struct bpf_str_key_desc name;
        struct bpf_str_key_desc addr;
        struct bpf_str_key_stor stor;
        char raw[DFT_STR_KEY_SIZE];
};

#include "str_htab_bench.skel.h"

typedef void *(*get_nth_key)(struct str_htab_bench *skel, unsigned int i);
typedef void (*set_key)(void *key);

static const char strs[] =
"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[]^_`{|}~ ";

static struct str_htab_ctx {
	struct str_htab_bench *skel;
} ctx;

static struct {
	bool same_len;
	__u32 max_entries;
} args = {
	.same_len = false,
	.max_entries = 1000,
};

enum {
	ARG_SAME_LEN = 6000,
	ARG_MAX_ENTRIES = 6001,
};

static const struct argp_option opts[] = {
	{ "same-len", ARG_SAME_LEN, NULL, 0,
	  "Use the same length for string keys" },
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

	if (!args.max_entries ||
	    args.max_entries > ARRAY_SIZE(ctx.skel->bss->byte_keys)) {
		fprintf(stderr, "invalid max entries (max %zu)\n",
			ARRAY_SIZE(ctx.skel->bss->byte_keys));
		exit(1);
	}
}

static void setup_max_entries(struct str_htab_bench *skel, unsigned int nr)
{
	bpf_map__set_max_entries(skel->maps.byte_htab, nr);
	bpf_map__set_max_entries(skel->maps.str_htab, nr);
	bpf_map__set_max_entries(skel->maps.int_byte_htab, nr);
	bpf_map__set_max_entries(skel->maps.int_str_htab, nr);
	bpf_map__set_max_entries(skel->maps.int_bytes_htab, nr);
	bpf_map__set_max_entries(skel->maps.int_strs_htab, nr);
}

static void random_fill_str(char *str, unsigned int max_sz, unsigned int *sz)
{
	unsigned int len;
	unsigned int i;

	if (args.same_len)
		len = max_sz - 1;
	else
		len = random() % (max_sz - 1) + 1;
	if (sz)
		*sz = len + 1;

	/* Generate in byte-granularity to avoid zero byte */
	for (i = 0; i < len; i++)
		str[i] = strs[random() % (sizeof(strs) - 1)];
	str[i] = 0;
}

static void setup_keys(struct str_htab_bench *skel, get_nth_key getter, set_key setter)
{
	unsigned int i;

	for (i = 0; i < args.max_entries; i++) {
		void *key = getter(skel, i);

		setter(key);
	}
}

static void setup_htab(struct str_htab_bench *skel, struct bpf_map *map,
		       get_nth_key getter)
{
	int fd = bpf_map__fd(map);
	unsigned int value;
	unsigned int i;
	void *key;

	for (i = 0; i < args.max_entries; i++) {
		int err;

		key = getter(skel, i);
		value = i;
		err = bpf_map_update_elem(fd, key, &value, 0);
		if (err) {
			fprintf(stderr, "add #%u key on %s error %d\n",
				i, bpf_map__name(map), err);
			exit(1);
		}
	}
}

static void *byte_get_nth_key(struct str_htab_bench *skel, unsigned int i)
{
	return &skel->bss->byte_keys[i];
}

static void byte_set_key(void *key)
{
	struct htab_byte_key *cur = key;

	random_fill_str(cur->name, sizeof(cur->name), NULL);
}

static void *int_byte_get_nth_key(struct str_htab_bench *skel, unsigned int i)
{
	return &skel->bss->int_byte_keys[i];
}

static void int_byte_set_key(void *key)
{
	struct htab_int_byte_key *cur = key;

	cur->cookie = random();
	random_fill_str(cur->name, sizeof(cur->name), NULL);
}

static void *int_bytes_get_nth_key(struct str_htab_bench *skel, unsigned int i)
{
	return &skel->bss->int_bytes_keys[i];
}

static void int_bytes_set_key(void *key)
{
	struct htab_int_bytes_key *cur = key;

	cur->cookie = random();
	random_fill_str(cur->name, sizeof(cur->name), NULL);
	random_fill_str(cur->addr, sizeof(cur->addr), NULL);
}

static void *str_get_nth_key(struct str_htab_bench *skel, unsigned int i)
{
	return &skel->bss->str_keys[i];
}

static void str_set_key(void *key)
{
	struct htab_str_key *cur = key;

	cur->name.hash = 0;
	random_fill_str(cur->raw, sizeof(cur->raw), &cur->name.len);
}

static void *int_str_get_nth_key(struct str_htab_bench *skel, unsigned int i)
{
	return &skel->bss->int_str_keys[i];
}

static void int_str_set_key(void *key)
{
	struct htab_int_str_key *cur = key;

	cur->cookie = random();
	cur->name.hash = 0;
	random_fill_str(cur->raw, sizeof(cur->raw), &cur->name.len);
}

static void *int_strs_get_nth_key(struct str_htab_bench *skel, unsigned int i)
{
	return &skel->bss->int_strs_keys[i];
}

static void int_strs_set_key(void *key)
{
	struct htab_int_strs_key *cur = key;
	unsigned int max_sz = sizeof(cur->raw) / 2;

	cur->cookie = random();

	cur->name.offset = cur->raw - (char *)&cur->name;
	random_fill_str(cur->raw, max_sz, &cur->name.len);

	cur->addr.offset = cur->raw + cur->name.len - (char *)&cur->addr;
	random_fill_str(cur->raw + cur->name.len, max_sz, &cur->addr.len);

	cur->stor.hash = 0;
	cur->stor.len = cur->name.len + cur->addr.len;
}

static void str_htab_common_setup(void)
{
	struct str_htab_bench *skel;
	int err;

	srandom(time(NULL));

	setup_libbpf();

	skel = str_htab_bench__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		exit(1);
	}

	setup_max_entries(skel, args.max_entries);

	skel->bss->loops = args.max_entries;

	err = str_htab_bench__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton\n");
		str_htab_bench__destroy(skel);
		exit(1);
	}

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

static void str_htab_byte_lookup_setup(void)
{
	str_htab_common_setup();

	setup_keys(ctx.skel, byte_get_nth_key, byte_set_key);
	setup_htab(ctx.skel, ctx.skel->maps.byte_htab, byte_get_nth_key);

	ctx.skel->bss->key_type = 0;
	str_htab_attach_prog(ctx.skel->progs.htab_byte_lookup);
}

static void str_htab_int_byte_lookup_setup(void)
{
	str_htab_common_setup();

	setup_keys(ctx.skel, int_byte_get_nth_key, int_byte_set_key);
	setup_htab(ctx.skel, ctx.skel->maps.int_byte_htab, int_byte_get_nth_key);

	ctx.skel->bss->key_type = 1;
	str_htab_attach_prog(ctx.skel->progs.htab_byte_lookup);
}

static void str_htab_int_bytes_lookup_setup(void)
{
	str_htab_common_setup();

	setup_keys(ctx.skel, int_bytes_get_nth_key, int_bytes_set_key);
	setup_htab(ctx.skel, ctx.skel->maps.int_bytes_htab, int_bytes_get_nth_key);

	ctx.skel->bss->key_type = 2;
	str_htab_attach_prog(ctx.skel->progs.htab_byte_lookup);
}

static void str_htab_str_lookup_setup(void)
{
	str_htab_common_setup();

	setup_keys(ctx.skel, str_get_nth_key, str_set_key);
	setup_htab(ctx.skel, ctx.skel->maps.str_htab, str_get_nth_key);

	ctx.skel->bss->key_type = 0;
	str_htab_attach_prog(ctx.skel->progs.htab_str_lookup);
}

static void str_htab_int_str_lookup_setup(void)
{
	str_htab_common_setup();

	setup_keys(ctx.skel, int_str_get_nth_key, int_str_set_key);
	setup_htab(ctx.skel, ctx.skel->maps.int_str_htab, int_str_get_nth_key);

	ctx.skel->bss->key_type = 1;
	str_htab_attach_prog(ctx.skel->progs.htab_str_lookup);
}

static void str_htab_int_strs_lookup_setup(void)
{
	str_htab_common_setup();

	setup_keys(ctx.skel, int_strs_get_nth_key, int_strs_set_key);
	setup_htab(ctx.skel, ctx.skel->maps.int_strs_htab, int_strs_get_nth_key);

	ctx.skel->bss->key_type = 2;
	str_htab_attach_prog(ctx.skel->progs.htab_str_lookup);
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

const struct bench bench_htab_byte_lookup = {
	.name = "htab-byte-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_byte_lookup_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_htab_int_byte_lookup = {
	.name = "htab-int-byte-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_int_byte_lookup_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_htab_int_bytes_lookup = {
	.name = "htab-int-bytes-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_int_bytes_lookup_setup,
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

const struct bench bench_htab_int_str_lookup = {
	.name = "htab-int-str-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_int_str_lookup_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};

const struct bench bench_htab_int_strs_lookup = {
	.name = "htab-int-strs-lookup",
	.validate = str_htab_validate,
	.setup = str_htab_int_strs_lookup_setup,
	.producer_thread = str_htab_producer,
	.consumer_thread = str_htab_consumer,
	.measure = str_htab_measure,
	.report_progress = hits_drops_report_progress,
	.report_final = hits_drops_report_final,
};
