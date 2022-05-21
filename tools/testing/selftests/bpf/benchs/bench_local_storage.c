// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <argp.h>
#include <linux/btf.h>

#include "local_storage_bench__get_int.skel.h"
#include "local_storage_bench__get_seq.skel.h"
#include "local_storage_bench__hashmap.skel.h"
#include "bench.h"

#include <test_btf.h>

static struct {
	__u32 nr_maps;
} args = {
	.nr_maps = 100,
};

enum {
	ARG_NR_MAPS = 6000,
};

static const struct argp_option opts[] = {
	{ "nr_maps", ARG_NR_MAPS, "NR_MAPS", 0,
		"Set number of local_storage maps"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long ret;

	switch (key) {
	case ARG_NR_MAPS:
		ret = strtol(arg, NULL, 10);
		if (ret < 1 || ret > UINT_MAX) {
			fprintf(stderr, "invalid nr_maps");
			argp_usage(state);
		}
		args.nr_maps = ret;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

const struct argp bench_local_storage_argp = {
	.options = opts,
	.parser = parse_arg,
};

static void validate(void)
{
	if (env.producer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-producer!\n");
		exit(1);
	}
	if (env.consumer_cnt != 1) {
		fprintf(stderr, "benchmark doesn't support multi-consumer!\n");
		exit(1);
	}

	if (args.nr_maps > 1000) {
		fprintf(stderr, "nr_maps must be <= 1000\n");
		exit(1);
	}
}

/* Keep in sync w/ array of maps in bpf */
#define MAX_NR_MAPS 1000

static struct {
	void (*destroy_skel)(void *obj);
	int (*load_skel)(void *obj);
	long *important_hits;
	long *hits;
	void *progs;
	void *skel;
	struct bpf_map *array_of_maps;
	struct bpf_link *attached_prog;
	int created_maps[MAX_NR_MAPS];
} ctx;

static void teardown(void)
{
	int i;

	bpf_link__detach(ctx.attached_prog);

	if (ctx.destroy_skel && ctx.skel)
		ctx.destroy_skel(ctx.skel);

	for (i = 0; i < MAX_NR_MAPS; i++) {
		if (!ctx.created_maps[i])
			break;
		close(ctx.created_maps[i]);
	}
}

static int setup_inner_map_and_load(int inner_fd)
{
	int err, mim_fd;

	err = bpf_map__set_inner_map_fd(ctx.array_of_maps, inner_fd);
	if (err)
		return -1;

	err = ctx.load_skel(ctx.skel);
	if (err)
		return -1;

	mim_fd = bpf_map__fd(ctx.array_of_maps);
	if (mim_fd < 0)
		return -1;

	return mim_fd;
}

static int load_btf(void)
{
	static const char btf_str_sec[] = "\0";
	__u32 btf_raw_types[] = {
		/* int */
		BTF_TYPE_INT_ENC(0, BTF_INT_SIGNED, 0, 32, 4),  /* [1] */
	};
	struct btf_header btf_hdr = {
		.magic = BTF_MAGIC,
		.version = BTF_VERSION,
		.hdr_len = sizeof(struct btf_header),
		.type_len = sizeof(btf_raw_types),
		.str_off = sizeof(btf_raw_types),
		.str_len = sizeof(btf_str_sec),
	};
	__u8 raw_btf[sizeof(struct btf_header) + sizeof(btf_raw_types) +
				sizeof(btf_str_sec)];

	memcpy(raw_btf, &btf_hdr, sizeof(btf_hdr));
	memcpy(raw_btf + sizeof(btf_hdr), btf_raw_types, sizeof(btf_raw_types));
	memcpy(raw_btf + sizeof(btf_hdr) + sizeof(btf_raw_types),
	       btf_str_sec, sizeof(btf_str_sec));

	return bpf_btf_load(raw_btf, sizeof(raw_btf), NULL);
}

static void __setup(struct bpf_program *prog, bool hashmap)
{
	int i, fd, mim_fd, err;
	int btf_fd = 0;

	LIBBPF_OPTS(bpf_map_create_opts, create_opts);

	memset(&ctx.created_maps, 0, MAX_NR_MAPS * sizeof(int));

	btf_fd = load_btf();
	create_opts.btf_fd = btf_fd;
	create_opts.btf_key_type_id = 1;
	create_opts.btf_value_type_id = 1;
	if (!hashmap)
		create_opts.map_flags = BPF_F_NO_PREALLOC;

	mim_fd = 0;
	for (i = 0; i < args.nr_maps; i++) {
		if (hashmap)
			fd = bpf_map_create(BPF_MAP_TYPE_HASH, NULL, sizeof(int),
					    sizeof(int), 65536, &create_opts);
		else
			fd = bpf_map_create(BPF_MAP_TYPE_TASK_STORAGE, NULL, sizeof(int),
					    sizeof(int), 0, &create_opts);
		if (fd < 0) {
			fprintf(stderr, "Error creating map %d\n", i);
			goto err_out;
		}

		if (i == 0) {
			mim_fd = setup_inner_map_and_load(fd);
			if (mim_fd < 0) {
				fprintf(stderr, "Error doing setup_inner_map_and_load\n");
				goto err_out;
			}
		}

		err = bpf_map_update_elem(mim_fd, &i, &fd, 0);
		if (err) {
			fprintf(stderr, "Error updating array-of-maps w/ map %d\n", i);
			goto err_out;
		}
		ctx.created_maps[i] = fd;
	}
	close(btf_fd);

	ctx.attached_prog = bpf_program__attach(prog);
	if (!ctx.attached_prog) {
		fprintf(stderr, "Error attaching bpf program\n");
		goto err_out;
	}

	return;
err_out:
	if (btf_fd)
		close(btf_fd);
	teardown();
	exit(1);
}

static void hashmap_setup(void)
{
	struct local_storage_bench__hashmap *skel;

	setup_libbpf();

	skel = local_storage_bench__hashmap__open();
	ctx.skel = skel;
	ctx.hits = &skel->bss->hits;
	ctx.important_hits = &skel->bss->important_hits;
	ctx.load_skel = (int (*)(void *))local_storage_bench__hashmap__load;
	ctx.progs = (void *)&skel->progs;
	ctx.destroy_skel = (void (*)(void *))local_storage_bench__hashmap__destroy;
	ctx.array_of_maps = skel->maps.array_of_maps;

	__setup(skel->progs.get_local, true);
}

static void local_storage_cache_get_setup(void)
{
	struct local_storage_bench__get_seq *skel;

	setup_libbpf();

	skel = local_storage_bench__get_seq__open();
	ctx.skel = skel;
	ctx.hits = &skel->bss->hits;
	ctx.important_hits = &skel->bss->important_hits;
	ctx.load_skel = (int (*)(void *))local_storage_bench__get_seq__load;
	ctx.progs = (void *)&skel->progs;
	ctx.destroy_skel = (void (*)(void *))local_storage_bench__get_seq__destroy;
	ctx.array_of_maps = skel->maps.array_of_maps;

	__setup(skel->progs.get_local, false);
}

static void local_storage_cache_get_interleaved_setup(void)
{
	struct local_storage_bench__get_int *skel;

	setup_libbpf();

	skel = local_storage_bench__get_int__open();
	ctx.skel = skel;
	ctx.hits = &skel->bss->hits;
	ctx.important_hits = &skel->bss->important_hits;
	ctx.load_skel = (int (*)(void *))local_storage_bench__get_int__load;
	ctx.progs = (void *)&skel->progs;
	ctx.destroy_skel = (void (*)(void *))local_storage_bench__get_int__destroy;
	ctx.array_of_maps = skel->maps.array_of_maps;

	__setup(skel->progs.get_local, false);
}

static void measure(struct bench_res *res)
{
	if (ctx.hits)
		res->hits = atomic_swap(ctx.hits, 0);
	if (ctx.important_hits)
		res->important_hits = atomic_swap(ctx.important_hits, 0);
}

static inline void trigger_bpf_program(void)
{
	syscall(__NR_getpgid);
}

static void *consumer(void *input)
{
	return NULL;
}

static void *producer(void *input)
{
	while (true)
		trigger_bpf_program();

	return NULL;
}

/* cache sequential and interleaved get benchs test local_storage get
 * performance, specifically they demonstrate performance cliff of
 * current list-plus-cache local_storage model.
 *
 * cache sequential get: call bpf_task_storage_get on n maps in order
 * cache interleaved get: like "sequential get", but interleave 4 calls to the
 *	'important' map (idx 0 in array_of_maps) for every 10 calls. Goal
 *	is to mimic environment where many progs are accessing their local_storage
 *	maps, with 'our' prog needing to access its map more often than others
 */
const struct bench bench_local_storage_cache_seq_get = {
	.name = "local-storage-cache-seq-get",
	.validate = validate,
	.setup = local_storage_cache_get_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = local_storage_report_progress,
	.report_final = local_storage_report_final,
	.teardown = teardown,
};

const struct bench bench_local_storage_cache_interleaved_get = {
	.name = "local-storage-cache-int-get",
	.validate = validate,
	.setup = local_storage_cache_get_interleaved_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = local_storage_report_progress,
	.report_final = local_storage_report_final,
	.teardown = teardown,
};

const struct bench bench_local_storage_cache_hashmap_control = {
	.name = "local-storage-cache-hashmap-control",
	.validate = validate,
	.setup = hashmap_setup,
	.producer_thread = producer,
	.consumer_thread = consumer,
	.measure = measure,
	.report_progress = local_storage_report_progress,
	.report_final = local_storage_report_final,
	.teardown = teardown,
};
