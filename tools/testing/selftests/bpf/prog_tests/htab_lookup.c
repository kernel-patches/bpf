// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdbool.h>
#include <test_progs.h>
#include "htab_lookup.skel.h"

struct htab_op_ctx {
	int fd;
	int loop;
	unsigned int entries;
	bool stop;
};

static void *htab_lookup_fn(void *arg)
{
	struct htab_op_ctx *ctx = arg;
	int i = 0;

	while (i++ < ctx->loop && !ctx->stop) {
		unsigned int j;

		for (j = 0; j < ctx->entries; j++) {
			unsigned long key = j, value;
			int err;

			err = bpf_map_lookup_elem(ctx->fd, &key, &value);
			if (err) {
				ctx->stop = true;
				return (void *)(long)err;
			}
		}
	}

	return NULL;
}

static void *htab_update_fn(void *arg)
{
	struct htab_op_ctx *ctx = arg;
	int i = 0;

	while (i++ < ctx->loop && !ctx->stop) {
		unsigned int j;

		for (j = 0; j < ctx->entries; j++) {
			unsigned long key = j, value = j;
			int err;

			err = bpf_map_update_elem(ctx->fd, &key, &value, BPF_EXIST);
			if (err) {
				if (err == -ENOMEM)
					continue;
				ctx->stop = true;
				return (void *)(long)err;
			}
		}
	}

	return NULL;
}

static int setup_htab(int fd, unsigned int entries)
{
	unsigned int i;

	for (i = 0; i < entries; i++) {
		unsigned long key = i, value = i;
		int err;

		err = bpf_map_update_elem(fd, &key, &value, 0);
		if (!ASSERT_OK(err, "init update"))
			return -1;
	}

	return 0;
}

void test_htab_lookup(void)
{
	unsigned int i, wr_nr = 2, rd_nr = 8;
	pthread_t tids[wr_nr + rd_nr];
	struct htab_lookup *skel;
	struct htab_op_ctx ctx;
	int err;

	skel = htab_lookup__open_and_load();
	if (!ASSERT_OK_PTR(skel, "htab_lookup__open_and_load"))
		return;

	ctx.fd = bpf_map__fd(skel->maps.htab);
	ctx.loop = 50;
	ctx.stop = false;
	ctx.entries = 64;

	err = setup_htab(ctx.fd, ctx.entries);
	if (err)
		goto destroy;

	memset(tids, 0, sizeof(tids));
	for (i = 0; i < wr_nr; i++) {
		err = pthread_create(&tids[i], NULL, htab_update_fn, &ctx);
		if (!ASSERT_OK(err, "pthread_create")) {
			ctx.stop = true;
			goto reap;
		}
	}
	for (i = 0; i < rd_nr; i++) {
		err = pthread_create(&tids[i + wr_nr], NULL, htab_lookup_fn, &ctx);
		if (!ASSERT_OK(err, "pthread_create")) {
			ctx.stop = true;
			goto reap;
		}
	}

reap:
	for (i = 0; i < wr_nr + rd_nr; i++) {
		void *ret = NULL;
		char desc[32];

		if (!tids[i])
			continue;

		snprintf(desc, sizeof(desc), "thread %u", i + 1);
		err = pthread_join(tids[i], &ret);
		ASSERT_OK(err, desc);
		ASSERT_EQ(ret, NULL, desc);
	}
destroy:
	htab_lookup__destroy(skel);
}
