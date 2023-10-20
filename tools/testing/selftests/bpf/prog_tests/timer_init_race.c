// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include "timer_init_race.skel.h"

struct thread_ctx {
	struct bpf_map_create_opts opts;
	pthread_barrier_t barrier;
	int outer_map_fd;
	int start, abort;
	int loop, err;
};

static int wait_for_start_or_abort(struct thread_ctx *ctx)
{
	while (!ctx->start && !ctx->abort)
		usleep(1);
	return ctx->abort ? -1 : 0;
}

static void *close_map_fn(void *data)
{
	struct thread_ctx *ctx = data;
	int loop = ctx->loop, err = 0;

	if (wait_for_start_or_abort(ctx) < 0)
		return NULL;

	while (loop-- > 0) {
		int fd, zero = 0, i;
		volatile int s = 0;

		fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, NULL, 4, sizeof(struct bpf_timer),
				    1, &ctx->opts);
		if (fd < 0) {
			err |= 1;
			pthread_barrier_wait(&ctx->barrier);
			continue;
		}

		if (bpf_map_update_elem(ctx->outer_map_fd, &zero, &fd, 0) < 0)
			err |= 2;

		pthread_barrier_wait(&ctx->barrier);
		/* let bpf_timer_init run first */
		for (i = 0; i < 5000; i++)
			s++;
		close(fd);
	}

	ctx->err = err;

	return NULL;
}

static void *init_timer_fn(void *data)
{
	struct thread_ctx *ctx = data;
	int loop = ctx->loop;

	if (wait_for_start_or_abort(ctx) < 0)
		return NULL;

	while (loop-- > 0) {
		pthread_barrier_wait(&ctx->barrier);
		syscall(SYS_getpgid);
	}

	return NULL;
}

void test_timer_init_race(void)
{
	struct timer_init_race *skel;
	struct thread_ctx ctx;
	pthread_t tid[2];
	struct btf *btf;
	int err;

	skel = timer_init_race__open();
	if (!ASSERT_OK_PTR(skel, "timer_init_race open"))
		return;

	err = timer_init_race__load(skel);
	if (!ASSERT_EQ(err, 0, "timer_init_race load"))
		goto out;

	memset(&ctx, 0, sizeof(ctx));

	btf = bpf_object__btf(skel->obj);
	if (!ASSERT_OK_PTR(btf, "timer_init_race btf"))
		goto out;

	LIBBPF_OPTS_RESET(ctx.opts);
	ctx.opts.btf_fd = bpf_object__btf_fd(skel->obj);
	if (!ASSERT_GE((int)ctx.opts.btf_fd, 0, "btf_fd"))
		goto out;
	ctx.opts.btf_key_type_id = btf__find_by_name(btf, "int");
	if (!ASSERT_GT(ctx.opts.btf_key_type_id, 0, "key_type_id"))
		goto out;
	ctx.opts.btf_value_type_id = btf__find_by_name_kind(btf, "inner_value", BTF_KIND_STRUCT);
	if (!ASSERT_GT(ctx.opts.btf_value_type_id, 0, "value_type_id"))
		goto out;

	err = timer_init_race__attach(skel);
	if (!ASSERT_EQ(err, 0, "timer_init_race attach"))
		goto out;

	skel->bss->tgid = getpid();

	pthread_barrier_init(&ctx.barrier, NULL, 2);
	ctx.outer_map_fd = bpf_map__fd(skel->maps.outer_map);
	ctx.loop = 8;

	err = pthread_create(&tid[0], NULL, close_map_fn, &ctx);
	if (!ASSERT_OK(err, "close_thread"))
		goto out;

	err = pthread_create(&tid[1], NULL, init_timer_fn, &ctx);
	if (!ASSERT_OK(err, "init_thread")) {
		ctx.abort = 1;
		pthread_join(tid[0], NULL);
		goto out;
	}

	ctx.start = 1;
	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);

	ASSERT_EQ(ctx.err, 0, "error");
	ASSERT_EQ(skel->bss->cnt, 8, "cnt");
out:
	timer_init_race__destroy(skel);
}
