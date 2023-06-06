// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023. Huawei Technologies Co., Ltd */
#include <stdbool.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct update_ctx {
	unsigned int from;
	unsigned int step;
	unsigned int max;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, 4);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} htab SEC(".maps");

char _license[] SEC("license") = "GPL";

unsigned char zeroed_value[4096];
unsigned int nr_entries = 0;
unsigned int nr_thread = 0;
long loop_cnt = 0;

static int noop_htab(unsigned int i, struct update_ctx *ctx)
{
	if (ctx->from >= ctx->max)
		return 1;

	ctx->from += ctx->step;
	return 0;
}

static int write_htab(unsigned int i, struct update_ctx *ctx, unsigned int flags)
{
	if (ctx->from >= ctx->max)
		return 1;

	bpf_map_update_elem(&htab, &ctx->from, zeroed_value, flags);
	ctx->from += ctx->step;

	return 0;
}

static int overwrite_htab(unsigned int i, struct update_ctx *ctx)
{
	return write_htab(i, ctx, 0);
}

static int newwrite_htab(unsigned int i, struct update_ctx *ctx)
{
	return write_htab(i, ctx, BPF_NOEXIST);
}

static int del_htab(unsigned int i, struct update_ctx *ctx)
{
	if (ctx->from >= ctx->max)
		return 1;

	bpf_map_delete_elem(&htab, &ctx->from);
	ctx->from += ctx->step;

	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
int no_op(void *ctx)
{
	struct update_ctx update;

	update.from = bpf_get_smp_processor_id();
	update.step = nr_thread;
	update.max = nr_entries;
	bpf_loop(update.max, noop_htab, &update, 0);
	__sync_fetch_and_add(&loop_cnt, 1);

	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
int overwrite(void *ctx)
{
	struct update_ctx update;

	update.from = bpf_get_smp_processor_id();
	update.step = nr_thread;
	update.max = nr_entries;
	bpf_loop(update.max, overwrite_htab, &update, 0);
	/* Increase when nr_entries / nr_thread elements are deleted and then added */
	__sync_fetch_and_add(&loop_cnt, 1);
	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
int batch_add_batch_del(void *ctx)
{
	struct update_ctx update;

	update.from = bpf_get_smp_processor_id();
	update.step = nr_thread;
	update.max = nr_entries;
	bpf_loop(update.max, overwrite_htab, &update, 0);

	update.from = bpf_get_smp_processor_id();
	bpf_loop(update.max, del_htab, &update, 0);

	/* Increase when nr_entries / nr_thread elements are added and then deleted */
	__sync_fetch_and_add(&loop_cnt, 1);
	return 0;
}

SEC("?tp/syscalls/sys_enter_getpgid")
int add_del_on_diff_cpu(void *ctx)
{
	struct update_ctx update;
	unsigned int from;

	from = bpf_get_smp_processor_id();
	update.from = from / 2;
	update.step = nr_thread / 2;
	update.max = nr_entries;

	if (from & 1)
		bpf_loop(update.max, newwrite_htab, &update, 0);
	else
		bpf_loop(update.max, del_htab, &update, 0);

	/* Increase when nr_entries / nr_thread * 2 elements are added or deleted */
	__sync_fetch_and_add(&loop_cnt, 1);
	return 0;
}
