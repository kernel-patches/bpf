// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define _STR "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define STREAM_STR (u64)(_STR _STR _STR _STR)

int stream_page_cnt;
int stream_page_next_cnt;

static __noinline void exhaust_stream_memory(int id)
{
	struct bpf_stream *stream;

	bpf_repeat(32) {
		stream = bpf_stream_get(id, NULL);
		if (!stream)
			break;
		bpf_stream_vprintk(stream, "...", &(u64){0}, 0);
	}
}

static __noinline int stream_exercise(int id, int N)
{
	struct bpf_stream_elem *elem, *earr[56] = {};
	struct bpf_stream_elem_batch *batch;
	struct bpf_stream *stream;
	int ret;
	u32 i;

	if (N > 56)
		return 56;

	stream = bpf_stream_get(id, NULL);
	if (!stream)
		return 1;
	for (i = 0; i < N; i++)
		if ((ret = bpf_stream_vprintk(stream, "%llu%s", &(u64[]){i, STREAM_STR}, 16)) < 0) {
			bpf_printk("bpf_stream_vprintk ret=%d", ret);
			return 2;
		}
	batch = bpf_stream_next_elem_batch(stream);
	if (!batch)
		return 3;
	ret = 0;
	for (i = 0; i < N; i++) {
		elem = bpf_stream_next_elem(batch);
		if (!elem) {
			ret = 4;
			break;
		}
		earr[i] = elem;

		if (elem->flags & BPF_STREAM_ELEM_F_PAGE)
			stream_page_cnt++;
		if (elem->flags & BPF_STREAM_ELEM_F_NEXT)
			stream_page_next_cnt++;
	}
	for (i = 0; i < N; i++)
		if (earr[i])
			bpf_stream_free_elem(earr[i]);
	bpf_stream_free_elem_batch(batch);
	return ret;
}

static __noinline int stream_exercise_nums(int id)
{
	int ret = 0;

	ret = ret ?: stream_exercise(id, 56);
	ret = ret ?: stream_exercise(id, 42);
	ret = ret ?: stream_exercise(id, 28);
	ret = ret ?: stream_exercise(id, 10);
	ret = ret ?: stream_exercise(id, 1);

	return ret;
}

SEC("syscall")
__success __retval(0)
int stream_test(void *ctx)
{
	unsigned long flags;
	int ret;

	bpf_local_irq_save(&flags);

	/*
	 * We grab 32 entries from a supposedly filled cache, so we'll have a
	 * case of elements mixing bpf_mem_alloc() and bpf_stream_page
	 * allocations.
	 *
	 * This also ensures that we test the path where the batch dequeued from
	 * the kernel contains extra non-extracted elements, that are then freed
	 * to the respective memory allocator depending on if they come from a
	 * page or not.
	 */
	exhaust_stream_memory(BPF_STDOUT);

	bpf_repeat(50) {
		ret = stream_exercise_nums(BPF_STDOUT);
		if (ret)
			break;
		if (!stream_page_cnt)
			break;
	}

	if (ret) {
		bpf_local_irq_restore(&flags);
		return ret;
	}

	if (!stream_page_cnt) {
		bpf_local_irq_restore(&flags);
		return 41;
	}

	stream_page_cnt = 0;

	bpf_repeat(100) {
		stream_page_cnt = 0;
		ret = stream_exercise_nums(BPF_STDERR);
		if (ret)
			break;
	}

	exhaust_stream_memory(BPF_STDOUT);

	bpf_local_irq_restore(&flags);

	if (ret)
		return ret;

	if (!stream_page_cnt)
		return 42;

	if (!stream_page_next_cnt)
		return 43;

	ret = stream_exercise_nums(BPF_STDOUT);
	if (ret)
		return ret;
	return stream_exercise_nums(BPF_STDERR);
}

char _license[] SEC("license") = "GPL";
