// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define _STR "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define STREAM_STR (u64)(_STR _STR _STR _STR)

static __noinline int stream_exercise(int id, int N)
{
	struct bpf_stream_elem *elem, *earr[56] = {};
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
	ret = 0;
	for (i = 0; i < N; i++) {
		elem = bpf_stream_next_elem(stream);
		if (!elem) {
			ret = 4;
			break;
		}
		earr[i] = elem;
	}
	elem = bpf_stream_next_elem(stream);
	if (elem) {
		bpf_stream_free_elem(elem);
		ret = 5;
	}
	for (i = 0; i < N; i++)
		if (earr[i])
			bpf_stream_free_elem(earr[i]);
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
	bpf_repeat(50) {
		ret = stream_exercise_nums(BPF_STDOUT);
		if (ret)
			break;
	}
	if (ret) {
		bpf_local_irq_restore(&flags);
		return ret;
	}
	bpf_repeat(100) {
		ret = stream_exercise_nums(BPF_STDERR);
		if (ret)
			break;
	}
	bpf_local_irq_restore(&flags);

	if (ret)
		return ret;

	ret = stream_exercise_nums(BPF_STDOUT);
	if (ret)
		return ret;
	return stream_exercise_nums(BPF_STDERR);
}

SEC("syscall")
__success __retval(0)
int stream_test_output(void *ctx)
{
	for (int i = 0; i < 1000; i++)
		bpf_stream_printk(BPF_STDOUT, "num=%d\n", i);
	return 0;
}

SEC("syscall")
__success __retval(0)
int stream_test_limit(void *ctx)
{
	struct bpf_stream *stream;
	bool failed = false;

	stream = bpf_stream_get(BPF_STDOUT, NULL);
	if (!stream)
		return 2;

	bpf_repeat(BPF_MAX_LOOPS) {
		failed = bpf_stream_vprintk(stream, "%s%s%s", &(u64[]){STREAM_STR, STREAM_STR}, 16) != 0;
		if (failed)
			break;
	}

	if (failed)
		return 0;
	return 1;
}

char _license[] SEC("license") = "GPL";
