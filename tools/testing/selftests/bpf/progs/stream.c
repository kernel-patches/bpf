// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

struct arr_elem {
	struct bpf_res_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct arr_elem);
} arrmap SEC(".maps");

#define ENOSPC 28
#define _STR "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define STREAM_STR (u64)(_STR _STR _STR _STR)

SEC("syscall")
__success __retval(0)
int stream_exhaust(void *ctx)
{
	bpf_repeat(BPF_MAX_LOOPS)
		if (bpf_stream_printk(BPF_STDOUT, _STR) == -ENOSPC)
			return 0;
	return 1;
}

SEC("syscall")
__success __retval(0)
int stream_cond_break(void *ctx)
{
	while (can_loop)
		;
	return 0;
}

SEC("syscall")
__success __retval(0)
int stream_deadlock(void *ctx)
{
	struct bpf_res_spin_lock *lock, *nlock;

	lock = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!lock)
		return 0;
	nlock = bpf_map_lookup_elem(&arrmap, &(int){0});
	if (!nlock)
		return 0;
	if (bpf_res_spin_lock(lock))
		return 0;
	if (bpf_res_spin_lock(nlock)) {
		bpf_res_spin_unlock(lock);
		return 0;
	}
	bpf_res_spin_unlock(nlock);
	bpf_res_spin_unlock(lock);
	return 0;
}

SEC("syscall")
__success __retval(0)
int stream_syscall(void *ctx)
{
	bpf_stream_printk(BPF_STDOUT, "foo");
	return 0;
}

char _license[] SEC("license") = "GPL";
