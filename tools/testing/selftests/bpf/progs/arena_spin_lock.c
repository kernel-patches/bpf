// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_arena_qspinlock.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 100); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

#if defined(ENABLE_ATOMICS_TESTS) && defined(__BPF_FEATURE_ADDR_SPACE_CAST)
struct qspinlock __arena lock;
void *ptr;
int test_skip = 1;
#else
int test_skip = 2;
#endif

int counter;

SEC("tc")
int prog(void *ctx)
{
	bool ret = false;

#if defined(ENABLE_ATOMICS_TESTS) && defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	ptr = &arena;
	bpf_preempt_disable();
	if (queued_spin_lock(&lock))
		return false;
	WRITE_ONCE(counter, READ_ONCE(counter) + 1);
	bpf_repeat(BPF_MAX_LOOPS);
	ret = true;
	queued_spin_unlock(&lock);
	bpf_preempt_enable();
#endif
	return ret;
}

char _license[] SEC("license") = "GPL";
