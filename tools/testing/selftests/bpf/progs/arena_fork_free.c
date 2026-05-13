// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
/*
 * Validate arena VMA tracking across fork.
 *
 * Provides BPF programs to allocate and free arena pages, exercised by
 * the userspace test to verify that zap_pages() correctly handles VMA
 * lifecycle when a forked child holds an inherited arena mmap.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 10); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

bool skip = false;

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST

void __arena *alloc_ptr;
int alloc_page_cnt;

SEC("syscall")
int arena_alloc(void *ctx)
{
	alloc_ptr = bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
	if (!alloc_ptr)
		return 1;
	alloc_page_cnt = 2;
	return 0;
}

SEC("syscall")
int arena_free(void *ctx)
{
	if (!alloc_ptr || !alloc_page_cnt)
		return 1;
	bpf_printk("arena_free: ptr=%p cnt=%d", alloc_ptr, alloc_page_cnt);
	bpf_arena_free_pages(&arena, alloc_ptr, alloc_page_cnt);
	bpf_printk("arena_free: done");
	alloc_ptr = NULL;
	alloc_page_cnt = 0;
	return 0;
}

#else

SEC("syscall")
int arena_alloc(void *ctx)
{
	skip = true;
	return 0;
}

SEC("syscall")
int arena_free(void *ctx)
{
	skip = true;
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
