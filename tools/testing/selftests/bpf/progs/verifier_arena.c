// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2); /* arena of two pages close to 32-bit boundary*/
	__ulong(map_extra, (1ull << 44) | (~0u - __PAGE_SIZE * 2 + 1)); /* start of mmap() region */
} arena SEC(".maps");

SEC("syscall")
__success __retval(0)
int basic_alloc1(void *ctx)
{
	volatile int __arena *page1, *page2, *no_page, *page3;

	page1 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page1)
		return 1;
	*page1 = 1;
	page2 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page2)
		return 2;
	*page2 = 2;
	no_page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (no_page)
		return 3;
	if (*page1 != 1)
		return 4;
	if (*page2 != 2)
		return 5;
	bpf_arena_free_pages(&arena, (void __arena *)page2, 1);
	if (*page1 != 1)
		return 6;
	if (*page2 != 0) /* use-after-free should return 0 */
		return 7;
	page3 = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!page3)
		return 8;
	*page3 = 3;
	if (page2 != page3)
		return 9;
	if (*page1 != 1)
		return 10;
	return 0;
}

SEC("syscall")
__success __retval(0)
int basic_alloc2(void *ctx)
{
	volatile char __arena *page1, *page2, *page3, *page4;

	page1 = bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
	if (!page1)
		return 1;
	page2 = page1 + __PAGE_SIZE;
	page3 = page1 + __PAGE_SIZE * 2;
	page4 = page1 - __PAGE_SIZE;
	*page1 = 1;
	*page2 = 2;
	*page3 = 3;
	*page4 = 4;
	if (*page1 != 1)
		return 1;
	if (*page2 != 2)
		return 2;
	if (*page3 != 0)
		return 3;
	if (*page4 != 0)
		return 4;
	bpf_arena_free_pages(&arena, (void __arena *)page1, 2);
	if (*page1 != 0)
		return 5;
	if (*page2 != 0)
		return 6;
	if (*page3 != 0)
		return 7;
	if (*page4 != 0)
		return 8;
	return 0;
}

char _license[] SEC("license") = "GPL";
