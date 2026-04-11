// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 16); /* number of pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32); /* start of mmap() region */
#else
	__ulong(map_extra, 0x1ull << 44); /* start of mmap() region */
#endif
} arena SEC(".maps");

void __arena *alloc_addr;

SEC("syscall")
int arena_alloc(void *ctx)
{
	void __arena *p;

	p = bpf_arena_alloc_pages(&arena, NULL, 4, NUMA_NO_NODE, 0);
	if (!p)
		return 1;
	alloc_addr = p;
	return 0;
}

SEC("syscall")
int arena_free(void *ctx)
{
	if (!alloc_addr)
		return 1;
	bpf_arena_free_pages(&arena, alloc_addr, 4);
	return 0;
}

char _license[] SEC("license") = "GPL";
