// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_experimental.h"
#include "bpf_arena_common.h"
#include "bpf_misc.h"

#define ARENA_PAGES (64)
#define GLOBAL_PAGES (16)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, ARENA_PAGES); /* Arena of 64 pages */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, (1ull << 32) | (~0u - __PAGE_SIZE * ARENA_PAGES + 1));
#else
	__ulong(map_extra, (1ull << 44) | (~0u - __PAGE_SIZE * ARENA_PAGES + 1));
#endif
} arena SEC(".maps");

/*
 * Global data small enough that we can apply the maximum
 * offset into the arena. Userspace will also use this to
 * ensure the offset doesn't unexpectedly change from
 * under us.
 */
char __arena global_data[PAGE_SIZE][GLOBAL_PAGES];

SEC("syscall")
__success __retval(0)
int check_reserve1(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	__u8 __arena *guard, *globals;
	int ret;

	guard = (void __arena *)arena_base(&arena);
	globals = (void __arena *)(arena_base(&arena) + (ARENA_PAGES - GLOBAL_PAGES) * PAGE_SIZE);

	/* Reserve the region we've offset the globals by. */
	ret = bpf_arena_reserve_pages(&arena, guard, ARENA_PAGES - GLOBAL_PAGES);
	if (ret)
		return 1;

	/* Make sure the globals are placed GLOBALS_PGOFF pages in. */
	ret = bpf_arena_reserve_pages(&arena, globals, 1);
	if (!ret)
		return 2;
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
