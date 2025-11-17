// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include "bpf_arena_common.h"

#define ARENA_PAGES (32)

#define ARENA_AVAIL_PAGES (6)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, ARENA_PAGES); /* Arena of 32 pages (standard offset is 16 pages) */
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, (1ull << 32) | (~0u - __PAGE_SIZE * ARENA_PAGES + 1));
#else
	__ulong(map_extra, (1ull << 44) | (~0u - __PAGE_SIZE * ARENA_PAGES + 1));
#endif
} arena SEC(".maps");

/*
 * Enough global data to fill most of the arena. Force libbpf to
 * adjust the offset into the arena enough for the data to fit.
 */

char __arena global_data[PAGE_SIZE][ARENA_PAGES - ARENA_AVAIL_PAGES];

SEC("syscall")
__success __retval(0)
int check_reserve3(void *ctx)
{
	void __arena *guard, *globals;
	int ret;

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	guard = (void __arena *)arena_base(&arena);
	globals = (void __arena *)(arena_base(&arena) + 4 * PAGE_SIZE);

	/*
	 * The data should be offset 4 pages in (the largest
	 * possible power of 2 that still leaves enough room
	 * to the global data).
	 */
	ret = bpf_arena_reserve_pages(&arena, guard, 4);
	if (ret)
		return 1;

	ret = bpf_arena_reserve_pages(&arena, globals, 1);
	if (!ret)
		return 2;
#endif
	return 0;
}

char _license[] SEC("license") = "GPL";
