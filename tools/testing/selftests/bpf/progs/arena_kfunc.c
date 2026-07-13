// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Tejun Heo <tj@kernel.org> */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"
#include <bpf_arena_common.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

/* volatile to force the scalar reloads below */
volatile u64 stash;

SEC("syscall")
__success __retval(0)
int arena_arg_forms(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	u64 __arena *val;
	u64 ret;

	val = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!val)
		return 1;

	/* PTR_TO_ARENA argument */
	*val = 41;
	ret = bpf_kfunc_arena_arg_test((u64 *)val);
	if (ret != 41 || *val != 42)
		return 2;

	/* the low 32 bits as a scalar */
	stash = (u64)val;
	ret = bpf_kfunc_arena_arg_test((u64 *)stash);
	if (ret != 42 || *val != 43)
		return 3;

	/* the full user address as a scalar */
	stash = (u64)val;
	bpf_addr_space_cast(stash, 1, 0);
	ret = bpf_kfunc_arena_arg_test((u64 *)stash);
	if (ret != 43 || *val != 44)
		return 4;

	/* NULL is preserved */
	ret = bpf_kfunc_arena_arg_test(NULL);
	if (ret != 0xdeadbeef)
		return 5;

	bpf_arena_free_pages(&arena, (void __arena *)val, 1);
#endif
	return 0;
}

SEC("syscall")
__success __retval(0)
int arena_args5(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	u64 __arena *val;

	val = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!val)
		return 1;

	val[0] = 1;
	val[1] = 2;
	val[2] = 4;
	val[3] = 8;
	val[4] = 16;

	if (bpf_kfunc_arena_args5_test((u64 *)&val[0], (u64 *)&val[1],
				       (u64 *)&val[2], (u64 *)&val[3],
				       (u64 *)&val[4]) != 31)
		return 2;

	/* mix in NULLs */
	if (bpf_kfunc_arena_args5_test((u64 *)&val[0], NULL, (u64 *)&val[2],
				       NULL, (u64 *)&val[4]) != 21)
		return 3;

	bpf_arena_free_pages(&arena, (void __arena *)val, 1);
#endif
	return 0;
}

/* kernel-side faults on unpopulated pages recover via the scratch page */
SEC("syscall")
__success __retval(0)
int arena_arg_unpopulated(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST) && \
	(defined(__TARGET_ARCH_x86) || defined(__TARGET_ARCH_arm64))
	u64 __arena *val;

	val = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!val)
		return 1;

	stash = (u64)val + PAGE_SIZE;
	bpf_kfunc_arena_arg_test((u64 *)stash);

	bpf_arena_free_pages(&arena, (void __arena *)val, 1);
#endif
	return 0;
}

SEC("syscall")
__failure __msg("arena pointer requires a program with an associated arena")
int arena_arg_no_arena(void *ctx)
{
	bpf_kfunc_arena_arg_test((u64 *)1);
	return 0;
}

SEC("syscall")
__failure __msg("is not a pointer to arena or scalar")
int arena_arg_bad_reg(void *ctx)
{
	u64 buf = 0;

	/* use the arena so the program passes the arena presence check */
	bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	bpf_kfunc_arena_arg_test(&buf);
	return 0;
}

char _license[] SEC("license") = "GPL";
