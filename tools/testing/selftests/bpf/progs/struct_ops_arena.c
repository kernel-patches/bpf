// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Tejun Heo <tj@kernel.org> */

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include <bpf_arena_common.h>
#include "../test_kmods/bpf_testmod.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	/* page 0 hosts the arena globals, page 1 is for allocations */
	__uint(max_entries, 2);
} arena SEC(".maps");

/* also associates the callback with the arena */
u64 __arena arena_touch;

SEC("struct_ops/test_arena")
int test_arena_cb(unsigned long long *ctx)
{
	u64 __arena *ptr = (u64 __arena *)ctx[0];

	arena_touch++;
	if (!ptr)
		return 0xbee;
	*ptr += 1;
	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops3 testmod_arena = {
	.test_arena = (void *)test_arena_cb,
};

SEC("syscall")
int trigger(void *ctx)
{
#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)
	u64 __arena *val;
	int ret;

	val = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!val)
		return 1;

	*val = 41;
	ret = bpf_testmod_ops3_call_test_arena((u64 *)val);
	if (ret)
		return 2;
	if (*val != 42)
		return 3;

	/* NULL reaches the callback as NULL */
	ret = bpf_testmod_ops3_call_test_arena(NULL);
	if (ret != 0xbee)
		return 4;

	bpf_arena_free_pages(&arena, (void __arena *)val, 1);
#endif
	return 0;
}
