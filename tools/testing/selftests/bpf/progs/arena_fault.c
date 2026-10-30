// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"
#include "../test_kmods/bpf_test_arena_fault.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 2);
} arena SEC(".maps");

u64 __arena arena_pad;
volatile u64 observed;

SEC("syscall")
int stash_and_free(void *ctx)
{
	u64 __arena *val;

	val = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!val)
		return 1;

	*val = 42;
	bpf_test_arena_fault_stash((u64 *)val);
	bpf_arena_free_pages(&arena, val, 1);
	return 0;
}

SEC("syscall")
int fault_stashed_wrong_arena(void *ctx)
{
	u64 __arena *val;

	val = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!val)
		return 1;

	*val = 1;
	observed = bpf_test_arena_fault_load_stashed();
	bpf_arena_free_pages(&arena, val, 1);
	return observed != 0;
}

SEC("syscall")
int clear_stashed(void *ctx)
{
	bpf_test_arena_fault_clear_stashed();
	return 0;
}

char _license[] SEC("license") = "GPL";
