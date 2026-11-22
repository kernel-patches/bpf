// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 8);
} arena SEC(".maps");

SEC("syscall")
int alloc_beyond_vma(void *ctx)
{
	void __arena *page;

	/* A successful allocation at offset zero can return a NULL pointer. */
	bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	page = bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
	if (!page)
		return 1;
	/* Only one of the four mmap()ed pages remains available. */
	page = bpf_arena_alloc_pages(&arena, NULL, 2, NUMA_NO_NODE, 0);
	if (page)
		return 2;
	page = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	return page ? 0 : 3;
}

char _license[] SEC("license") = "GPL";
