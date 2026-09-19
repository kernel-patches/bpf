// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_experimental.h"
#include <bpf_arena_common.h>

#define PATTERN 0x5a17c0decafef00dULL
#define PAGE_QWORDS (PAGE_SIZE / sizeof(__u64))

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
#ifdef __TARGET_ARCH_arm64
	__ulong(map_extra, 0x1ull << 32);
#else
	__ulong(map_extra, 0x1ull << 44);
#endif
} arena SEC(".maps");

void __arena *page;
__u32 alloc_wins;
const volatile bool deferred_free;

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

static __always_inline void fill_page(__u64 __arena *p)
{
	int i;

	for (i = 0; i < PAGE_QWORDS; i++)
		p[i] = PATTERN;
}

static __always_inline __u64 __arena *get_page(void)
{
	__u64 addr = (__u64)page;

	if (!addr)
		return NULL;
	return (__u64 __arena *)((__u64)arena_base(&arena) + (__u32)addr);
}

SEC("syscall")
int init_page(void *ctx)
{
	__u64 __arena *p;

	p = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!p)
		return 1;
	fill_page(p);
	page = p;
	return 0;
}

SEC("syscall")
int prime_tlb(void *ctx)
{
	__u64 __arena *p = get_page();

	if (!p)
		return 1;
	return p[0] != PATTERN;
}

SEC("syscall")
int free_page(void *ctx)
{
	void __arena *p = page;

	if (!p)
		return 1;
	if (deferred_free)
		bpf_rcu_read_lock();
	bpf_arena_free_pages(&arena, p, 1);
	if (deferred_free)
		bpf_rcu_read_unlock();
	return 0;
}

SEC("syscall")
int alloc_page(void *ctx)
{
	__u64 __arena *p;

	p = bpf_arena_alloc_pages(&arena, NULL, 1, NUMA_NO_NODE, 0);
	if (!p)
		return 0;
	fill_page(p);
	page = p;
	__sync_fetch_and_add(&alloc_wins, 1);
	return 0;
}

SEC("syscall")
int check_page(void *ctx)
{
	__u64 __arena *p = get_page();
	int i;

	if (!p)
		return 1;
	for (i = 0; i < PAGE_QWORDS; i++) {
		if (p[i] != PATTERN)
			return i + 1;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
