// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES
 */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
#include "bpf_arena_common.h"
#ifdef __TARGET_ARCH_powerpc
/* PowerPC does not support arena load-acquire/store-release instructions. */
#undef __BPF_FEATURE_LOAD_ACQ_STORE_REL
#endif
#include "bpf_atomic.h"
#endif
#include "arena_kvm_shared.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE);
	__uint(max_entries, 1);
} arena SEC(".maps");

volatile __u32 signal_offset;

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST

SEC("syscall")
int allocate(void *ctx)
{
	struct signal_page __arena *page;

	page = bpf_arena_alloc_pages(&arena, NULL, 1, ARENA_KVM_NODE, 0);
	if (!page)
		return 1;
	signal_offset = (__u32)((__u64)page - (__u64)arena_base(&arena));
	smp_store_release(&page->ready, GUEST_READY);
	return 0;
}

SEC("syscall")
int probe_free(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);

	bpf_arena_free_pages(&arena, page, 1);
	return page->ready == GUEST_READY ? 0 : 1;
}

SEC("syscall")
int exchange(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);
	__u64 seq = smp_load_acquire(&page->h2g_seq);
	__u64 payload;

	if ((seq != 1 && seq != 2) || page->g2h_seq == seq)
		return 1;
	payload = page->h2g_payload;
	if (seq == 1 && payload != HOST_FIRST)
		return 2;
	if (seq == 2 && payload != HOST_SECOND)
		return 3;
	page->g2h_payload = seq == 1 ? GUEST_FIRST : GUEST_SECOND;
	smp_store_release(&page->g2h_seq, seq);
	return 0;
}

SEC("syscall")
int complete(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);

	return smp_load_acquire(&page->h2g_seq) == 3 ? 0 : 1;
}

#else
SEC("syscall") int allocate(void *ctx) { return 1; }
SEC("syscall") int probe_free(void *ctx) { return 1; }
SEC("syscall") int exchange(void *ctx) { return 1; }
SEC("syscall") int complete(void *ctx) { return 1; }
#endif

char _license[] SEC("license") = "GPL";
