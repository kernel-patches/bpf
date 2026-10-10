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
	__uint(map_flags, BPF_F_MMAPABLE | BPF_F_ARENA_NO_FREE | BPF_F_ARENA_EXPORT);
	/* The host runner reuses the map created with the selected capacity. */
	__uint(max_entries, 1);
} arena SEC(".maps");

volatile __u32 signal_offset;

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST

SEC("syscall")
int exchange(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);
	__u64 seq = page->h2g_seq;

	if (smp_load_acquire(&page->ready) != GUEST_READY)
		return 4;
	if (!seq) {
		page->h2g_payload = HOST_FIRST;
		smp_store_release(&page->h2g_seq, 1);
		return 0;
	}
	if (seq == 1 && smp_load_acquire(&page->g2h_seq) == 1) {
		if (page->g2h_payload != GUEST_FIRST)
			return 3;
		page->h2g_payload = HOST_SECOND;
		smp_store_release(&page->h2g_seq, 2);
		return 0;
	}
	if (seq == 2 && smp_load_acquire(&page->g2h_seq) == 2) {
		if (page->g2h_payload != GUEST_SECOND)
			return 3;
		smp_store_release(&page->h2g_seq, 3);
		return 2;
	}
	return 1;
}

SEC("syscall")
int check_reply(void *ctx)
{
	struct signal_page __arena *page =
		(struct signal_page __arena *)((char __arena *)arena_base(&arena) +
					     signal_offset);
	__u64 seq = page->h2g_seq;

	if ((seq != 1 && seq != 2) || smp_load_acquire(&page->g2h_seq) != seq)
		return 1;
	return page->g2h_payload == (seq == 1 ? GUEST_FIRST : GUEST_SECOND) ? 0 : 3;
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

#else
SEC("syscall") int exchange(void *ctx) { return 1; }
SEC("syscall") int check_reply(void *ctx) { return 1; }
SEC("syscall") int probe_free(void *ctx) { return 1; }
#endif

char _license[] SEC("license") = "GPL";
