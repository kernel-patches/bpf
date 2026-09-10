// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "memcg_stat_cross_cpu.h"

char _license[] SEC("license") = "GPL";

/* Ensure the upper-bound checks also reject negative BPF arguments. */
_Static_assert((enum vm_event_item)-1 >= NR_VM_EVENT_ITEMS,
	       "negative vm_event_item must fail the bounds check");
_Static_assert((enum memcg_memory_event)-1 >= MEMCG_NR_MEMORY_EVENTS,
	       "negative memcg_memory_event must fail the bounds check");

/* Declare kfuncs that may be absent from the build-time vmlinux.h. */
struct mem_cgroup *bpf_get_mem_cgroup(struct cgroup_subsys_state *css) __ksym;
void bpf_put_mem_cgroup(struct mem_cgroup *memcg) __ksym;
void bpf_mem_cgroup_flush_stats(struct mem_cgroup *memcg) __ksym;
unsigned long bpf_mem_cgroup_page_state(struct mem_cgroup *memcg, int idx) __ksym;
unsigned long bpf_mem_cgroup_vm_events(struct mem_cgroup *memcg,
				       enum vm_event_item event) __ksym;

/* Userspace resizes this cgroup-ID map before load. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, struct memcg_stat_snapshot);
} results SEC(".maps");

/* Isolate capability failures from verifier failures in the test program. */
SEC("iter.s/cgroup")
int memcg_kfuncs_probe(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct mem_cgroup *memcg;

	if (!cgrp)
		return 0;

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg)
		return 0;

	bpf_mem_cgroup_flush_stats(memcg);
	bpf_mem_cgroup_page_state(memcg, 0);
	bpf_mem_cgroup_vm_events(memcg, 0);
	bpf_put_mem_cgroup(memcg);
	return 0;
}

/* Sleepable iterator: flush the root once, then snapshot each cgroup. */
SEC("iter.s/cgroup")
int cgroup_memcg_stat_cross_cpu(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct memcg_stat_snapshot snap = {};
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	int idx_anon, idx_file, idx_shmem, idx_fmapped, idx_pgfault;
	__u64 cg_id;

	/* Ignore the final post-processing call. */
	if (!cgrp)
		return 0;

	css = &cgrp->self;
	memcg = bpf_get_mem_cgroup(css);
	if (!memcg)
		return 0;

	/* DESCENDANTS_PRE visits the subtree root first. */
	if (ctx->meta->seq_num == 0)
		bpf_mem_cgroup_flush_stats(memcg);

	cg_id = BPF_CORE_READ(cgrp, kn, id);
	snap.cgroup_id = cg_id;

	idx_anon = bpf_core_enum_value(enum node_stat_item, NR_ANON_MAPPED);
	idx_file = bpf_core_enum_value(enum node_stat_item, NR_FILE_PAGES);
	idx_shmem = bpf_core_enum_value(enum node_stat_item, NR_SHMEM);
	idx_fmapped = bpf_core_enum_value(enum node_stat_item, NR_FILE_MAPPED);
	idx_pgfault = bpf_core_enum_value(enum vm_event_item, PGFAULT);

	snap.anon = bpf_mem_cgroup_page_state(memcg, idx_anon);
	snap.file = bpf_mem_cgroup_page_state(memcg, idx_file);
	snap.shmem = bpf_mem_cgroup_page_state(memcg, idx_shmem);
	snap.file_mapped = bpf_mem_cgroup_page_state(memcg, idx_fmapped);
	snap.pgfault = bpf_mem_cgroup_vm_events(memcg, idx_pgfault);

	/* Read page counters from the trusted pointer. */
	snap.usage_pages = BPF_CORE_READ(memcg, memory.usage.counter);
	snap.max_pages = BPF_CORE_READ(memcg, memory.max);

	bpf_map_update_elem(&results, &cg_id, &snap, BPF_ANY);

	bpf_put_mem_cgroup(memcg);
	return 0;
}
