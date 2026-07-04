// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "memcg_stat_reader.h"

char _license[] SEC("license") = "GPL";

/*
 * Flipped by userspace between timed runs (a plain .bss global, writable at
 * runtime through the skeleton mmap):
 *   0 - collect only the matched subset (a handful of kfunc calls)
 *   1 - additionally fold in the full memory.stat field set (many kfunc calls)
 */
int collect_full;

/*
 * Per-cgroup results, keyed by cgroup id.  The BPF-side id (cgrp->kn->id)
 * equals the userspace get_cgroup_id() value, so the test can correlate map
 * entries back to the cgroups it created.  max_entries is resized by userspace
 * (bpf_map__set_max_entries) to the size of the subtree before load.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u64);
	__type(value, struct memcg_stat_snapshot);
} results SEC(".maps");

/*
 * Accumulate one page-state / vm-event read.  Each enumerator is guarded by
 * bpf_core_enum_value_exists(): the full field set below spans counters that are
 * config- or version-gated (e.g. NR_SECONDARY_PAGETABLE, PGDEMOTE_KHUGEPAGED,
 * MEMCG_PERCPU_B), so on a kernel whose BTF lacks one, the bpf_core_enum_value()
 * relocation would otherwise poison the instruction and fail the *entire*
 * program load.  With the _exists guard the missing enumerator relocates to a
 * compile-time-false branch that the verifier drops as dead code, so the fold is
 * simply skipped and the rest of the program (including the matched/correctness
 * path) still loads.
 */
#define FOLD_PS(ENUM, NAME) do {						\
	if (bpf_core_enum_value_exists(enum ENUM, NAME)) {			\
		__u64 __v = bpf_mem_cgroup_page_state(memcg,			\
				bpf_core_enum_value(enum ENUM, NAME));		\
		if (__v != (__u64)-1) {						\
			sum += __v;						\
			nr++;							\
		}								\
	}									\
} while (0)

#define FOLD_EV(NAME) do {							\
	if (bpf_core_enum_value_exists(enum vm_event_item, NAME)) {		\
		__u64 __v = bpf_mem_cgroup_vm_events(memcg,			\
				bpf_core_enum_value(enum vm_event_item, NAME));	\
		if (__v != (__u64)-1) {						\
			sum += __v;						\
			nr++;						\
		}							\
	}								\
} while (0)

/*
 * Read a broad memory.stat field set so the timed "full" run pays the realistic
 * per-field kfunc cost.  Enumerators absent from the running kernel's BTF are
 * skipped (see the _exists guard in FOLD_PS/FOLD_EV), so this stays loadable
 * across kernel configs/versions.  __always_inline so the acquired memcg
 * reference stays in the main frame (no cross-subprog reference tracking); the
 * runtime collect_full branch keeps it off the matched path.
 */
static __always_inline void collect_full_stats(struct mem_cgroup *memcg,
					       struct memcg_stat_snapshot *snap)
{
	__u64 sum = 0;
	__u32 nr = 0;

	/* node_stat_item: size + event counters that memory.stat prints */
	FOLD_PS(node_stat_item, NR_ANON_MAPPED);
	FOLD_PS(node_stat_item, NR_FILE_PAGES);
	FOLD_PS(node_stat_item, NR_FILE_MAPPED);
	FOLD_PS(node_stat_item, NR_FILE_DIRTY);
	FOLD_PS(node_stat_item, NR_WRITEBACK);
	FOLD_PS(node_stat_item, NR_SHMEM);
	FOLD_PS(node_stat_item, NR_INACTIVE_ANON);
	FOLD_PS(node_stat_item, NR_ACTIVE_ANON);
	FOLD_PS(node_stat_item, NR_INACTIVE_FILE);
	FOLD_PS(node_stat_item, NR_ACTIVE_FILE);
	FOLD_PS(node_stat_item, NR_UNEVICTABLE);
	FOLD_PS(node_stat_item, NR_SLAB_RECLAIMABLE_B);
	FOLD_PS(node_stat_item, NR_SLAB_UNRECLAIMABLE_B);
	FOLD_PS(node_stat_item, NR_KERNEL_STACK_KB);
	FOLD_PS(node_stat_item, NR_PAGETABLE);
	FOLD_PS(node_stat_item, NR_SECONDARY_PAGETABLE);
	FOLD_PS(node_stat_item, NR_VMALLOC);
	FOLD_PS(node_stat_item, WORKINGSET_REFAULT_ANON);
	FOLD_PS(node_stat_item, WORKINGSET_REFAULT_FILE);
	FOLD_PS(node_stat_item, WORKINGSET_ACTIVATE_ANON);
	FOLD_PS(node_stat_item, WORKINGSET_ACTIVATE_FILE);
	FOLD_PS(node_stat_item, WORKINGSET_RESTORE_ANON);
	FOLD_PS(node_stat_item, WORKINGSET_RESTORE_FILE);
	FOLD_PS(node_stat_item, WORKINGSET_NODERECLAIM);
	FOLD_PS(node_stat_item, PGDEMOTE_KSWAPD);
	FOLD_PS(node_stat_item, PGDEMOTE_DIRECT);
	FOLD_PS(node_stat_item, PGDEMOTE_KHUGEPAGED);
	FOLD_PS(node_stat_item, PGSTEAL_KSWAPD);
	FOLD_PS(node_stat_item, PGSTEAL_DIRECT);
	FOLD_PS(node_stat_item, PGSTEAL_KHUGEPAGED);
	FOLD_PS(node_stat_item, PGSCAN_KSWAPD);
	FOLD_PS(node_stat_item, PGSCAN_DIRECT);
	FOLD_PS(node_stat_item, PGSCAN_KHUGEPAGED);
	FOLD_PS(node_stat_item, PGREFILL);

	/* memcg_stat_item: numbered past NR_VM_NODE_STAT_ITEMS */
	FOLD_PS(memcg_stat_item, MEMCG_KMEM);
	FOLD_PS(memcg_stat_item, MEMCG_SOCK);
	FOLD_PS(memcg_stat_item, MEMCG_PERCPU_B);

	/* vm_event_item: the raw-count tail of memory.stat */
	FOLD_EV(PGFAULT);
	FOLD_EV(PGMAJFAULT);
	FOLD_EV(PGACTIVATE);
	FOLD_EV(PGDEACTIVATE);
	FOLD_EV(PGLAZYFREE);
	FOLD_EV(PGLAZYFREED);

	snap->full_sum = sum;
	snap->full_fields = nr;
}

SEC("iter.s/cgroup")
int cgroup_memcg_stat_reader(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct memcg_stat_snapshot snap = {};
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	__u64 cg_id;

	/*
	 * DESCENDANTS_PRE ends with a terminal element where cgroup == NULL.
	 * Return 0 (not 1) so the walk runs to completion.
	 */
	if (!cgrp)
		return 0;

	css = &cgrp->self;
	memcg = bpf_get_mem_cgroup(css);
	if (!memcg)
		return 0;

	/* Bring this memcg's rstat up to date before reading it. */
	bpf_mem_cgroup_flush_stats(memcg);

	cg_id = BPF_CORE_READ(cgrp, kn, id);
	snap.cgroup_id = cg_id;

	/* Matched subset: always collected so correctness holds in both modes. */
	snap.anon = bpf_mem_cgroup_page_state(memcg,
			bpf_core_enum_value(enum node_stat_item, NR_ANON_MAPPED));
	snap.file = bpf_mem_cgroup_page_state(memcg,
			bpf_core_enum_value(enum node_stat_item, NR_FILE_PAGES));
	snap.shmem = bpf_mem_cgroup_page_state(memcg,
			bpf_core_enum_value(enum node_stat_item, NR_SHMEM));
	snap.file_mapped = bpf_mem_cgroup_page_state(memcg,
			bpf_core_enum_value(enum node_stat_item, NR_FILE_MAPPED));
	snap.pgfault = bpf_mem_cgroup_vm_events(memcg,
			bpf_core_enum_value(enum vm_event_item, PGFAULT));

	/* page_counter fields need no kfunc; read them off the trusted ptr. */
	snap.usage_pages = BPF_CORE_READ(memcg, memory.usage.counter);
	snap.max_pages = BPF_CORE_READ(memcg, memory.max);

	if (collect_full)
		collect_full_stats(memcg, &snap);

	bpf_map_update_elem(&results, &cg_id, &snap, BPF_ANY);

	bpf_put_mem_cgroup(memcg);
	return 0;
}
