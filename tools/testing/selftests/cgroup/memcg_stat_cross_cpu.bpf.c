// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "memcg_stat_cross_cpu.h"

char _license[] SEC("license") = "GPL";

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
 * Sleepable cgroup iterator: flush the subtree's rstat once at the root, then
 * for every cgroup in the walked subtree read a fixed set of memcg statistics
 * through the memcg kfuncs and stash them in the hash map for userspace to
 * compare against memory.stat.
 *
 * The flush kfunc may sleep, hence SEC("iter.s/cgroup").
 */
SEC("iter.s/cgroup")
int cgroup_memcg_stat_cross_cpu(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct memcg_stat_snapshot snap = {};
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	int idx_anon, idx_file, idx_shmem, idx_fmapped, idx_pgfault;
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

	/*
	 * Flush once, at the subtree root -- the first element visited in
	 * DESCENDANTS_PRE order (seq_num == 0).  css_rstat_flush() is
	 * subtree-wide, so this one flush brings the whole walked subtree
	 * up to date and every descendant read afterwards is accurate;
	 * flushing again per-cgroup would only hit the no-op threshold gate.
	 */
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

	/* page_counter fields need no kfunc; read them off the trusted ptr. */
	snap.usage_pages = BPF_CORE_READ(memcg, memory.usage.counter);
	snap.max_pages = BPF_CORE_READ(memcg, memory.max);

	bpf_map_update_elem(&results, &cg_id, &snap, BPF_ANY);

	bpf_put_mem_cgroup(memcg);
	return 0;
}
