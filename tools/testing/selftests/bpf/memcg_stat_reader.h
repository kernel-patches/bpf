/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#ifndef __MEMCG_STAT_READER_H
#define __MEMCG_STAT_READER_H

/*
 * One per-cgroup snapshot, produced by the BPF cgroup iterator and read back
 * from a BPF hash map keyed by cgroup id.  The "matched" subset is always
 * populated so it can be compared field-by-field against what userspace parses
 * out of memory.stat / memory.current / memory.max.  The "full" fold is only
 * populated when collect_full is set and exists to (a) force the extra kfunc
 * reads to happen (so the full-vs-matched timing is honest) and (b) give a
 * coarse, informational signal of how many fields the full path touched.
 */
struct memcg_stat_snapshot {
	__u64 cgroup_id;

	/* Matched subset. Page-state values are in bytes (already unit-scaled
	 * by the kernel), so they compare directly against memory.stat.
	 */
	__u64 anon;		/* NR_ANON_MAPPED, bytes */
	__u64 file;		/* NR_FILE_PAGES, bytes */
	__u64 shmem;		/* NR_SHMEM, bytes */
	__u64 file_mapped;	/* NR_FILE_MAPPED, bytes */
	__u64 pgfault;		/* PGFAULT, count */
	__u64 usage_pages;	/* page_counter memory.usage, in PAGES */
	__u64 max_pages;	/* page_counter memory.max, in PAGES */

	/* Full-mode fold: sum and count of every field the full path read. */
	__u64 full_sum;
	__u32 full_fields;
	__u32 pad;
};

#endif /* __MEMCG_STAT_READER_H */
