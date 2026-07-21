/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __MEMCG_STAT_CROSS_CPU_H
#define __MEMCG_STAT_CROSS_CPU_H

/*
 * One per-cgroup snapshot, produced by the BPF cgroup iterator and read back
 * from a BPF hash map keyed by cgroup id.  After the charge has quiesced the
 * test compares every field against what userspace parses from
 * memory.stat / memory.current / memory.max, so the two must agree.
 *
 * Page-state values are in bytes (already unit-scaled by the kernel), so they
 * compare directly against memory.stat.  usage_pages / max_pages come straight
 * off the page_counter and are in PAGES.
 */
struct memcg_stat_snapshot {
	__u64 cgroup_id;
	__u64 anon;		/* NR_ANON_MAPPED, bytes */
	__u64 file;		/* NR_FILE_PAGES, bytes */
	__u64 shmem;		/* NR_SHMEM, bytes */
	__u64 file_mapped;	/* NR_FILE_MAPPED, bytes */
	__u64 pgfault;		/* PGFAULT, count */
	__u64 usage_pages;	/* page_counter memory.usage, in PAGES */
	__u64 max_pages;	/* page_counter memory.max, in PAGES */
};

#endif /* __MEMCG_STAT_CROSS_CPU_H */
