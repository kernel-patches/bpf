/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __MEMCG_STAT_CROSS_CPU_H
#define __MEMCG_STAT_CROSS_CPU_H

/*
 * One per-cgroup snapshot, written by the BPF program and read by the test, so
 * the fields are fixed-width rather than the long the other cgroup tests use.
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
