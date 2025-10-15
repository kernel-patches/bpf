/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#ifndef __CGROUP_ITER_MEMCG_H
#define __CGROUP_ITER_MEMCG_H

struct memcg_query {
	/* some node_stat_item's */
	long nr_anon_mapped;
	long nr_shmem;
	long nr_file_pages;
	long nr_file_mapped;
	/* some memcg_stat_item */
	long memcg_kmem;
	/* some vm_event_item */
	long pgfault;
};

#endif /* __CGROUP_ITER_MEMCG_H */
