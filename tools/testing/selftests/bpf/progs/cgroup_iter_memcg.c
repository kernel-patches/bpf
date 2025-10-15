// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include "cgroup_iter_memcg.h"

char _license[] SEC("license") = "GPL";

extern void memcg_flush_stats(struct cgroup *cgrp) __ksym;
extern unsigned long memcg_stat_fetch(struct cgroup *cgrp,
		enum memcg_stat_item item) __ksym;
extern unsigned long memcg_node_stat_fetch(struct cgroup *cgrp,
		enum node_stat_item item) __ksym;
extern unsigned long memcg_vm_event_fetch(struct cgroup *cgrp,
		enum vm_event_item item) __ksym;

/* The latest values read are stored here. */
struct memcg_query memcg_query SEC(".data.query");

/*
 * Helpers for fetching any of the three different types of memcg stats.
 * BPF core macros are used to ensure an enumerator is present in the given
 * kernel. Falling back on -1 indicates its absence.
 */
#define node_stat_fetch_if_exists(cgrp, item) \
	bpf_core_enum_value_exists(enum node_stat_item, item) ? \
		memcg_node_stat_fetch((cgrp), bpf_core_enum_value( \
					 enum node_stat_item, item)) : -1

#define memcg_stat_fetch_if_exists(cgrp, item) \
	bpf_core_enum_value_exists(enum memcg_stat_item, item) ? \
		memcg_node_stat_fetch((cgrp), bpf_core_enum_value( \
					 enum memcg_stat_item, item)) : -1

#define vm_event_fetch_if_exists(cgrp, item) \
	bpf_core_enum_value_exists(enum vm_event_item, item) ? \
		memcg_vm_event_fetch((cgrp), bpf_core_enum_value( \
					 enum vm_event_item, item)) : -1

SEC("iter.s/cgroup")
int cgroup_memcg_query(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;

	if (!cgrp)
		return 1;

	memcg_flush_stats(cgrp);

	memcg_query.nr_anon_mapped = node_stat_fetch_if_exists(cgrp,
			NR_ANON_MAPPED);
	memcg_query.nr_shmem = node_stat_fetch_if_exists(cgrp, NR_SHMEM);
	memcg_query.nr_file_pages = node_stat_fetch_if_exists(cgrp,
			NR_FILE_PAGES);
	memcg_query.nr_file_mapped = node_stat_fetch_if_exists(cgrp,
			NR_FILE_MAPPED);
	memcg_query.memcg_kmem = memcg_stat_fetch_if_exists(cgrp, MEMCG_KMEM);
	memcg_query.pgfault = vm_event_fetch_if_exists(cgrp, PGFAULT);

	return 0;
}
