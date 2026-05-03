// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include "mthp_ext.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <vdso/bits.h>

struct mem_info {
	unsigned long stall;
	unsigned int  order;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mem_info);
} cgrp_storage SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct config_local configs;

/*
 * mthp_choose_impl: Choose the custom mTHP orders, read order from cgrp_storage,
 *		     which is Adjustment by the cgroup_scan().
 * @cgrp: control group
 * @orders: original orders
 *
 * Return suited mTHP orders.
 */
SEC("struct_ops/mthp_choose")
unsigned long BPF_PROG(mthp_choose_impl, struct cgroup *cgrp, unsigned long orders)
{
	struct mem_info *info;
	unsigned int order;

	if (configs.fixed) {
		order = configs.init_order;
		goto out;
	}

	info = bpf_cgrp_storage_get(&cgrp_storage, cgrp, 0, 0);
	if (!info)
		return orders;

	order = info->order;
out:
	if (!order)
		return 0;

	orders &= BIT(order + 1) - 1;
	return orders;
}

SEC(".struct_ops.link")
struct bpf_mthp_ops mthp_ops = {
	.mthp_choose = (void *)mthp_choose_impl,
};

/* backport from kernel/cgroup/cgroup.c */
static bool cgroup_has_tasks(struct cgroup *cgrp)
{
	return cgrp->nr_populated_csets;
}

/*
 * cgroup_scan: scan all descendant cgroups under root cgroup.
 *
 * 1. When the memory usage of the sub-cgroup falls below the <min> threshold,
 *    it will automatically fall back to using 4KB size; otherwise, it will
 *    use all mTHP sizes.
 * 2. When memory.pressure stall time of the sub-cgroup exceeds <threshold>,
 *    it will automatically fall back to using 4KB size; otherwise, it will
 *    use all mTHP sizes.
 *
 * Return 1 indicates termination of the iteration loop, and return 0 indicates
 * iteration to the next sub-cgroup.
 */
SEC("iter.s/cgroup")
int cgroup_scan(struct bpf_iter__cgroup *ctx)
{
	struct cgroup *cgrp = ctx->cgroup;
	struct mem_cgroup *memcg;
	struct mem_info *info;
	struct alert_event *e;
	unsigned long curr_stall;
	unsigned long curr_mem;
	unsigned long delta;

	if (!cgrp)
		return 1;

	if (!cgroup_has_tasks(cgrp))
		return 0;

	info = bpf_cgrp_storage_get(&cgrp_storage, cgrp, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!info)
		return 0;

	memcg = bpf_get_mem_cgroup(&cgrp->self);
	if (!memcg)
		return 0;

	bpf_cgroup_flush_stats(cgrp);
	curr_stall = bpf_cgroup_stall(cgrp, PSI_MEM_FULL);
	delta = curr_stall - info->stall;
	bpf_mem_cgroup_flush_stats(memcg);
	curr_mem = bpf_mem_cgroup_page_state(memcg, NR_ANON_MAPPED) +
		   bpf_mem_cgroup_page_state(memcg, NR_SHMEM);
	if (curr_mem < FROM_MB(configs.min_mem) || delta >= configs.threshold)
		info->order = 0;
	else
		info->order = PMD_ORDER;

	if (configs.debug) {
		e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
		if (e) {
			e->prev_stall = info->stall;
			e->curr_stall = curr_stall;
			e->delta = delta;
			e->mem = curr_mem;
			e->order = info->order;
			bpf_probe_read_kernel_str(e->name, sizeof(e->name),
						  cgrp->kn->name);
			bpf_ringbuf_submit(e, 0);
		}
	}

	info->stall = curr_stall;
	bpf_put_mem_cgroup(memcg);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
