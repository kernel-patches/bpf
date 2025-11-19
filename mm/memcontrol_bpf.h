/* SPDX-License-Identifier: GPL-2.0-or-later */
/* memcontrol_bpf.h - Memory Controller eBPF support
 *
 * Author: Hui Zhu <zhuhui@kylinos.cn>
 * Copyright (C) 2025 KylinSoft Corporation.
 */

#ifndef _LINUX_MEMCONTROL_BPF_H
#define _LINUX_MEMCONTROL_BPF_H

#ifdef CONFIG_MEMCG_BPF

struct try_charge_memcg {
	struct mem_cgroup *memcg;
	gfp_t gfp_mask;
	unsigned long nr_pages;
	struct mem_cgroup *mem_over_limit;
	unsigned int reclaim_options;
	bool charge_done;
};

struct memcg_ops {
	int (*try_charge_memcg)(struct try_charge_memcg *tcm);
	struct percpu_ref refcount;
	struct completion destroy_done;
};

extern struct memcg_ops __rcu *memcg_ops;
DECLARE_STATIC_KEY_FALSE(memcg_bpf_enable);

static inline struct memcg_ops *memcg_ops_get(void)
{
	struct memcg_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(memcg_ops);
	if (likely(ops)) {
		if (unlikely(!percpu_ref_tryget_live(&ops->refcount)))
			ops = NULL;
	}
	rcu_read_unlock();

	return ops;
}

static inline void memcg_ops_put(struct memcg_ops *ops)
{
	percpu_ref_put(&ops->refcount);
}

static inline unsigned long
bpf_try_charge_memcg(struct mem_cgroup *memcg,
		     gfp_t gfp_mask,
		     unsigned int nr_pages,
		     struct mem_cgroup *mem_over_limit,
		     unsigned int reclaim_options,
		     bool charge_done)
{
	struct memcg_ops *ops;
	struct try_charge_memcg tcm;
	int update_nr_pages;

	if (likely(!static_branch_unlikely(&memcg_bpf_enable)))
		goto out;

	ops = memcg_ops_get();
	if (unlikely(!ops))
		goto out;

	tcm.memcg = memcg;
	tcm.gfp_mask = gfp_mask;
	tcm.nr_pages = nr_pages;
	tcm.mem_over_limit = mem_over_limit;
	tcm.reclaim_options = reclaim_options;
	tcm.charge_done = charge_done;

	update_nr_pages = ops->try_charge_memcg(&tcm);

	memcg_ops_put(ops);

	if (update_nr_pages && !charge_done && tcm.nr_pages &&
	    tcm.nr_pages <= HPAGE_PMD_NR)
		nr_pages = tcm.nr_pages;

out:
	return nr_pages;
}

#else

#define bpf_try_charge_memcg(memcg, gfp_mask, nr_pages, \
			     mem_over_limit, reclaim_options, \
			     charge_done) \
			     ((void)memcg, \
			      (void)gfp_mask, \
			      nr_pages, \
			      (void)mem_over_limit, \
			      (void)reclaim_options, \
			      (void)charge_done)

#endif

#endif
