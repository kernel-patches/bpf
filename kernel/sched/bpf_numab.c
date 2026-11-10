// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Per-cgroup NUMA balancing mode
 *
 * A cgroup overrides the global state through its memcg. Task and folio
 * lookups walk the memcg chain; an opt-out binds the subtree, while the
 * remaining bits OR together.
 *
 * Author: Yafang Shao <laoar.shao@gmail.com>
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/numa_balancing.h>

DEFINE_STATIC_KEY_FALSE(numab_cgroup_mode_set);

/* Whether this memcg may still own a NUMA balancing request. */
static bool numab_memcg_active(struct mem_cgroup *memcg)
{
	unsigned int flags;

	if (mem_cgroup_is_root(memcg))
		return true;

	/* Take one snapshot so all three state bits describe the same moment. */
	flags = READ_ONCE(memcg->css.flags);

	return (flags & CSS_ONLINE) &&
	       !(flags & CSS_DYING) &&
	       (flags & CSS_VISIBLE);
}

/*
 * Combine the requests of @memcg and of every ancestor. A task chain
 * stops at an explicit opt-out: a task can never be forced into
 * balancing. A folio chain skips opt-outs instead (a memcg's DISABLED
 * request only speaks for its tasks, never for its memory) and keeps
 * collecting the remaining requests.
 */
static int numab_memcg_mode(struct mem_cgroup *memcg, bool folio_side)
{
	int req = 0;

	for (; memcg; memcg = parent_mem_cgroup(memcg)) {
		int mode;

		if (!numab_memcg_active(memcg))
			continue;

		/* Paired with WRITE_ONCE() under numab_mode_mutex. */
		mode = data_race(READ_ONCE(memcg->numab_mode));
		if (mode == NUMAB_FOLLOW_SYSTEM)
			continue;
		if (mode == NUMAB_DISABLED) {
			if (!folio_side)
				return NUMAB_DISABLED;
			continue;
		}
		req |= mode;
	}
	return req ?: NUMAB_FOLLOW_SYSTEM;
}

/*
 * The combined request for @p. Kernel threads have no user memory to
 * balance, so they make no request.  The walk needs no reference: the
 * memcg chain is RCU-protected, so rcu_read_lock() keeps it alive for
 * the whole walk.
 */
int task_numab_mode(struct task_struct *p)
{
	struct mem_cgroup *memcg;
	int mode;

	if (mem_cgroup_disabled() || !p->mm)
		return NUMAB_FOLLOW_SYSTEM;

	rcu_read_lock();
	memcg = mem_cgroup_from_task(p);
	mode = memcg ? numab_memcg_mode(memcg, false) : NUMAB_FOLLOW_SYSTEM;
	rcu_read_unlock();
	return mode;
}

/*
 * The combined request for @folio's owner. An uncharged folio makes no
 * request. A folio charged to a memcg whose cgroup the kfunc cannot
 * reach carries no request and follows the global state.
 */
int folio_numab_mode(struct folio *folio)
{
	struct mem_cgroup *memcg;
	int mode;

	if (mem_cgroup_disabled())
		return NUMAB_FOLLOW_SYSTEM;

	rcu_read_lock();
	memcg = folio_memcg(folio);
	mode = memcg ? numab_memcg_mode(memcg, true) : NUMAB_FOLLOW_SYSTEM;
	rcu_read_unlock();
	return mode;
}

static DEFINE_MUTEX(numab_mode_mutex);

/*
 * Reset the request when the memory controller is disabled, the memcg is
 * offlined or the memcg is pinned.  A memcg may be made visible again, so
 * it must start transparent.
 */
void numab_memcg_reset(struct mem_cgroup *memcg)
{
	mutex_lock(&numab_mode_mutex);
	if (memcg->numab_mode != NUMAB_FOLLOW_SYSTEM) {
		WRITE_ONCE(memcg->numab_mode, NUMAB_FOLLOW_SYSTEM);
		static_branch_dec(&numab_cgroup_mode_set);
	}
	mutex_unlock(&numab_mode_mutex);
}

__bpf_kfunc_start_defs();

/**
 * bpf_numab_set_mode() - Set the NUMA balancing mode of a cgroup's memcg.
 * @cgid: kernfs id of the cgroup whose memcg is updated
 * @mode: NUMAB_FOLLOW_SYSTEM to defer to the global sysctl state, or a
 *        NUMAB_* mode. The kernel reads the bits independently, the way
 *        kernel.numa_balancing reads them, so
 *        NUMAB_NORMAL|NUMAB_TIERING engages both modes. A
 *        NUMAB_DISABLED request only speaks for the memcg's tasks, never
 *        for its memory, which follows the remaining requests of its
 *        ancestors.
 *
 * The cgroup must have a visible, online memory cgroup; otherwise the
 * update is rejected.
 *
 * Return: 0 on success; %-EINVAL for a mode outside the domain;
 *         %-ENOENT for an id that resolves to no cgroup; %-EOPNOTSUPP
 *         for a cgroup without a visible, online memcg.
 */
__bpf_kfunc int bpf_numab_set_mode(u64 cgid, enum numab_mode mode)
{
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	int old;

	if (mode != NUMAB_FOLLOW_SYSTEM &&
	    (mode < 0 || mode > NUMAB_NORMAL_TIERING))
		return -EINVAL;

	cgrp = __cgroup_get_from_id(cgid);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	if (mem_cgroup_disabled()) {
		cgroup_put(cgrp);
		return -EOPNOTSUPP;
	}

	rcu_read_lock();
	css = cgroup_css(cgrp, &memory_cgrp_subsys);
	memcg = mem_cgroup_from_css(css);
	if (memcg && !mem_cgroup_tryget_online(memcg))
		memcg = NULL;
	rcu_read_unlock();

	if (!memcg) {
		cgroup_put(cgrp);
		return -EOPNOTSUPP;
	}

	mutex_lock(&numab_mode_mutex);
	if (!numab_memcg_active(memcg)) {
		mutex_unlock(&numab_mode_mutex);
		mem_cgroup_put(memcg);
		cgroup_put(cgrp);
		return -EOPNOTSUPP;
	}

	old = READ_ONCE(memcg->numab_mode);
	if (old == NUMAB_FOLLOW_SYSTEM && mode != NUMAB_FOLLOW_SYSTEM)
		static_branch_inc(&numab_cgroup_mode_set);
	else if (old != NUMAB_FOLLOW_SYSTEM && mode == NUMAB_FOLLOW_SYSTEM)
		static_branch_dec(&numab_cgroup_mode_set);
	WRITE_ONCE(memcg->numab_mode, (int)mode);
	mutex_unlock(&numab_mode_mutex);

	mem_cgroup_put(memcg);
	cgroup_put(cgrp);
	return 0;
}

/**
 * bpf_numab_get_mode() - Read the NUMA balancing mode that applies to a cgroup.
 * @cgid: kernfs id of the cgroup
 *
 * The combined task-side request of the cgroup's effective memcg and of
 * every ancestor: an opt-out wins, otherwise the requested bits OR
 * together, and the kernel reads them independently, as
 * kernel.numa_balancing does, so a combined
 * NUMAB_NORMAL|NUMAB_TIERING engages both modes. NUMAB_FOLLOW_SYSTEM
 * when nobody makes a request. If the cgroup
 * has no memcg, the nearest ancestor memcg is used. The folio-side view
 * stays internal to the kernel.
 *
 * Return: the combined mode, NUMAB_FOLLOW_SYSTEM (-1) included, or
 *         %-ENOENT for an id that resolves to no cgroup.
 */
__bpf_kfunc s64 bpf_numab_get_mode(u64 cgid)
{
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	s64 mode;

	cgrp = __cgroup_get_from_id(cgid);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	if (mem_cgroup_disabled()) {
		cgroup_put(cgrp);
		return NUMAB_FOLLOW_SYSTEM;
	}

	rcu_read_lock();
	memcg = mem_cgroup_from_css(cgroup_e_css(cgrp, &memory_cgrp_subsys));
	mode = memcg ? numab_memcg_mode(memcg, false) : NUMAB_FOLLOW_SYSTEM;
	rcu_read_unlock();

	cgroup_put(cgrp);
	return mode;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(numab_kfunc_ids)
BTF_ID_FLAGS(func, bpf_numab_set_mode, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_numab_get_mode)
BTF_KFUNCS_END(numab_kfunc_ids)

static const struct btf_kfunc_id_set numab_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &numab_kfunc_ids,
};

static int __init numab_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &numab_kfunc_set);
	if (ret)
		pr_warn("numab: failed to register kfuncs: %d\n", ret);
	return ret;
}
late_initcall(numab_kfunc_init);
