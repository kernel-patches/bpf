// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Per-cgroup NUMA balancing mode
 *
 * A cgroup can override the global NUMA balancing state for the tasks it
 * runs and the memory it owns: the bpf_numab_set_mode() kfunc stores a
 * requested mode in struct cgroup, and the NUMA balancing hot paths combine
 * the requests of the matching cgroup and of every ancestor. For a task
 * that is the chain of the task's cgroup; for a folio it is the chain of
 * the memcg the folio is charged to. An opt-out wins and binds the
 * subtree; otherwise the requested bits OR together and are read
 * independently, the way the sysctl reads them.
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

/*
 * Set while any cgroup overrides the global state: the hot paths skip the
 * consult entirely while it stays off. Counted per cgroup that makes a
 * request, so the key goes off again once the last request is gone.
 */
DEFINE_STATIC_KEY_FALSE(numab_cgroup_mode_set);

/*
 * Combine the requests of @cgrp and of every ancestor. A task chain
 * stops at an explicit opt-out: a task can never be forced into
 * balancing. A folio chain skips opt-outs instead (a cgroup's DISABLED
 * request only speaks for its tasks, never for its memory) and keeps
 * collecting the remaining requests.
 */
static int numab_cgroup_mode(struct cgroup *cgrp, bool folio_side)
{
	int req = 0;

	for (; cgrp; cgrp = cgroup_parent(cgrp)) {
		/* data_race: the field is written under numab_mode_mutex. */
		int mode = data_race(READ_ONCE(cgrp->numab_mode));

		if (mode == NUMAB_FOLLOW_SYSTEM)
			continue;
		if (mode == NUMA_BALANCING_DISABLED) {
			if (!folio_side)
				return NUMA_BALANCING_DISABLED;
			continue;
		}
		req |= mode;
	}
	return req ?: NUMAB_FOLLOW_SYSTEM;
}

/*
 * The combined request for @p. Kernel threads have no user memory to
 * balance, so they make no request. The walk needs no reference: the
 * cgroup chain is freed only after an RCU grace period, so
 * rcu_read_lock() keeps it alive for the whole walk.
 */
int task_numab_mode(struct task_struct *p)
{
	int mode;

	if (!p->mm)
		return NUMAB_FOLLOW_SYSTEM;

	rcu_read_lock();
	mode = numab_cgroup_mode(task_dfl_cgroup(p), false);
	rcu_read_unlock();
	return mode;
}

/*
 * The combined request for @folio's owner. An uncharged folio makes no
 * request. A folio charged to a v1 memcg resolves to a cgroup chain the
 * kfunc cannot reach, so it carries no request either and the folio
 * follows the global state.
 */
int folio_numab_mode(struct folio *folio)
{
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	int mode;

	rcu_read_lock();
	memcg = folio_memcg(folio);
	cgrp = memcg ? memcg->css.cgroup : NULL;
	mode = cgrp ? numab_cgroup_mode(cgrp, true) : NUMAB_FOLLOW_SYSTEM;
	rcu_read_unlock();
	return mode;
}

/*
 * Serialize the static key accounting: without it, two concurrent
 * setters on the same cgroup could both count one transition, and the
 * key would stay on after the last request is gone.
 */
static DEFINE_MUTEX(numab_mode_mutex);

__bpf_kfunc_start_defs();

/**
 * bpf_numab_set_mode() - Set the NUMA balancing mode requested for a cgroup.
 * @cgid: kernfs id of the cgroup, e.g. from name_to_handle_at() on its
 * directory or from bpf_get_current_cgroup_id()
 * @mode: NUMAB_FOLLOW_SYSTEM to defer to the global sysctl state, or a
 * NUMA_BALANCING_* bitmask. The kernel reads the bits independently,
 * the way kernel.numa_balancing reads them, so NORMAL|TIERING engages
 * both modes. A DISABLED request only speaks for the cgroup's tasks,
 * never for its memory, which follows the remaining requests of its
 * ancestors.
 *
 * Return: 0 on success, -EINVAL for a mode outside the domain, -ENOENT
 * for an id that resolves to no cgroup.
 */
__bpf_kfunc int bpf_numab_set_mode(u64 cgid, s64 mode)
{
	struct cgroup *cgrp;
	int old;

	if (mode != NUMAB_FOLLOW_SYSTEM &&
	    (mode < 0 || mode > (NUMA_BALANCING_NORMAL |
				 NUMA_BALANCING_MEMORY_TIERING)))
		return -EINVAL;

	cgrp = __cgroup_get_from_id(cgid);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	mutex_lock(&numab_mode_mutex);
	old = cgrp->numab_mode;
	if (old == NUMAB_FOLLOW_SYSTEM && mode != NUMAB_FOLLOW_SYSTEM)
		static_branch_inc(&numab_cgroup_mode_set);
	else if (old != NUMAB_FOLLOW_SYSTEM && mode == NUMAB_FOLLOW_SYSTEM)
		static_branch_dec(&numab_cgroup_mode_set);
	WRITE_ONCE(cgrp->numab_mode, (int)mode);
	mutex_unlock(&numab_mode_mutex);
	cgroup_put(cgrp);
	return 0;
}

/**
 * bpf_numab_get_mode() - Read the NUMA balancing mode that applies to a cgroup.
 * @cgid: kernfs id of the cgroup
 *
 * The combined request of the cgroup and of every ancestor: an opt-out
 * wins, otherwise the requested bits OR together, and the kernel reads
 * them independently, as kernel.numa_balancing does, so a combined
 * NORMAL|TIERING engages both modes. NUMAB_FOLLOW_SYSTEM when nobody
 * makes a request. This is the view of the cgroup's tasks: its memory
 * follows the remaining requests of the chain when it opts out, and
 * that folio-side view stays internal to the kernel.
 *
 * Return: the combined mode, NUMAB_FOLLOW_SYSTEM (-1) included, or
 * -ENOENT for an id that resolves to no cgroup.
 */
__bpf_kfunc s64 bpf_numab_get_mode(u64 cgid)
{
	struct cgroup *cgrp;
	s64 mode;

	cgrp = __cgroup_get_from_id(cgid);
	if (IS_ERR(cgrp))
		return PTR_ERR(cgrp);

	rcu_read_lock();
	mode = numab_cgroup_mode(cgrp, false);
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
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &numab_kfunc_set);
}
late_initcall(numab_kfunc_init);
