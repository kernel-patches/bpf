// SPDX-License-Identifier: GPL-2.0
/*
 * CPU Controller-related BPF kfuncs
 *
 * bpf_cpu_cgroup_cputime() is defined in rstat.c, which owns the locking it
 * needs, and only registered here.
 *
 * Author: Ziyang Men <ziyang.meme@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>

#include "cgroup-internal.h"

__bpf_kfunc_start_defs();

/**
 * bpf_cpu_cgroup_flush_stats - Flush a cgroup's base CPU-time statistics
 * @cgrp: cgroup to flush
 *
 * Propagate the cgroup's base CPU-time statistics up the cgroup tree.
 */
__bpf_kfunc void bpf_cpu_cgroup_flush_stats(struct cgroup *cgrp)
{
	css_rstat_flush(&cgrp->self);
}

/**
 * bpf_cpu_cgroup_throttled_self - Read a cgroup's own throttled time
 * @cgrp: cgroup to read from
 *
 * Return: The throttled time in microseconds, or 0 if config is off.
 */
__bpf_kfunc u64 bpf_cpu_cgroup_throttled_self(struct cgroup *cgrp)
{
/* cpu_cgrp_id needs the cpu controller, which CFS bandwidth depends on */
#ifdef CONFIG_CFS_BANDWIDTH
	struct cgroup_subsys_state *css;

	guard(rcu)();

	css = rcu_dereference(cgrp->subsys[cpu_cgrp_id]);
	if (!css)
		return 0;

	return div_u64(throttled_time_self((struct task_group *)css),
		       NSEC_PER_USEC);
#else
	return 0;
#endif
}

__bpf_kfunc_end_defs();

/* KF_SLEEPABLE keeps the rstat spinlock out of NMI */
BTF_KFUNCS_START(bpf_cpu_cgroup_kfunc_ids)
BTF_ID_FLAGS(func, bpf_cpu_cgroup_flush_stats, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_cpu_cgroup_cputime, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_cpu_cgroup_throttled_self)
BTF_KFUNCS_END(bpf_cpu_cgroup_kfunc_ids)

static const struct btf_kfunc_id_set bpf_cpu_cgroup_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &bpf_cpu_cgroup_kfunc_ids,
};

static int __init bpf_cpu_cgroup_kfunc_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					&bpf_cpu_cgroup_kfunc_set);
	if (err)
		pr_warn("error while registering cpu cgroup kfuncs: %d\n", err);

	return err;
}
late_initcall(bpf_cpu_cgroup_kfunc_init);
