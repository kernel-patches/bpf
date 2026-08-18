// SPDX-License-Identifier: GPL-2.0
/*
 * CPU controller BPF kfuncs
 *
 * Author: Ziyang Men <ziyang.meme@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>

#ifdef CONFIG_CGROUP_SCHED
struct task_group;

__bpf_kfunc_start_defs();

/**
 * bpf_css_to_task_group - Cast a CPU controller css to its task group
 * @css: CPU controller css
 *
 * Must be called under RCU.
 * A C cast does not give the verifier a task_group pointer. This kfunc
 * preserves the task_group and per-CPU types needed to read cfs_rq.
 *
 * Return: The task group, or NULL if @css belongs to another controller.
 */
__bpf_kfunc struct task_group *
bpf_css_to_task_group(struct cgroup_subsys_state *css)
{
	if (css->ss != &cpu_cgrp_subsys)
		return NULL;

	/* task_group embeds css at offset zero. */
	return (struct task_group *)css;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_cpu_cgroup_kfunc_ids)
BTF_ID_FLAGS(func, bpf_css_to_task_group,
	     KF_RCU | KF_RCU_PROTECTED | KF_RET_NULL)
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
#endif /* CONFIG_CGROUP_SCHED */
