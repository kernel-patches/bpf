// SPDX-License-Identifier: GPL-2.0
/*
 * Cgroup BPF kfuncs
 *
 * Author: Ziyang Men <ziyang.meme@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>

#ifdef CONFIG_CGROUP_SCHED
#include "../sched/sched.h"
#endif

__bpf_kfunc_start_defs();

/**
 * bpf_cgroup_css - Get a reference to one controller's css
 * @cgrp: cgroup to look in
 * @ssid: controller ID
 *
 * The returned css must be released with bpf_css_release().
 *
 * Return: The referenced css, or NULL.
 */
__bpf_kfunc struct cgroup_subsys_state *
bpf_cgroup_css(struct cgroup *cgrp, int ssid)
{
	struct cgroup_subsys_state *css;

	if (unlikely(ssid < 0 || ssid >= CGROUP_SUBSYS_COUNT))
		return NULL;

	rcu_read_lock();
	css = rcu_dereference(cgrp->subsys[ssid]);
	if (css && !css_tryget(css))
		css = NULL;
	rcu_read_unlock();

	return css;
}

/**
 * bpf_css_release - Release a css reference
 * @css: css to release
 */
__bpf_kfunc void bpf_css_release(struct cgroup_subsys_state *css)
{
	css_put(css);
}

#ifdef CONFIG_CGROUP_SCHED
/**
 * bpf_css_to_task_group - Cast a CPU controller css to its task group
 * @css: CPU controller css
 *
 * Must be called under RCU. The kfunc gives BPF a typed task_group pointer.
 *
 * Return: The task group, or NULL if @css belongs to another controller.
 */
__bpf_kfunc struct task_group *
bpf_css_to_task_group(struct cgroup_subsys_state *css)
{
	if (unlikely(css->ss != &cpu_cgrp_subsys))
		return NULL;

	return container_of(css, struct task_group, css);
}
#endif /* CONFIG_CGROUP_SCHED */

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_cgroup_kfunc_ids)
BTF_ID_FLAGS(func, bpf_cgroup_css, KF_ACQUIRE | KF_RCU | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_css_release, KF_RELEASE)
#ifdef CONFIG_CGROUP_SCHED
BTF_ID_FLAGS(func, bpf_css_to_task_group,
	     KF_RCU | KF_RCU_PROTECTED | KF_RET_NULL)
#endif
BTF_KFUNCS_END(bpf_cgroup_kfunc_ids)

static const struct btf_kfunc_id_set bpf_cgroup_kfunc_set = {
	.owner		= THIS_MODULE,
	.set		= &bpf_cgroup_kfunc_ids,
};

static int __init bpf_cgroup_kfunc_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					&bpf_cgroup_kfunc_set);
	if (err)
		pr_warn("error while registering cgroup kfuncs: %d\n", err);

	return err;
}
late_initcall(bpf_cgroup_kfunc_init);
