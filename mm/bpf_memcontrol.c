// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Memory Controller-related BPF kfuncs and auxiliary code
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/memcontrol.h>
#include <linux/bpf.h>

__bpf_kfunc_start_defs();

__bpf_kfunc struct mem_cgroup *bpf_get_root_mem_cgroup(void)
{
	/* css_get() is not needed */
	return root_mem_cgroup;
}

__bpf_kfunc struct mem_cgroup *
bpf_get_mem_cgroup(struct cgroup_subsys_state *css)
{
	struct mem_cgroup *memcg = NULL;
	bool rcu_unlock = false;

	if (!root_mem_cgroup)
		return NULL;

	if (root_mem_cgroup->css.ss != css->ss) {
		struct cgroup *cgroup = css->cgroup;
		int ssid = root_mem_cgroup->css.ss->id;

		rcu_read_lock();
		rcu_unlock = true;
		css = rcu_dereference_raw(cgroup->subsys[ssid]);
	}

	if (css && css_tryget(css))
		memcg = container_of(css, struct mem_cgroup, css);

	if (rcu_unlock)
		rcu_read_unlock();

	return memcg;
}

__bpf_kfunc void bpf_put_mem_cgroup(struct mem_cgroup *memcg)
{
	css_put(&memcg->css);
}

__bpf_kfunc unsigned long bpf_mem_cgroup_events(struct mem_cgroup *memcg, int event)
{

	if (event < 0 || event >= NR_VM_EVENT_ITEMS)
		return (unsigned long)-1;

	return memcg_events(memcg, event);
}

__bpf_kfunc unsigned long bpf_mem_cgroup_usage(struct mem_cgroup *memcg, bool swap)
{
	return mem_cgroup_usage(memcg, swap);
}

__bpf_kfunc unsigned long bpf_mem_cgroup_page_state(struct mem_cgroup *memcg, int idx)
{
	if (idx < 0 || idx >= MEMCG_NR_STAT)
		return (unsigned long)-1;

	return memcg_page_state(memcg, idx);
}

__bpf_kfunc void bpf_mem_cgroup_flush_stats(struct mem_cgroup *memcg)
{
	mem_cgroup_flush_stats(memcg);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_memcontrol_kfuncs)
BTF_ID_FLAGS(func, bpf_get_root_mem_cgroup, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_get_mem_cgroup, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_put_mem_cgroup, KF_RELEASE)

BTF_ID_FLAGS(func, bpf_mem_cgroup_events, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_mem_cgroup_usage, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_mem_cgroup_page_state, KF_TRUSTED_ARGS)
BTF_ID_FLAGS(func, bpf_mem_cgroup_flush_stats, KF_TRUSTED_ARGS)

BTF_KFUNCS_END(bpf_memcontrol_kfuncs)

static const struct btf_kfunc_id_set bpf_memcontrol_kfunc_set = {
	.owner          = THIS_MODULE,
	.set            = &bpf_memcontrol_kfuncs,
};

static int __init bpf_memcontrol_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					&bpf_memcontrol_kfunc_set);
	if (err)
		pr_warn("error while registering bpf memcontrol kfuncs: %d", err);

	return err;
}
late_initcall(bpf_memcontrol_init);
