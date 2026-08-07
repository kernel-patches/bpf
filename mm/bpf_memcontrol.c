// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Memory Controller-related BPF kfuncs and auxiliary code
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/memcontrol.h>
#include <linux/swap.h>
#include <linux/bpf.h>

__bpf_kfunc_start_defs();

/**
 * bpf_get_root_mem_cgroup - Returns a pointer to the root memory cgroup
 *
 * The function has KF_ACQUIRE semantics, even though the root memory
 * cgroup is never destroyed after being created and doesn't require
 * reference counting. And it's perfectly safe to pass it to
 * bpf_put_mem_cgroup()
 *
 * Return: A pointer to the root memory cgroup.
 */
__bpf_kfunc struct mem_cgroup *bpf_get_root_mem_cgroup(void)
{
	if (mem_cgroup_disabled())
		return NULL;

	/* css_get() is not needed */
	return root_mem_cgroup;
}

/**
 * bpf_get_mem_cgroup - Get a reference to a memory cgroup
 * @css: pointer to the css structure
 *
 * It's fine to pass a css which belongs to any cgroup controller,
 * e.g. unified hierarchy's main css.
 *
 * Implements KF_ACQUIRE semantics.
 *
 * Return: A pointer to a mem_cgroup structure after bumping
 * the corresponding css's reference counter.
 */
__bpf_kfunc struct mem_cgroup *
bpf_get_mem_cgroup(struct cgroup_subsys_state *css)
{
	struct mem_cgroup *memcg = NULL;
	bool rcu_unlock = false;

	if (mem_cgroup_disabled() || !root_mem_cgroup)
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

/**
 * bpf_put_mem_cgroup - Put a reference to a memory cgroup
 * @memcg: memory cgroup to release
 *
 * Releases a previously acquired memcg reference.
 * Implements KF_RELEASE semantics.
 */
__bpf_kfunc void bpf_put_mem_cgroup(struct mem_cgroup *memcg)
{
	css_put(&memcg->css);
}

/**
 * bpf_mem_cgroup_vm_events - Read memory cgroup's vm event counter
 * @memcg: memory cgroup
 * @event: event id
 *
 * Allows to read memory cgroup event counters.
 *
 * Return: The current value of the corresponding events counter.
 */
__bpf_kfunc unsigned long bpf_mem_cgroup_vm_events(struct mem_cgroup *memcg,
						   enum vm_event_item event)
{
	if (unlikely(!memcg_vm_event_item_valid(event)))
		return (unsigned long)-1;

	return memcg_events(memcg, event);
}

/**
 * bpf_mem_cgroup_usage - Read memory cgroup's usage
 * @memcg: memory cgroup
 *
 * Please, note that the root memory cgroup it special and is exempt
 * from the memory accounting. The returned value is a sum of sub-cgroup's
 * usages and it not reflecting the size of the root memory cgroup itself.
 * If you need to get an approximation, you can use root level statistics:
 * e.g. NR_FILE_PAGES + NR_ANON_MAPPED.
 *
 * Return: The current memory cgroup size in bytes.
 */
__bpf_kfunc unsigned long bpf_mem_cgroup_usage(struct mem_cgroup *memcg)
{
	return page_counter_read(&memcg->memory) * PAGE_SIZE;
}

/**
 * bpf_mem_cgroup_memory_events - Read memory cgroup's memory event value
 * @memcg: memory cgroup
 * @event: memory event id
 *
 * Return: The current value of the memory event counter.
 */
__bpf_kfunc unsigned long bpf_mem_cgroup_memory_events(struct mem_cgroup *memcg,
						       enum memcg_memory_event event)
{
	if (unlikely(event >= MEMCG_NR_MEMORY_EVENTS))
		return (unsigned long)-1;

	return atomic_long_read(&memcg->memory_events[event]);
}

/**
 * bpf_mem_cgroup_page_state - Read memory cgroup's page state counter
 * @memcg: memory cgroup
 * @idx: counter idx
 *
 * Allows to read memory cgroup statistics. The output is in bytes.
 *
 * Return: The value of the page state counter in bytes.
 */
__bpf_kfunc unsigned long bpf_mem_cgroup_page_state(struct mem_cgroup *memcg, int idx)
{
	if (unlikely(!memcg_stat_item_valid(idx)))
		return (unsigned long)-1;

	return memcg_page_state_output(memcg, idx);
}

/**
 * bpf_mem_cgroup_flush_stats - Flush memory cgroup's statistics
 * @memcg: memory cgroup
 *
 * Propagate memory cgroup's statistics up the cgroup tree.
 */
__bpf_kfunc void bpf_mem_cgroup_flush_stats(struct mem_cgroup *memcg)
{
	mem_cgroup_flush_stats(memcg);
}

/**
 * bpf_try_to_free_mem_cgroup_pages - attempt to reclaim pages from
 *                                    a memory cgroup
 * @memcg:           the target memory cgroup to reclaim from
 * @nr_pages:        the number of pages to reclaim
 * @gfp_mask:        GFP flags controlling the reclaim behavior
 * @reclaim_options: bitmask of MEMCG_RECLAIM_* flags to tune
 *                   reclaim strategy
 * @swappiness:      swappiness override value, or a sentinel to use
 *                   the default
 *
 * BPF-facing wrapper around try_to_free_mem_cgroup_pages() that
 * validates and translates the @swappiness argument before
 * delegating to the core reclaim path.
 *
 * The @swappiness parameter follows these semantics:
 *   - Values in [MIN_SWAPPINESS, SWAPPINESS_ANON_ONLY] are passed
 *     through as an explicit swappiness override.
 *   - Values below MIN_SWAPPINESS are treated as "use the system
 *     default"; the override pointer is set to NULL and the cgroup's
 *     own swappiness setting takes effect.
 *   - Values above SWAPPINESS_ANON_ONLY are rejected as invalid.
 *   - If @reclaim_options does not include MEMCG_RECLAIM_PROACTIVE,
 *     the @swappiness override is ignored entirely by the core
 *     reclaim path and the system default is used regardless.
 *
 * Swap usage during reclaim is gated on @reclaim_options: swap is
 * considered only when MEMCG_RECLAIM_MAY_SWAP is set.  Without this
 * flag, reclaim is restricted to file-backed pages regardless of the
 * @swappiness value or the cgroup's swappiness setting.
 *
 * Return:
 *   The number of pages actually reclaimed on success, or 0
 *   if @swappiness exceeds SWAPPINESS_ANON_ONLY.
 */
__bpf_kfunc unsigned long
bpf_try_to_free_mem_cgroup_pages(struct mem_cgroup *memcg,
				 unsigned long nr_pages,
				 gfp_t gfp_mask,
				 unsigned int reclaim_options,
				 int swappiness)
{
	int *swapiness_ptr;

	if (swappiness > SWAPPINESS_ANON_ONLY)
		return 0;
	else if (swappiness < MIN_SWAPPINESS)
		swapiness_ptr = NULL;
	else
		swapiness_ptr = &swappiness;

	return try_to_free_mem_cgroup_pages(memcg, nr_pages, gfp_mask,
					    reclaim_options, swapiness_ptr);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_memcontrol_kfuncs)
BTF_ID_FLAGS(func, bpf_get_root_mem_cgroup, KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_get_mem_cgroup, KF_ACQUIRE | KF_RET_NULL | KF_RCU)
BTF_ID_FLAGS(func, bpf_put_mem_cgroup, KF_RELEASE)

BTF_ID_FLAGS(func, bpf_mem_cgroup_vm_events)
BTF_ID_FLAGS(func, bpf_mem_cgroup_memory_events)
BTF_ID_FLAGS(func, bpf_mem_cgroup_usage)
BTF_ID_FLAGS(func, bpf_mem_cgroup_page_state)
BTF_ID_FLAGS(func, bpf_mem_cgroup_flush_stats, KF_SLEEPABLE)

BTF_ID_FLAGS(func, bpf_try_to_free_mem_cgroup_pages, KF_SLEEPABLE)

BTF_KFUNCS_END(bpf_memcontrol_kfuncs)

static const struct btf_kfunc_id_set bpf_memcontrol_kfunc_set = {
	.owner          = THIS_MODULE,
	.set            = &bpf_memcontrol_kfuncs,
};

static int __init bpf_memcontrol_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					&bpf_memcontrol_kfunc_set);
	if (err)
		pr_warn("error while registering bpf memcontrol kfuncs: %d", err);

	return err;
}
late_initcall(bpf_memcontrol_init);
