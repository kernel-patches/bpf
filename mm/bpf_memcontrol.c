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

/*
 * Reclaim must not recurse. try_to_free_mem_cgroup_pages() unconditionally
 * overwrites current->reclaim_state on entry and resets it to NULL on exit.
 * So invoking it from an in-flight reclaim would clobber the outer reclaim
 * state and corrupt its accounting.
 *
 * The guard is PF_MEMALLOC. Every reclaim entry point marks the current
 * task with it for the whole reclaim window: try_to_free_mem_cgroup_pages()
 * and __perform_reclaim() do so via memalloc_noreclaim_save(), and kswapd
 * keeps it set for its entire lifetime. A hook inside the reclaim path
 * (shrink_node, shrink_slab, ...) executes in the context of the
 * reclaiming task, where current->flags already carries the flag. The page
 * allocator, the memcg charging path and node_reclaim() rely on the same
 * flag to avoid reclaim recursion.
 *
 * In try_to_free_mem_cgroup_pages(), reclaim_state is set slightly before
 * PF_MEMALLOC, with only a tracepoint in between, which a sleepable BPF
 * program cannot attach to.
 * Also, PF_MEMALLOC is set in some non-reclaim contexts (e.g. direct compaction
 * and vmalloc), where the kfunc conservatively refuses to reclaim as well.
 */
static bool bpf_in_reclaim_context(void)
{
	return current->flags & PF_MEMALLOC;
}

/*
 * Shared implementation of the proactive reclaim kfuncs: performs one
 * reclaim pass on @memcg with @nr_pages as the goal, allowing swap, and
 * @swappiness as the anon/file balance override (NULL to follow the
 * cgroup's own swappiness setting).
 */
static unsigned long
bpf_proactive_reclaim_pages(struct mem_cgroup *memcg, unsigned long nr_pages,
			    int *swappiness)
{
	if (!nr_pages || unlikely(bpf_in_reclaim_context()))
		return 0;

	return try_to_free_mem_cgroup_pages(memcg, nr_pages, GFP_KERNEL,
					    MEMCG_RECLAIM_MAY_SWAP |
					    MEMCG_RECLAIM_PROACTIVE,
					    swappiness);
}

/**
 * bpf_proactive_reclaim - proactively reclaim memory from a memory
 *                         cgroup
 * @memcg: the target memory cgroup to reclaim from
 * @size:  the amount of memory to reclaim, in bytes
 *
 * Trigger one proactive reclaim pass on @memcg, similar to a write to
 * the memory.reclaim cgroup file: pages are reclaimed according to the
 * cgroup's own swappiness setting and swap is allowed. Note that,
 * unlike memory.reclaim, this does not retry until @size is reached;
 * callers can invoke it again if needed.
 *
 * Return:
 *   The number of pages actually reclaimed, or 0 if @size is smaller
 *   than a page or the calling task is already in a reclaim/freeing
 *   context (PF_MEMALLOC).
 */
__bpf_kfunc unsigned long bpf_proactive_reclaim(struct mem_cgroup *memcg,
						unsigned long size)
{
	return bpf_proactive_reclaim_pages(memcg, size / PAGE_SIZE, NULL);
}

/**
 * bpf_proactive_reclaim_swappiness - proactively reclaim memory from a
 *                                    memory cgroup with an explicit
 *                                    swappiness
 * @memcg:      the target memory cgroup to reclaim from
 * @size:       the amount of memory to reclaim, in bytes
 * @swappiness: swappiness override for this reclaim pass
 *
 * Same as bpf_proactive_reclaim(), except that the anon/file reclaim
 * balance is controlled by @swappiness instead of the cgroup's
 * swappiness setting. Valid values are [MIN_SWAPPINESS, MAX_SWAPPINESS]
 * and SWAPPINESS_ANON_ONLY, which restricts reclaim to anon folios.
 *
 * Return:
 *   The number of pages actually reclaimed, or 0 if @size is smaller
 *   than a page, @swappiness is out of range, or the calling task is
 *   already in a reclaim/freeing context (PF_MEMALLOC).
 */
__bpf_kfunc unsigned long
bpf_proactive_reclaim_swappiness(struct mem_cgroup *memcg, unsigned long size,
				 int swappiness)
{
	if (swappiness < MIN_SWAPPINESS || swappiness > SWAPPINESS_ANON_ONLY)
		return 0;

	return bpf_proactive_reclaim_pages(memcg, size / PAGE_SIZE,
					   &swappiness);
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

BTF_ID_FLAGS(func, bpf_proactive_reclaim, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_proactive_reclaim_swappiness, KF_SLEEPABLE)

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
