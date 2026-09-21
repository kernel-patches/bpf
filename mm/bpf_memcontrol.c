// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Memory Controller-related BPF kfuncs and auxiliary code
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/memcontrol.h>
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/bpf_memcontrol.h>
#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/sched.h>

#include "internal.h"

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
 * bpf_proactive_reclaim - proactively reclaim memory from a memory cgroup
 * @memcg: the target memory cgroup to reclaim from.
 * @size: the amount of memory to reclaim, in bytes, clamped to
 *        MEMCG_CHARGE_BATCH.
 * @swappiness: the reclaim swappiness, in the range [MIN_SWAPPINESS,
 *              MAX_SWAPPINESS], or one of the special modes: -1 to use
 *              the memcg's own swappiness, or SWAPPINESS_ANON_ONLY to
 *              reclaim only anon folios.
 *
 * Performs one proactive reclaim pass on @memcg, like a write to
 * memory.reclaim but without retrying until @size is reached. Call it
 * repeatedly to reclaim more than one batch.
 *
 * Only available to BPF_PROG_TYPE_SYSCALL, because other sleepable programs
 * may run with filesystem locks held, which the reclaim path can deadlock
 * on via filesystem shrinkers.
 *
 * Return: The amount of memory reclaimed, in bytes, or a negative error.
 */
__bpf_kfunc long bpf_proactive_reclaim(struct mem_cgroup *memcg,
				       unsigned long size,
				       int swappiness)
{
	unsigned long nr_reclaimed;
	unsigned long nr_pages;

	if (swappiness != -1 && swappiness != SWAPPINESS_ANON_ONLY) {
		if (swappiness < MIN_SWAPPINESS || swappiness > MAX_SWAPPINESS)
			return -EINVAL;
	}

	if (size < PAGE_SIZE)
		return -EINVAL;

	nr_pages = min(size / PAGE_SIZE, (unsigned long)MEMCG_CHARGE_BATCH);

	nr_reclaimed = try_to_free_mem_cgroup_pages(memcg, nr_pages, GFP_KERNEL,
						    MEMCG_RECLAIM_MAY_SWAP |
						    MEMCG_RECLAIM_PROACTIVE,
						    swappiness == -1 ? NULL : &swappiness);

	return nr_reclaimed * PAGE_SIZE;
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

BTF_KFUNCS_END(bpf_memcontrol_kfuncs)

BTF_KFUNCS_START(bpf_memcontrol_reclaim_kfuncs)
BTF_ID_FLAGS(func, bpf_proactive_reclaim, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_memcontrol_reclaim_kfuncs)

static const struct btf_kfunc_id_set bpf_memcontrol_kfunc_set = {
	.owner          = THIS_MODULE,
	.set            = &bpf_memcontrol_kfuncs,
};

static const struct btf_kfunc_id_set bpf_memcontrol_reclaim_kfunc_set = {
	.owner          = THIS_MODULE,
	.set            = &bpf_memcontrol_reclaim_kfuncs,
};

/*
 * bpf_memcg_ops: memcg policy attached to a cgroup.  A program returns a
 * request and the kernel acts on it.  Nothing here reclaims or sleeps.
 */

/*
 * CFI stubs.  These really run: a slot points at them while its policy is
 * being detached.  Return 0, the identity for the kernel's OR.
 */
static u32 high_policy_stub(const struct bpf_memcg_ctx *ctx)
{
	return BPF_MEMCG_HIGH_NO_OPINION;
}

static struct bpf_memcg_ops __bpf_memcg_ops = {
	.high_policy = high_policy_stub,
};

static const struct bpf_func_proto *
bpf_memcg_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	/*
	 * The base set is all a policy needs today, and none of it sleeps.
	 * Anything added here must be safe from the charge path.
	 */
	return bpf_base_func_proto(func_id, prog);
}

static bool bpf_memcg_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	/* The context is read-only. */
	if (type != BPF_READ)
		return false;

	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_memcg_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	/* Mandatory: the core calls it without a NULL check. */
	return 0;
}

static int bpf_memcg_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	/* Members run from the charge path, which cannot sleep. */
	if (prog->sleepable)
		return -EINVAL;

	return 0;
}

static int bpf_memcg_init(struct btf *btf)
{
	return 0;
}

static int bpf_memcg_validate(void *kdata)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_memcg_verifier_ops = {
	.get_func_proto		= bpf_memcg_get_func_proto,
	.is_valid_access	= bpf_memcg_is_valid_access,
};

static struct bpf_struct_ops bpf_memcg_ops_desc = {
	.verifier_ops	= &bpf_memcg_verifier_ops,
	.init		= bpf_memcg_init,
	.init_member	= bpf_memcg_init_member,
	.check_member	= bpf_memcg_check_member,
	.validate	= bpf_memcg_validate,
	.name		= "bpf_memcg_ops",
	.cgroup_atype	= CGROUP_MEMCG_OPS,
	.cfi_stubs	= &__bpf_memcg_ops,
	.owner		= THIS_MODULE,
	/*
	 * .reg/.unreg stay NULL: the cgroup layer does attach and detach, and
	 * registration fails if a cgroup_atype comes with either.
	 *
	 * .free_after_mult_rcu_gp stays false while no member sleeps.  A
	 * sleepable one would also need a tasks-trace RCU version of
	 * bpf_cgroup_struct_ops_foreach().
	 */
};

static void bpf_memcg_ctx_init(struct bpf_memcg_ctx *ctx,
			       struct mem_cgroup *memcg,
			       struct mem_cgroup *over_limit, gfp_t gfp_mask)
{
	ctx->memcg = memcg;
	ctx->memcg_over_limit = over_limit;
	ctx->task = current;
	ctx->cgroup_id = cgroup_id(memcg->css.cgroup);
	ctx->over_limit_cgroup_id = over_limit ?
		cgroup_id(over_limit->css.cgroup) : 0;
	ctx->nr_pages_over_high = current->memcg_nr_pages_over_high;
	ctx->gfp_flags = (__force u32)gfp_mask;
}

u32 bpf_memcg_high_policy(struct mem_cgroup *memcg,
			  struct mem_cgroup *over_limit, gfp_t gfp_mask)
{
	const struct bpf_prog_array_item *item;
	const struct bpf_memcg_ops *ops;
	struct bpf_memcg_ctx ctx;
	u32 acc = BPF_MEMCG_HIGH_NO_OPINION;
	struct cgroup *cgrp;

	if (!cgroup_bpf_enabled(CGROUP_MEMCG_OPS))
		return acc;

	/*
	 * Only the default hierarchy has a cgroup_bpf, and the static key is
	 * global, so one policy anywhere turns this on for v1 memcgs too.  A
	 * v1 memcg still cannot get here, because memory.high and swap.high
	 * are both v2-only and so it never builds the debt that leads to this
	 * call.  A hook on a path v1 can reach needs its own cgroup_on_dfl()
	 * test: a v1 cgroup has no effective array and an uninitialised
	 * cgrp->bpf.refcnt.
	 */
	cgrp = memcg->css.cgroup;

	/*
	 * A program can allocate and re-enter the charge path.  Skip the
	 * nested call.  This guards the callbacks only.
	 */
	if (current->in_bpf_memcg)
		return acc;
	current->in_bpf_memcg = 1;

	rcu_read_lock_dont_migrate();

	/*
	 * A memcg outlives its cgroup while it has charges, and
	 * cgroup_bpf_release() frees the arrays when the cgroup goes.
	 */
	if (!cgroup_bpf_tryget_live(cgrp))
		goto out;

	bpf_memcg_ctx_init(&ctx, memcg, over_limit, gfp_mask);

	bpf_cgroup_struct_ops_foreach(ops, item, cgrp, CGROUP_MEMCG_OPS) {
		if (ops->high_policy)
			acc |= ops->high_policy(&ctx) &
			       BPF_MEMCG_HIGH_VALID_MASK;
	}

	cgroup_bpf_put(cgrp);
out:
	rcu_read_unlock_migrate();

	current->in_bpf_memcg = 0;

	return acc;
}

static int __init bpf_memcg_ops_register(void)
{
	/*
	 * register_bpf_struct_ops() is a no-op without struct_ops support, so
	 * this needs no guard of its own.
	 */
	return register_bpf_struct_ops(&bpf_memcg_ops_desc, bpf_memcg_ops);
}

static int __init bpf_memcontrol_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					&bpf_memcontrol_kfunc_set);
	if (err) {
		pr_warn("error while registering bpf memcontrol kfuncs: %d", err);
		return err;
	}

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					&bpf_memcontrol_reclaim_kfunc_set);
	if (err) {
		pr_warn("error registering bpf reclaim kfuncs: %d\n", err);
		return err;
	}

	err = bpf_memcg_ops_register();
	if (err)
		pr_warn("error while registering bpf_memcg_ops: %d", err);

	return err;
}
late_initcall(bpf_memcontrol_init);
