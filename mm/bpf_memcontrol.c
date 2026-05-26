// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Memory Controller-related BPF kfuncs and auxiliary code
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/memcontrol.h>
#include <linux/bpf.h>

/* Protects memcg->bpf_ops pointer for read and write. */
DEFINE_SRCU(memcg_bpf_srcu);

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

static const struct btf_kfunc_id_set bpf_memcontrol_kfunc_set = {
	.owner          = THIS_MODULE,
	.set            = &bpf_memcontrol_kfuncs,
};

/**
 * memcontrol_bpf_online - Inherit BPF programs for a new online cgroup.
 * @memcg: The memory cgroup that is coming online.
 *
 * When a new memcg is brought online, it inherits the BPF programs
 * attached to its parent. This ensures consistent BPF-based memory
 * control policies throughout the cgroup hierarchy.
 *
 * After inheriting, if the BPF program has an online handler, it is
 * invoked for the new memcg.
 */
void memcontrol_bpf_online(struct mem_cgroup *memcg)
{
	struct memcg_bpf_ops *ops;
	struct mem_cgroup *parent_memcg;

	/* The root cgroup does not inherit from a parent. */
	if (mem_cgroup_is_root(memcg))
		return;

	/*
	 * Because only functions bpf_memcg_ops_reg and bpf_memcg_ops_unreg
	 * write to memcg->bpf_ops and memcg->bpf_ops_flags under the
	 * protection of cgroup_mutex, ensuring that cgroup_mutex is already
	 * locked here allows safe reading and writing of memcg->bpf_ops and
	 * memcg->bpf_ops_flags without needing to acquire a lock on
	 * memcg_bpf_srcu.
	 */
	lockdep_assert_held(&cgroup_mutex);

	parent_memcg = parent_mem_cgroup(memcg);

	/* Inherit the BPF program from the parent cgroup. */
	ops = READ_ONCE(parent_memcg->bpf_ops);
	if (!ops)
		return;
	WRITE_ONCE(memcg->bpf_ops, ops);
	memcg->bpf_ops_flags = parent_memcg->bpf_ops_flags;

	/*
	 * If the BPF program implements it, call the online handler to
	 * allow the program to perform setup tasks for the new cgroup.
	 */
	if (ops->handle_cgroup_online)
		ops->handle_cgroup_online(memcg);
}

/**
 * memcontrol_bpf_offline - Run BPF cleanup for an offline cgroup.
 * @memcg: The memory cgroup that is going offline.
 *
 * If a BPF program is attached and implements an offline handler,
 * it is invoked to perform cleanup tasks before the memcg goes
 * completely offline.
 */
void memcontrol_bpf_offline(struct mem_cgroup *memcg)
{
	struct memcg_bpf_ops *ops;

	/* Same locking rules as memcontrol_bpf_online(). */
	lockdep_assert_held(&cgroup_mutex);

	ops = READ_ONCE(memcg->bpf_ops);
	if (!ops || !ops->handle_cgroup_offline)
		return;

	ops->handle_cgroup_offline(memcg);
}

static int memcg_ops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	return -EACCES;
}

static bool memcg_ops_is_valid_access(int off, int size, enum bpf_access_type type,
	const struct bpf_prog *prog,
	struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

const struct bpf_verifier_ops bpf_memcg_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.btf_struct_access = memcg_ops_btf_struct_access,
	.is_valid_access = memcg_ops_is_valid_access,
};

static void cfi_handle_cgroup_online(struct mem_cgroup *memcg)
{
}

static void cfi_handle_cgroup_offline(struct mem_cgroup *memcg)
{
}

static bool
cfi_below_low(struct mem_cgroup *memcg, unsigned long elow,
	      unsigned long usage)
{
	return false;
}

static bool
cfi_below_min(struct mem_cgroup *memcg, unsigned long emin,
	      unsigned long usage)
{
	return false;
}

static unsigned int cfi_memcg_charged(struct mem_cgroup *memcg,
				      unsigned int nr_pages)
{
	return 0;
}

static void cfi_memcg_uncharged(struct mem_cgroup *memcg, unsigned int nr_pages)
{
}

static struct memcg_bpf_ops cfi_bpf_memcg_ops = {
	.handle_cgroup_online = cfi_handle_cgroup_online,
	.handle_cgroup_offline = cfi_handle_cgroup_offline,
	.below_low = cfi_below_low,
	.below_min = cfi_below_min,
	.memcg_charged = cfi_memcg_charged,
	.memcg_uncharged = cfi_memcg_uncharged,
};

static int bpf_memcg_ops_init(struct btf *btf)
{
	return 0;
}

static int bpf_memcg_ops_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct memcg_bpf_ops, handle_cgroup_online):
	case offsetof(struct memcg_bpf_ops, handle_cgroup_offline):
	case offsetof(struct memcg_bpf_ops, below_low):
	case offsetof(struct memcg_bpf_ops, below_min):
	case offsetof(struct memcg_bpf_ops, memcg_charged):
	case offsetof(struct memcg_bpf_ops, memcg_uncharged):
		break;
	default:
		return -EINVAL;
	}

	if (prog->sleepable)
		return -EINVAL;

	return 0;
}

static int bpf_memcg_ops_init_member(const struct btf_type *t,
				const struct btf_member *member,
				void *kdata, const void *udata)
{
	return 0;
}

static int bpf_memcg_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *ops_link;
	struct memcg_bpf_ops *ops = kdata, *old_ops;
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg, *iter;
	int err = 0;

	if (!link)
		return -EOPNOTSUPP;
	ops_link = container_of(link, struct bpf_struct_ops_link, link);
	if (!ops_link->cgroup)
		return -EINVAL;

	cgroup_lock();

	css = cgroup_e_css(ops_link->cgroup, &memory_cgrp_subsys);
	if (!css) {
		err = -EINVAL;
		goto unlock_out;
	}
	memcg = mem_cgroup_from_css(css);

	/*
	 * Check if memcg has bpf_ops and whether it is inherited from
	 * parent.
	 * If inherited and BPF_F_ALLOW_OVERRIDE is set, allow override.
	 */
	old_ops = READ_ONCE(memcg->bpf_ops);
	if (old_ops) {
		struct mem_cgroup *parent_memcg = parent_mem_cgroup(memcg);

		if (!parent_memcg ||
		    !(memcg->bpf_ops_flags & BPF_F_ALLOW_OVERRIDE) ||
		    READ_ONCE(parent_memcg->bpf_ops) != old_ops) {
			err = -EBUSY;
			goto unlock_out;
		}
	}

	/* Check for incompatible bpf_ops in descendants. */
	iter = NULL;
	while ((iter = mem_cgroup_iter(memcg, iter, NULL))) {
		struct memcg_bpf_ops *iter_ops = READ_ONCE(iter->bpf_ops);

		if (iter_ops && iter_ops != old_ops) {
			/* cannot override existing bpf_ops of sub-cgroup. */
			mem_cgroup_iter_break(memcg, iter);
			err = -EBUSY;
			goto unlock_out;
		}
	}

	iter = NULL;
	while ((iter = mem_cgroup_iter(memcg, iter, NULL))) {
		WRITE_ONCE(iter->bpf_ops, ops);
		iter->bpf_ops_flags = ops_link->flags;
	}

unlock_out:
	cgroup_unlock();
	return err;
}

/* Unregister the struct ops instance */
static void bpf_memcg_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *ops_link;
	struct memcg_bpf_ops *ops = kdata;
	struct cgroup_subsys_state *css;
	struct mem_cgroup *memcg;
	struct mem_cgroup *iter;
	struct memcg_bpf_ops *parent_bpf_ops = NULL;
	u32 parent_bpf_ops_flags = 0;

	if (!link)
		return;
	ops_link = container_of(link, struct bpf_struct_ops_link, link);
	if (!ops_link->cgroup)
		return;

	cgroup_lock();

	css = cgroup_e_css(ops_link->cgroup, &memory_cgrp_subsys);
	if (!css)
		goto unlock_out;
	memcg = mem_cgroup_from_css(css);

	/* Get the parent bpf_ops and bpf_ops_flags */
	iter = parent_mem_cgroup(memcg);
	if (iter) {
		parent_bpf_ops = READ_ONCE(iter->bpf_ops);
		parent_bpf_ops_flags = iter->bpf_ops_flags;
	}

	iter = NULL;
	while ((iter = mem_cgroup_iter(memcg, iter, NULL))) {
		if (READ_ONCE(iter->bpf_ops) == ops) {
			WRITE_ONCE(iter->bpf_ops, parent_bpf_ops);
			iter->bpf_ops_flags = parent_bpf_ops_flags;
		}
	}

unlock_out:
	cgroup_unlock();
	synchronize_srcu(&memcg_bpf_srcu);
}

static struct bpf_struct_ops bpf_memcg_bpf_ops = {
	.verifier_ops = &bpf_memcg_verifier_ops,
	.init = bpf_memcg_ops_init,
	.check_member = bpf_memcg_ops_check_member,
	.init_member = bpf_memcg_ops_init_member,
	.reg = bpf_memcg_ops_reg,
	.unreg = bpf_memcg_ops_unreg,
	.name = "memcg_bpf_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &cfi_bpf_memcg_ops,
};

static int __init bpf_memcontrol_init(void)
{
	int err, err2;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
					&bpf_memcontrol_kfunc_set);
	if (err)
		pr_warn("error while registering bpf memcontrol kfuncs: %d", err);

	err2 = register_bpf_struct_ops(&bpf_memcg_bpf_ops, memcg_bpf_ops);
	if (err2)
		pr_warn("error while registering memcontrol bpf ops: %d\n",
			err2);

	return err ? err : err2;
}
late_initcall(bpf_memcontrol_init);
