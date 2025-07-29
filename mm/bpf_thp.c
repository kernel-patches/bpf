// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/huge_mm.h>
#include <linux/khugepaged.h>

struct bpf_thp_ops {
	/**
	 * @get_suggested_order: Get the suggested highest THP order for allocation
	 * @mm: mm_struct associated with the THP allocation
	 * @tva_flags: TVA flags for current context
	 *             %TVA_IN_PF: Set when in page fault context
	 *             Other flags: Reserved for future use
	 * @order: The highest order being considered for this THP allocation.
	 *         %PUD_ORDER for PUD-mapped allocations
	 *         %PMD_ORDER for PMD-mapped allocations
	 *         %PMD_ORDER - 1 for mTHP allocations
	 *
	 * Rerurn: Suggested highest THP order to use for allocation. The returned
	 * order will never exceed the input @order value.
	 */
	int (*get_suggested_order)(struct mm_struct *mm, unsigned long tva_flags, int order) __rcu;
};

static struct bpf_thp_ops bpf_thp;
static DEFINE_SPINLOCK(thp_ops_lock);

int get_suggested_order(struct mm_struct *mm, unsigned long tva_flags, int order)
{
	int (*bpf_suggested_order)(struct mm_struct *mm, unsigned long tva_flags, int order);
	int suggested_order = order;

	/* No BPF program is attached */
	if (!test_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED,
		      &transparent_hugepage_flags))
		return suggested_order;

	rcu_read_lock();
	bpf_suggested_order = rcu_dereference(bpf_thp.get_suggested_order);
	if (!bpf_suggested_order)
		goto out;

	suggested_order = bpf_suggested_order(mm, tva_flags, order);
	if (suggested_order > order)
		suggested_order = order;

out:
	rcu_read_unlock();
	return suggested_order;
}

static bool bpf_thp_ops_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_func_proto *
bpf_thp_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops thp_bpf_verifier_ops = {
	.get_func_proto = bpf_thp_get_func_proto,
	.is_valid_access = bpf_thp_ops_is_valid_access,
};

static int bpf_thp_init(struct btf *btf)
{
	return 0;
}

static int bpf_thp_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	return 0;
}

static int bpf_thp_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *ops = kdata;

	spin_lock(&thp_ops_lock);
	if (test_and_set_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED,
		&transparent_hugepage_flags)) {
		spin_unlock(&thp_ops_lock);
		return -EBUSY;
	}
	WARN_ON_ONCE(bpf_thp.get_suggested_order);
	WRITE_ONCE(bpf_thp.get_suggested_order, ops->get_suggested_order);
	spin_unlock(&thp_ops_lock);
	return 0;
}

static void bpf_thp_unreg(void *kdata, struct bpf_link *link)
{
	spin_lock(&thp_ops_lock);
	clear_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED, &transparent_hugepage_flags);
	WARN_ON_ONCE(!bpf_thp.get_suggested_order);
	rcu_replace_pointer(bpf_thp.get_suggested_order, NULL, lockdep_is_held(&thp_ops_lock));
	spin_unlock(&thp_ops_lock);

	synchronize_rcu();
}

static int bpf_thp_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *ops = kdata;
	struct bpf_thp_ops *old = old_kdata;

	if (!ops || !old)
		return -EINVAL;

	spin_lock(&thp_ops_lock);
	if (!test_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED, &transparent_hugepage_flags))
		goto out;
	rcu_replace_pointer(bpf_thp.get_suggested_order, ops->get_suggested_order,
			    lockdep_is_held(&thp_ops_lock));

out:
	spin_unlock(&thp_ops_lock);
	synchronize_rcu();
	return 0;
}

static int bpf_thp_validate(void *kdata)
{
	struct bpf_thp_ops *ops = kdata;

	if (!ops->get_suggested_order) {
		pr_err("bpf_thp: required ops isn't implemented\n");
		return -EINVAL;
	}
	return 0;
}

static int suggested_order(struct mm_struct *mm, unsigned long vm_flags, int order)
{
	return order;
}

static struct bpf_thp_ops __bpf_thp_ops = {
	.get_suggested_order = suggested_order,
};

static struct bpf_struct_ops bpf_bpf_thp_ops = {
	.verifier_ops = &thp_bpf_verifier_ops,
	.init = bpf_thp_init,
	.init_member = bpf_thp_init_member,
	.reg = bpf_thp_reg,
	.unreg = bpf_thp_unreg,
	.update = bpf_thp_update,
	.validate = bpf_thp_validate,
	.cfi_stubs = &__bpf_thp_ops,
	.owner = THIS_MODULE,
	.name = "bpf_thp_ops",
};

__bpf_kfunc_start_defs();

/**
 * bpf_mm_get_mem_cgroup - Get the memory cgroup associated with a mm_struct.
 * @mm: The mm_struct to query
 *
 * The obtained mem_cgroup must be released by calling bpf_put_mem_cgroup().
 *
 * Return: The associated mem_cgroup on success, or NULL on failure. Note that
 * this function depends on CONFIG_MEMCG being enabled - it will always return
 * NULL if CONFIG_MEMCG is not configured.
 */
__bpf_kfunc struct mem_cgroup *bpf_mm_get_mem_cgroup(struct mm_struct *mm)
{
	return get_mem_cgroup_from_mm(mm);
}

/**
 * bpf_put_mem_cgroup - Release a memory cgroup obtained from bpf_mm_get_mem_cgroup()
 * @memcg: The memory cgroup to release
 */
__bpf_kfunc void bpf_put_mem_cgroup(struct mem_cgroup *memcg)
{
#ifdef CONFIG_MEMCG
	if (!memcg)
		return;
	css_put(&memcg->css);
#endif
}

/**
 * bpf_mm_get_task - Get the task struct associated with a mm_struct.
 * @mm: The mm_struct to query
 *
 * The obtained task_struct must be released by calling bpf_task_release().
 *
 * Return: The associated task_struct on success, or NULL on failure. Note that
 * this function depends on CONFIG_MEMCG being enabled - it will always return
 * NULL if CONFIG_MEMCG is not configured.
 */
__bpf_kfunc struct task_struct *bpf_mm_get_task(struct mm_struct *mm)
{
#ifdef CONFIG_MEMCG
	struct task_struct *task;

	if (!mm)
		return NULL;
	rcu_read_lock();
	task = rcu_dereference(mm->owner);
	if (!task)
		goto out;
	if (!refcount_inc_not_zero(&task->rcu_users))
		goto out;

	rcu_read_unlock();
	return task;

out:
	rcu_read_unlock();
#endif
	return NULL;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_thp_ids)
BTF_ID_FLAGS(func, bpf_mm_get_mem_cgroup, KF_TRUSTED_ARGS | KF_ACQUIRE | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_put_mem_cgroup, KF_RELEASE)
BTF_ID_FLAGS(func, bpf_mm_get_task, KF_TRUSTED_ARGS | KF_ACQUIRE | KF_RET_NULL)
BTF_KFUNCS_END(bpf_thp_ids)

static const struct btf_kfunc_id_set bpf_thp_set = {
	.owner = THIS_MODULE,
	.set = &bpf_thp_ids,
};

static int __init bpf_thp_ops_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS, &bpf_thp_set);
	if (err) {
		pr_err("bpf_thp: Failed to register kfunc sets (%d)\n", err);
		return err;
	}

	err = register_bpf_struct_ops(&bpf_bpf_thp_ops, bpf_thp_ops);
	if (err)
		pr_err("bpf_thp: Failed to register struct_ops (%d)\n", err);
	return err;
}
late_initcall(bpf_thp_ops_init);
