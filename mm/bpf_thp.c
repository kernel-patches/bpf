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

static int __init bpf_thp_ops_init(void)
{
	int err = register_bpf_struct_ops(&bpf_bpf_thp_ops, bpf_thp_ops);

	if (err)
		pr_err("bpf_thp: Failed to register struct_ops (%d)\n", err);
	return err;
}
late_initcall(bpf_thp_ops_init);
