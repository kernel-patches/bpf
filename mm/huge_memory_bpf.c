// SPDX-License-Identifier: GPL-2.0
/*
 * BPF-based THP policy management
 *
 * Author: Yafang Shao <laoar.shao@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/huge_mm.h>
#include <linux/khugepaged.h>

/**
 * @thp_order_fn_t: Get the suggested THP order from a BPF program for allocation
 * @vma: vm_area_struct associated with the THP allocation
 * @type: TVA type for current @vma
 * @orders: Bitmask of available THP orders for this allocation
 *
 * Return: The suggested THP order for allocation from the BPF program. Must be
 *         a valid, available order.
 */
typedef int thp_order_fn_t(struct vm_area_struct *vma,
			   enum tva_type type,
			   unsigned long orders);

struct bpf_thp_ops {
	thp_order_fn_t __rcu *thp_get_order;
};

static struct bpf_thp_ops bpf_thp;
static DEFINE_SPINLOCK(thp_ops_lock);

unsigned long bpf_hook_thp_get_orders(struct vm_area_struct *vma,
				      enum tva_type type,
				      unsigned long orders)
{
	thp_order_fn_t *bpf_hook_thp_get_order;
	int bpf_order;

	/* No BPF program is attached */
	if (!test_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED,
		      &transparent_hugepage_flags))
		return orders;

	rcu_read_lock();
	bpf_hook_thp_get_order = rcu_dereference(bpf_thp.thp_get_order);
	if (WARN_ON_ONCE(!bpf_hook_thp_get_order))
		goto out;

	bpf_order = bpf_hook_thp_get_order(vma, type, orders);
	orders &= BIT(bpf_order);

out:
	rcu_read_unlock();
	return orders;
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

static int bpf_thp_check_member(const struct btf_type *t,
				const struct btf_member *member,
				const struct bpf_prog *prog)
{
	/* The call site operates under RCU protection. */
	if (prog->sleepable)
		return -EINVAL;
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
	WARN_ON_ONCE(rcu_access_pointer(bpf_thp.thp_get_order));
	rcu_assign_pointer(bpf_thp.thp_get_order, ops->thp_get_order);
	spin_unlock(&thp_ops_lock);
	return 0;
}

static void bpf_thp_unreg(void *kdata, struct bpf_link *link)
{
	thp_order_fn_t *old_fn;

	spin_lock(&thp_ops_lock);
	clear_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED, &transparent_hugepage_flags);
	old_fn = rcu_replace_pointer(bpf_thp.thp_get_order, NULL,
				     lockdep_is_held(&thp_ops_lock));
	WARN_ON_ONCE(!old_fn);
	spin_unlock(&thp_ops_lock);

	synchronize_rcu();
}

static int bpf_thp_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	thp_order_fn_t *old_fn, *new_fn;
	struct bpf_thp_ops *old = old_kdata;
	struct bpf_thp_ops *ops = kdata;
	int ret = 0;

	if (!ops || !old)
		return -EINVAL;

	spin_lock(&thp_ops_lock);
	/* The prog has aleady been removed. */
	if (!test_bit(TRANSPARENT_HUGEPAGE_BPF_ATTACHED,
		      &transparent_hugepage_flags)) {
		ret = -ENOENT;
		goto out;
	}

	new_fn = rcu_dereference(ops->thp_get_order);
	old_fn = rcu_replace_pointer(bpf_thp.thp_get_order, new_fn,
				     lockdep_is_held(&thp_ops_lock));
	WARN_ON_ONCE(!old_fn || !new_fn);

out:
	spin_unlock(&thp_ops_lock);
	if (!ret)
		synchronize_rcu();
	return ret;
}

static int bpf_thp_validate(void *kdata)
{
	struct bpf_thp_ops *ops = kdata;

	if (!ops->thp_get_order) {
		pr_err("bpf_thp: required ops isn't implemented\n");
		return -EINVAL;
	}
	return 0;
}

static int bpf_thp_get_order(struct vm_area_struct *vma,
			     enum tva_type type,
			     unsigned long orders)
{
	return -1;
}

static struct bpf_thp_ops __bpf_thp_ops = {
	.thp_get_order = (thp_order_fn_t __rcu *)bpf_thp_get_order,
};

static struct bpf_struct_ops bpf_bpf_thp_ops = {
	.verifier_ops = &thp_bpf_verifier_ops,
	.init = bpf_thp_init,
	.check_member = bpf_thp_check_member,
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
	int err;

	err = register_bpf_struct_ops(&bpf_bpf_thp_ops, bpf_thp_ops);
	if (err)
		pr_err("bpf_thp: Failed to register struct_ops (%d)\n", err);
	return err;
}
late_initcall(bpf_thp_ops_init);
