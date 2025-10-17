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
 * Return: The suggested THP order for allocation from the BPF program.
 *         Returns a negative value to preserve the original available @orders,
 *         which is useful in specific cases—for example, when only a particular
 *         @type is handled and others are ignored.
 */
typedef int thp_order_fn_t(struct vm_area_struct *vma,
			   enum tva_type type,
			   unsigned long orders);

struct bpf_thp_ops {
	pid_t pid; /* The pid to attach */
	thp_order_fn_t *thp_get_order;

	/* private */
	/* The list of mm_struct objects managed by this BPF-THP instance. */
	struct list_head mm_list;
};

static DEFINE_SPINLOCK(thp_ops_lock);
static struct bpf_thp_ops __rcu *bpf_thp_global; /* global mode */

static unsigned long
bpf_hook_thp_get_orders_global(struct vm_area_struct *vma,
			       enum tva_type type,
			       unsigned long orders)
{
	static struct bpf_thp_ops *bpf_thp;
	int bpf_order;

	rcu_read_lock();
	bpf_thp = rcu_dereference(bpf_thp_global);
	if (!bpf_thp || !bpf_thp->thp_get_order)
		goto out;

	bpf_order = bpf_thp->thp_get_order(vma, type, orders);
	if (bpf_order < 0)
		goto out;
	orders &= BIT(bpf_order);

out:
	rcu_read_unlock();
	return orders;
}

unsigned long bpf_hook_thp_get_orders(struct vm_area_struct *vma,
				      enum tva_type type,
				      unsigned long orders)
{
	struct mm_struct *mm = vma->vm_mm;
	struct bpf_thp_ops *bpf_thp;
	int bpf_order;

	if (!mm)
		return orders;

	/* Global BPF-THP takes precedence over per-process BPF-THP. */
	if (rcu_access_pointer(bpf_thp_global))
		return bpf_hook_thp_get_orders_global(vma, type, orders);

	rcu_read_lock();
	bpf_thp = rcu_dereference(mm->bpf_mm.bpf_thp);
	if (!bpf_thp || !bpf_thp->thp_get_order)
		goto out;

	bpf_order = bpf_thp->thp_get_order(vma, type, orders);
	if (bpf_order < 0)
		goto out;
	orders &= BIT(bpf_order);

out:
	rcu_read_unlock();
	return orders;
}

void bpf_thp_exit_mm(struct mm_struct *mm)
{
	if (!rcu_access_pointer(mm->bpf_mm.bpf_thp))
		return;

	spin_lock(&thp_ops_lock);
	if (!rcu_access_pointer(mm->bpf_mm.bpf_thp)) {
		spin_unlock(&thp_ops_lock);
		return;
	}
	list_del(&mm->bpf_mm.bpf_thp_list);
	RCU_INIT_POINTER(mm->bpf_mm.bpf_thp, NULL);
	spin_unlock(&thp_ops_lock);

}

void bpf_thp_retain_mm(struct mm_struct *mm, struct mm_struct *old_mm)
{
	struct bpf_thp_ops *bpf_thp;

	if (!old_mm || !rcu_access_pointer(old_mm->bpf_mm.bpf_thp))
		return;

	spin_lock(&thp_ops_lock);
	bpf_thp = rcu_dereference_protected(old_mm->bpf_mm.bpf_thp,
					    lockdep_is_held(&thp_ops_lock));
	if (!bpf_thp) {
		spin_unlock(&thp_ops_lock);
		return;
	}

	/* The new mm_struct is under initialization. */
	RCU_INIT_POINTER(mm->bpf_mm.bpf_thp, bpf_thp);

	/* The old mm_struct is being destroyed. */
	RCU_INIT_POINTER(old_mm->bpf_mm.bpf_thp, NULL);
	list_replace(&old_mm->bpf_mm.bpf_thp_list, &mm->bpf_mm.bpf_thp_list);
	spin_unlock(&thp_ops_lock);
}

void bpf_thp_fork(struct mm_struct *mm, struct mm_struct *old_mm)
{
	struct bpf_thp_ops *bpf_thp;

	if (!rcu_access_pointer(old_mm->bpf_mm.bpf_thp))
		return;

	spin_lock(&thp_ops_lock);
	bpf_thp = rcu_dereference_protected(old_mm->bpf_mm.bpf_thp,
					    lockdep_is_held(&thp_ops_lock));
	if (!bpf_thp) {
		spin_unlock(&thp_ops_lock);
		return;
	}

	/* The new mm_struct is under initialization. */
	RCU_INIT_POINTER(mm->bpf_mm.bpf_thp, bpf_thp);

	list_add_tail(&mm->bpf_mm.bpf_thp_list, &bpf_thp->mm_list);
	spin_unlock(&thp_ops_lock);
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
	const struct bpf_thp_ops *ubpf_thp;
	struct bpf_thp_ops *kbpf_thp;
	u32 moff;

	ubpf_thp = (const struct bpf_thp_ops *)udata;
	kbpf_thp = (struct bpf_thp_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct bpf_thp_ops, pid):
		/* bpf_struct_ops only handles func ptrs and zero-ed members.
		 * Return 1 to bypass the default handler.
		 */
		kbpf_thp->pid = ubpf_thp->pid;
		return 1;
	}
	return 0;
}

static int bpf_thp_reg_gloabl(void *kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *ops = kdata;

	/* Protect the global pointer bpf_thp_global from concurrent writes. */
	spin_lock(&thp_ops_lock);
	/* Only one instance is allowed. */
	if (rcu_access_pointer(bpf_thp_global)) {
		spin_unlock(&thp_ops_lock);
		return -EBUSY;
	}

	rcu_assign_pointer(bpf_thp_global, ops);
	spin_unlock(&thp_ops_lock);
	return 0;
}

static int bpf_thp_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *bpf_thp = kdata;
	struct list_head *mm_list;
	struct task_struct *p;
	struct mm_struct *mm;
	int err = 0;
	pid_t pid;

	pid = bpf_thp->pid;

	/* Fallback to global mode if pid is not set. */
	if (!pid)
		return bpf_thp_reg_gloabl(kdata, link);

	p = find_get_task_by_vpid(pid);
	if (!p)
		return -ESRCH;

	if (p->flags & PF_EXITING) {
		put_task_struct(p);
		return -ESRCH;
	}

	mm = get_task_mm(p);
	put_task_struct(p);
	if (!mm)
		return -EINVAL;

	/* To prevent conflicts, use this lock when multiple BPF-THP instances
	 * might register this task simultaneously.
	 */
	spin_lock(&thp_ops_lock);
	/* Each process is exclusively managed by a single BPF-THP.
	 * Global mode disables per-process instances.
	 */
	if (rcu_access_pointer(mm->bpf_mm.bpf_thp) || rcu_access_pointer(bpf_thp_global)) {
		err = -EBUSY;
		goto out;
	}
	rcu_assign_pointer(mm->bpf_mm.bpf_thp, bpf_thp);

	mm_list = &bpf_thp->mm_list;
	INIT_LIST_HEAD(mm_list);
	list_add_tail(&mm->bpf_mm.bpf_thp_list, mm_list);

out:
	spin_unlock(&thp_ops_lock);
	mmput(mm);
	return err;
}

static void bpf_thp_unreg_global(void *kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *bpf_thp;

	spin_lock(&thp_ops_lock);
	if (!rcu_access_pointer(bpf_thp_global)) {
		spin_unlock(&thp_ops_lock);
		return;
	}

	bpf_thp = rcu_replace_pointer(bpf_thp_global, NULL,
				      lockdep_is_held(&thp_ops_lock));
	WARN_ON_ONCE(!bpf_thp);
	spin_unlock(&thp_ops_lock);

	synchronize_rcu();
}

static void bpf_thp_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *bpf_thp = kdata;
	struct bpf_mm_ops *bpf_mm;
	struct list_head *pos, *n;

	if (!bpf_thp->pid)
		return bpf_thp_unreg_global(kdata, link);

	spin_lock(&thp_ops_lock);
	list_for_each_safe(pos, n, &bpf_thp->mm_list) {
		bpf_mm = list_entry(pos, struct bpf_mm_ops, bpf_thp_list);
		WARN_ON_ONCE(!bpf_mm);
		rcu_replace_pointer(bpf_mm->bpf_thp, NULL, lockdep_is_held(&thp_ops_lock));
		list_del(pos);
	}
	spin_unlock(&thp_ops_lock);

	synchronize_rcu();
}

static int bpf_thp_update_global(void *kdata, void *old_kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *old_bpf_thp = old_kdata;
	struct bpf_thp_ops *bpf_thp = kdata;
	struct bpf_thp_ops *old_global;

	if (!old_bpf_thp || !bpf_thp)
		return -EINVAL;

	spin_lock(&thp_ops_lock);
	/* BPF-THP global instance has already been removed. */
	if (!rcu_access_pointer(bpf_thp_global)) {
		spin_unlock(&thp_ops_lock);
		return -ENOENT;
	}

	old_global = rcu_replace_pointer(bpf_thp_global, bpf_thp,
					 lockdep_is_held(&thp_ops_lock));
	WARN_ON_ONCE(!old_global);
	spin_unlock(&thp_ops_lock);

	synchronize_rcu();
	return 0;
}

static int bpf_thp_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	struct bpf_thp_ops *old_bpf_thp = old_kdata;
	struct bpf_thp_ops *bpf_thp = kdata;
	struct bpf_mm_ops *bpf_mm;
	struct list_head *pos, *n;

	/* Updates are confined to instances of the same scope:
	 * global to global, process-local to process-local.
	 */
	if (!!old_bpf_thp->pid != !!bpf_thp->pid)
		return -EINVAL;

	if (!old_bpf_thp->pid)
		return bpf_thp_update_global(kdata, old_kdata, link);

	INIT_LIST_HEAD(&bpf_thp->mm_list);

	/* Could be optimized to a per-instance lock if this lock becomes a bottleneck. */
	spin_lock(&thp_ops_lock);
	list_for_each_safe(pos, n, &old_bpf_thp->mm_list) {
		bpf_mm = list_entry(pos, struct bpf_mm_ops, bpf_thp_list);
		WARN_ON_ONCE(!bpf_mm);
		rcu_replace_pointer(bpf_mm->bpf_thp, bpf_thp, lockdep_is_held(&thp_ops_lock));
		list_del(pos);
		list_add_tail(&bpf_mm->bpf_thp_list, &bpf_thp->mm_list);
	}
	spin_unlock(&thp_ops_lock);

	synchronize_rcu();
	return 0;
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
	.thp_get_order = (thp_order_fn_t *)bpf_thp_get_order,
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
