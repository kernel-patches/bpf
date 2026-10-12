// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BPF-based per-cgroup NUMA balancing
 *
 * A bpf_numab_ops is attached to a cgroup via a struct_ops link. Whenever
 * the kernel is about to act on NUMA balancing, it runs the policies of the
 * matching cgroup and of every ancestor, and combines what they return: for
 * a task, the chain of the task's cgroup; for a folio, the chain of the
 * memcg the folio is charged to.
 *
 * Author: Yafang Shao <laoar.shao@gmail.com>
 */
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/bpf_numab.h>
#include <linux/bpf_verifier.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/sched.h>

/*
 * CFI stubs. These really run: a slot points at them while its policy is
 * being detached. Return BPF_NUMAB_GLOBAL, the identity for the
 * kernel's OR.
 */
static u32 numab_mode_stub(struct task_struct *p, struct folio *folio)
{
	return BPF_NUMAB_GLOBAL;
}

static struct bpf_numab_ops __bpf_numab_ops = {
	.numab_mode = numab_mode_stub,
};

static const struct bpf_func_proto *
bpf_numab_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool bpf_numab_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	if (type != BPF_READ)
		return false;
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static int bpf_numab_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	/* Mandatory: the core calls it without a NULL check. */
	return 0;
}

static int bpf_numab_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	/*
	 * Members also run from the scheduler tick and from load
	 * balancing, which hold the rq lock, so they can never sleep.
	 */
	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_numab_init(struct btf *btf)
{
	return 0;
}

static int bpf_numab_validate(void *kdata)
{
	struct bpf_numab_ops *ops = kdata;

	/*
	 * A policy which implements nothing has no effect but still makes
	 * every task pay for the enabled static key. Reject it.
	 */
	if (!ops->numab_mode)
		return -EINVAL;
	return 0;
}

static const struct bpf_verifier_ops bpf_numab_verifier_ops = {
	.get_func_proto		= bpf_numab_get_func_proto,
	.is_valid_access	= bpf_numab_is_valid_access,
};

static struct bpf_struct_ops bpf_numab_ops_desc = {
	.verifier_ops	= &bpf_numab_verifier_ops,
	.init		= bpf_numab_init,
	.init_member	= bpf_numab_init_member,
	.check_member	= bpf_numab_check_member,
	.validate	= bpf_numab_validate,
	.name		= "bpf_numab_ops",
	.cgroup_atype	= CGROUP_NUMAB_OPS,
	.cfi_stubs	= &__bpf_numab_ops,
	.owner		= THIS_MODULE,
};

/*
 * Run every numab_mode on the matching cgroup and its ancestors, and
 * return the combined request for the caller to act on. A task question
 * walks @p's cgroup; a folio question walks the chain of the memcg @folio
 * is charged to, and an uncharged folio makes no request.
 */
u32 bpf_numab_mode(struct task_struct *p, struct folio *folio)
{
	const struct bpf_prog_array_item *item;
	const struct bpf_numab_ops *ops;
	struct mem_cgroup *memcg;
	struct cgroup *cgrp;
	u32 acc = BPF_NUMAB_GLOBAL;

	if (!cgroup_bpf_enabled(CGROUP_NUMAB_OPS))
		return acc;

	/* Kernel threads have no user memory to balance. */
	if (p && !p->mm)
		return acc;

	rcu_read_lock();

	if (p) {
		cgrp = task_dfl_cgroup(p);
	} else {
		memcg = folio_memcg(folio);
		cgrp = memcg ? memcg->css.cgroup : NULL;
	}

	/*
	 * A cgroup outlives its attachments while it is live, and
	 * cgroup_bpf_release() frees the arrays when the cgroup goes.
	 */
	if (!cgrp || !percpu_ref_tryget_live_rcu(&cgrp->bpf.refcnt))
		goto out;

	bpf_cgroup_struct_ops_foreach(ops, item, cgrp, CGROUP_NUMAB_OPS) {
		if (ops->numab_mode)
			acc |= ops->numab_mode(p, folio) & BPF_NUMAB_VALID_MASK;
	}

	cgroup_bpf_put(cgrp);
out:
	rcu_read_unlock();
	return acc;
}

static int __init bpf_numab_ops_register(void)
{
	int err;

	err = register_bpf_struct_ops(&bpf_numab_ops_desc, bpf_numab_ops);
	if (err)
		pr_err("bpf_numab: Failed to register struct_ops (%d)\n", err);
	return err;
}
late_initcall(bpf_numab_ops_register);
