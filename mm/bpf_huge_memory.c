// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Huge memory related BPF code
 *
 * Author: Vernon Yang <yanglincheng@kylinos.cn>
 */

#include <linux/bpf.h>
#include <linux/srcu.h>

/* Protects cgrp->mthp_ops pointer for read and write. */
DEFINE_SRCU(mthp_bpf_srcu);

unsigned long bpf_mthp_choose(struct mm_struct *mm, unsigned long orders)
{
	struct cgroup *cgrp;
	struct mem_cgroup *memcg;
	struct bpf_mthp_ops *ops;
	int idx;

	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg)
		return orders;

	cgrp = memcg->css.cgroup;
	ops = READ_ONCE(cgrp->mthp_ops);
	if (unlikely(ops)) {
		idx = srcu_read_lock(&mthp_bpf_srcu);
		if (ops->mthp_choose)
			orders = ops->mthp_choose(cgrp, orders);
		srcu_read_unlock(&mthp_bpf_srcu, idx);
	}

	mem_cgroup_put(memcg);

	return orders;
}

static int bpf_mthp_ops_btf_struct_access(struct bpf_verifier_log *log,
		const struct bpf_reg_state *reg, int off, int size)
{
	return -EACCES;
}

static bool bpf_mthp_ops_is_valid_access(int off, int size, enum bpf_access_type type,
		const struct bpf_prog *prog, struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

const struct bpf_verifier_ops bpf_mthp_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.btf_struct_access = bpf_mthp_ops_btf_struct_access,
	.is_valid_access = bpf_mthp_ops_is_valid_access,
};

static int bpf_mthp_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *st_link = (struct bpf_struct_ops_link *)link;
	struct bpf_mthp_ops *ops = kdata;
	struct cgroup *cgrp = st_link->cgroup;
	struct cgroup_subsys_state *pos;

	/* The link is not yet fully initialized, but cgroup should be set */
	if (!link)
		return -EOPNOTSUPP;

	cgroup_lock();
	css_for_each_descendant_pre(pos, &cgrp->self) {
		struct cgroup *child = pos->cgroup;

		if (READ_ONCE(child->mthp_ops)) {
			/* TODO
			 * Do not destroy the cgroup hierarchy property.
			 * If an eBPF program already exists in the sub-cgroup,
			 * trigger an error and clear the already set
			 * bpf_mthp_ops data.
			 */
			continue;
		}
		WRITE_ONCE(child->mthp_ops, ops);
	}
	cgroup_unlock();

	return 0;
}

static void bpf_mthp_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *st_link = (struct bpf_struct_ops_link *)link;
	struct bpf_mthp_ops *ops = kdata;
	struct cgroup *cgrp = st_link->cgroup;
	struct cgroup_subsys_state *pos;

	cgroup_lock();
	css_for_each_descendant_pre(pos, &cgrp->self) {
		struct cgroup *child = pos->cgroup;

		if (READ_ONCE(child->mthp_ops) == ops)
			WRITE_ONCE(child->mthp_ops, NULL);
	}
	cgroup_unlock();

	synchronize_srcu(&mthp_bpf_srcu);
}

static int bpf_mthp_ops_check_member(const struct btf_type *t,
				     const struct btf_member *member,
				     const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_mthp_ops, mthp_choose):
		break;
	default:
		return -EINVAL;
	}

	if (prog->sleepable)
		return -EINVAL;

	return 0;
}

static int bpf_mthp_ops_init_member(const struct btf_type *t,
				    const struct btf_member *member,
				    void *kdata, const void *udata)
{
	return 0;
}

static int bpf_mthp_ops_init(struct btf *btf)
{
	return 0;
}

static unsigned long cfi_mthp_choose(struct cgroup *cgrp, unsigned long orders)
{
	return 0;
}

static struct bpf_mthp_ops cfi_bpf_mthp_ops = {
	.mthp_choose = cfi_mthp_choose,
};

static struct bpf_struct_ops bso_bpf_mthp_ops = {
	.verifier_ops = &bpf_mthp_verifier_ops,
	.reg = bpf_mthp_ops_reg,
	.unreg = bpf_mthp_ops_unreg,
	.check_member = bpf_mthp_ops_check_member,
	.init_member = bpf_mthp_ops_init_member,
	.init = bpf_mthp_ops_init,
	.name = "bpf_mthp_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &cfi_bpf_mthp_ops,
};

static int __init bpf_huge_memory_init(void)
{
	int err;

	err = register_bpf_struct_ops(&bso_bpf_mthp_ops, bpf_mthp_ops);
	if (err)
		pr_warn("Registration of bpf_mthp_ops failed, err %d\n", err);

	return err;
}
late_initcall(bpf_huge_memory_init);
