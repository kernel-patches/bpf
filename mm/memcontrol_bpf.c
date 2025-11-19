// SPDX-License-Identifier: GPL-2.0
/*
 * Memory Controller eBPF support
 *
 * Author: Hui Zhu <zhuhui@kylinos.cn>
 * Copyright (C) 2025 KylinSoft Corporation.
 */

#include <linux/cgroup-defs.h>
#include <linux/page_counter.h>
#include <linux/memcontrol.h>
#include <linux/cgroup.h>
#include <linux/rcupdate.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/module.h>
#include "memcontrol_bpf.h"

struct memcg_ops __rcu *memcg_ops;
DEFINE_STATIC_KEY_FALSE(memcg_bpf_enable);

static void memcg_ops_release(struct percpu_ref *ref)
{
	struct memcg_ops *ops = container_of(ref,
		struct memcg_ops, refcount);

	/* Signal destruction completion */
	complete(&ops->destroy_done);
}

static int memcg_ops_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	size_t end;

	switch (off) {
	case offsetof(struct try_charge_memcg, nr_pages):
		end = offsetofend(struct try_charge_memcg, nr_pages);
		break;
	default:
		return -EACCES;
	}

	if (off + size > end)
		return -EACCES;

	return 0;
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

static int cfi_try_charge_memcg(struct try_charge_memcg *tcm)
{
	return -EINVAL;
}

static struct memcg_ops cfi_bpf_memcg_ops = {
	.try_charge_memcg = cfi_try_charge_memcg,
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
	case offsetof(struct memcg_ops, try_charge_memcg):
	case offsetof(struct memcg_ops, refcount):
	case offsetof(struct memcg_ops, destroy_done):
		break;
	default:
		if (prog->sleepable)
			return -EINVAL;
	}

	return 0;
}

static int default_try_charge_memcg(struct try_charge_memcg *tcm)
{
	return 0;
}

static int bpf_memcg_ops_init_member(const struct btf_type *t,
				const struct btf_member *member,
				void *kdata, const void *udata)
{
	struct memcg_ops *ops = (struct memcg_ops *)kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;
	int ret;

	if (moff == offsetof(struct memcg_ops, refcount)) {
		ret = percpu_ref_init(&ops->refcount, memcg_ops_release, 0, GFP_KERNEL);
		if (ret) {
			pr_err("Failed to percpu_ref_init: %d\n", ret);
			return ret;
		}

		init_completion(&ops->destroy_done);

		if (!ops->try_charge_memcg)
			ops->try_charge_memcg = default_try_charge_memcg;
	}

	return 0;
}

static int bpf_memcg_ops_reg(void *kdata, struct bpf_link *link)
{
	struct memcg_ops *new_ops, *old_ops;

	/*
	 * Check if ops already exists.
	 * just get old_ops but not keep lock because
	 * caller has locked st_map->lock.
	 */
	rcu_read_lock();
	old_ops = rcu_dereference(memcg_ops);
	rcu_read_unlock();
	if (old_ops)
		return -EEXIST;

	new_ops = kdata;

	/* Atomically set ops pointer (should be NULL at this point) */
	old_ops = rcu_replace_pointer(memcg_ops, new_ops, true);
	WARN_ON(old_ops);

	static_branch_enable(&memcg_bpf_enable);

	return 0;
}

/* Unregister the struct ops instance */
static void bpf_memcg_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct memcg_ops *ops;

	static_branch_disable(&memcg_bpf_enable);

	/* Not lock same with bpf_memcg_ops_reg. */
	ops = rcu_replace_pointer(memcg_ops, NULL, true);
	if (ops) {
		synchronize_rcu();

		percpu_ref_kill(&ops->refcount);
		wait_for_completion(&ops->destroy_done);

		percpu_ref_exit(&ops->refcount);
	}
}

static struct bpf_struct_ops bpf_memcg_ops = {
	.verifier_ops = &bpf_memcg_verifier_ops,
	.init = bpf_memcg_ops_init,
	.check_member = bpf_memcg_ops_check_member,
	.init_member = bpf_memcg_ops_init_member,
	.reg = bpf_memcg_ops_reg,
	.unreg = bpf_memcg_ops_unreg,
	.name = "memcg_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &cfi_bpf_memcg_ops,
};

static int __init memcontrol_bpf_init(void)
{
	int err;

	RCU_INIT_POINTER(memcg_ops, NULL);

	err = register_bpf_struct_ops(&bpf_memcg_ops, memcg_ops);
	if (err) {
		pr_warn("error while registering bpf memcg_ops: %d\n", err);
		return err;
	}

	pr_info("bpf memcg_ops registered successfully\n");
	return 0;
}
late_initcall(memcontrol_bpf_init);
