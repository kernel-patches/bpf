// SPDX-License-Identifier: GPL-2.0
/*
 * blk-iocost: BPF struct_ops plumbing for pluggable cost models.
 *
 * Registers the "iocost_model_ops" struct_ops type and maintains the
 * name registry of registered models.  A registered model is bound to
 * a device through io.cost.model; see include/linux/blk-iocost.h.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/blk-iocost.h>

static DEFINE_MUTEX(iocost_bpf_reg_lock);
static LIST_HEAD(iocost_bpf_models);

/*
 * The registry holds a bpf_struct_ops_get() reference obtained in .reg;
 * .unreg drops it, so the kdata of an unregistered model stays alive
 * while any device is still bound to it.
 */
struct iocost_bpf_model {
	struct list_head	list;
	const struct iocost_model_ops *ops;
};

/*
 * Look up a registered model by name and acquire a reference on it.
 * The registry lock is held across lookup and bpf_struct_ops_get() so
 * the model cannot be unregistered in between.
 */
int iocost_bpf_model_get(const char *name,
			 const struct iocost_model_ops **opsp)
{
	struct iocost_bpf_model *m;
	int ret = -ENOENT;

	mutex_lock(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_models, list) {
		if (!strcmp(m->ops->name, name)) {
			if (bpf_struct_ops_get(m->ops)) {
				*opsp = m->ops;
				ret = 0;
			}
			break;
		}
	}
	mutex_unlock(&iocost_bpf_reg_lock);
	return ret;
}

void iocost_bpf_model_put(const struct iocost_model_ops *ops)
{
	bpf_struct_ops_put(ops);
}

static struct iocost_bpf_model *
iocost_bpf_model_lookup(const struct iocost_model_ops *ops)
{
	struct iocost_bpf_model *m;

	list_for_each_entry(m, &iocost_bpf_models, list) {
		if (m->ops == ops)
			return m;
	}
	return NULL;
}

void iocost_notify_blkcg_online(struct blkcg *blkcg)
{
	struct iocost_bpf_model *m;

	guard(mutex)(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_models, list) {
		if (m->ops->blkcg_online)
			m->ops->blkcg_online(blkcg);
	}
}

void iocost_notify_blkcg_offline(struct blkcg *blkcg)
{
	struct iocost_bpf_model *m;

	guard(mutex)(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_models, list) {
		if (m->ops->blkcg_offline)
			m->ops->blkcg_offline(blkcg);
	}
}

static int bpf_iocost_model_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "iocost_model_ops", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	return 0;
}

static bool bpf_iocost_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       const struct bpf_prog *prog,
				       struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_func_proto *
bpf_iocost_get_func_proto(enum bpf_func_id func_id,
			  const struct bpf_prog *prog)
{
	switch (func_id) {
#ifdef CONFIG_CGROUPS
	case BPF_FUNC_cgrp_storage_get:
		return &bpf_cgrp_storage_get_proto;
#endif
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static int bpf_iocost_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	/* calc_cost() is called with RCU read lock held */
	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_iocost_init_member(const struct btf_type *t,
				  const struct btf_member *member,
				  void *kdata, const void *udata)
{
	struct iocost_model_ops *ops = kdata;
	const struct iocost_model_ops *uops = udata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct iocost_model_ops, name):
		if (bpf_obj_name_cpy(ops->name, uops->name,
				     sizeof(ops->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

static int bpf_iocost_validate(void *kdata)
{
	struct iocost_model_ops *ops = kdata;

	return ops->calc_cost ? 0 : -EINVAL;
}

static int bpf_iocost_reg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;
	struct iocost_bpf_model *m;
	int ret = 0;

	if (!bpf_struct_ops_get(ops))
		return -ENOENT;

	m = kzalloc(sizeof(*m), GFP_KERNEL);
	if (!m) {
		bpf_struct_ops_put(ops);
		return -ENOMEM;
	}

	mutex_lock(&iocost_bpf_reg_lock);
	{
		struct iocost_bpf_model *other;

		list_for_each_entry(other, &iocost_bpf_models, list) {
			if (!strcmp(other->ops->name, ops->name)) {
				ret = -EEXIST;
				break;
			}
		}
	}
	if (!ret) {
		m->ops = ops;
		list_add(&m->list, &iocost_bpf_models);
	}
	mutex_unlock(&iocost_bpf_reg_lock);

	if (ret) {
		bpf_struct_ops_put(ops);
		kfree(m);
	}
	return ret;
}

static void bpf_iocost_unreg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;
	struct iocost_bpf_model *m;

	mutex_lock(&iocost_bpf_reg_lock);
	m = iocost_bpf_model_lookup(ops);
	if (m) {
		list_del(&m->list);
		bpf_struct_ops_put(ops);
		kfree(m);
	}
	mutex_unlock(&iocost_bpf_reg_lock);
}

static const struct bpf_verifier_ops bpf_iocost_verifier_ops = {
	.get_func_proto = bpf_iocost_get_func_proto,
	.is_valid_access = bpf_iocost_is_valid_access,
};

static u64 bpf_iocost_calc_cost_stub(u64 opf, u64 nbytes, u64 sector,
				     struct blkcg *blkcg, u64 flags)
{
	return 0;
}

static struct iocost_model_ops __bpf_ops_iocost_model_ops = {
	.calc_cost = bpf_iocost_calc_cost_stub,
};

static struct bpf_struct_ops bpf_iocost_model_ops = {
	.verifier_ops = &bpf_iocost_verifier_ops,
	.init = bpf_iocost_model_init,
	.check_member = bpf_iocost_check_member,
	.init_member = bpf_iocost_init_member,
	.validate = bpf_iocost_validate,
	.reg = bpf_iocost_reg,
	.unreg = bpf_iocost_unreg,
	.name = "iocost_model_ops",
	.cfi_stubs = &__bpf_ops_iocost_model_ops,
	.owner = THIS_MODULE,
};

static int __init bpf_iocost_init(void)
{
	return register_bpf_struct_ops(&bpf_iocost_model_ops, iocost_model_ops);
}
late_initcall(bpf_iocost_init);
