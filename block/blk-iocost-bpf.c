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
static LIST_HEAD(iocost_bpf_lifecycle);

/*
 * One node per registered model.  refcount: 1 while registered
 * (dropped in .unreg) plus one per bound device (dropped in
 * iocost_bpf_model_put(), which pairs its bpf_struct_ops_get(), so the
 * kdata of an unregistered model stays alive while any device is still
 * bound to it).  The node sits on the lifecycle notify list exactly
 * while at least one device has the model bound.
 */
struct iocost_bpf_model {
	struct list_head	list;		/* name registry */
	struct list_head	lifecycle;	/* lifecycle notify list */
	const struct iocost_model_ops *ops;
	refcount_t		refs;
};

/*
 * Take a name and acquire a binding reference on the model it selects.
 * The registry is searched first; a model which is unregistered but
 * still bound to a device remains selectable by name until the last
 * device unbinds, so a coefficient-only write on such a device keeps
 * the model bound instead of failing with ENOENT.  The registry lock
 * is held across the lookup and bpf_struct_ops_get() so the model
 * cannot be unregistered in between.  Returns the ops or an ERR_PTR.
 */
const struct iocost_model_ops *iocost_bpf_model_get(const char *name)
{
	struct iocost_bpf_model *m;
	const struct iocost_model_ops *ops = ERR_PTR(-ENOENT);

	mutex_lock(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_models, list) {
		if (!strcmp(m->ops->name, name))
			goto found;
	}
	list_for_each_entry(m, &iocost_bpf_lifecycle, lifecycle) {
		if (!strcmp(m->ops->name, name))
			goto found;
	}
	mutex_unlock(&iocost_bpf_reg_lock);
	return ops;
found:
	if (bpf_struct_ops_get(m->ops)) {
		refcount_inc(&m->refs);
		/* first bind: join the notify list */
		if (refcount_read(&m->refs) == 2 &&
		    list_empty(&m->lifecycle))
			list_add(&m->lifecycle, &iocost_bpf_lifecycle);
		ops = m->ops;
	}
	mutex_unlock(&iocost_bpf_reg_lock);
	return ops;
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

/*
 * Lifecycle notifications walk the lifecycle list, which keeps a node
 * for as long as any device has the model bound, so an unregistered
 * but still-bound model keeps receiving blkcg online/offline.
 */
void iocost_notify_blkcg_online(struct blkcg *blkcg)
{
	struct iocost_bpf_model *m;

	guard(mutex)(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_lifecycle, lifecycle) {
		if (m->ops->blkcg_online)
			m->ops->blkcg_online(blkcg);
	}
}

void iocost_notify_blkcg_offline(struct blkcg *blkcg)
{
	struct iocost_bpf_model *m;

	guard(mutex)(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_lifecycle, lifecycle) {
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

/*
 * No iocost-specific helpers; bpf_base_func_proto already covers the
 * cgroup storage helpers under CONFIG_CGROUPS.
 */
static const struct bpf_func_proto *
bpf_iocost_get_func_proto(enum bpf_func_id func_id,
			  const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
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

/*
 * kvalue is zeroed at map allocation and function members are only
 * written when the BPF side provides a prog, so a model which did
 * not implement calc_cost leaves it NULL.  The dispatch would call
 * it on every bio, so reject it here.
 */
static int bpf_iocost_validate(void *kdata)
{
	struct iocost_model_ops *ops = kdata;

	if (!ops->calc_cost)
		return -EINVAL;
	/* "linear" is the builtin model; model=linear unbinds */
	if (!strcmp(ops->name, "linear"))
		return -EINVAL;
	return 0;
}

/*
 * The struct_ops core holds a reference on the map while the model is
 * registered, so kdata stays valid until .unreg returns; no extra
 * reference is needed here.
 */
static int bpf_iocost_reg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;
	struct iocost_bpf_model *m;
	int ret = 0;

	m = kzalloc_obj(struct iocost_bpf_model, GFP_KERNEL);
	if (!m)
		return -ENOMEM;
	refcount_set(&m->refs, 1);
	INIT_LIST_HEAD(&m->lifecycle);

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

	if (ret)
		kfree(m);
	return ret;
}

/*
 * Unregistering drops the registration reference.  If a device is
 * still bound, the binding references keep the node (and the kdata,
 * through their bpf_struct_ops_get()) alive and it keeps receiving
 * blkcg online/offline notifications; otherwise the node is freed.
 */
static void bpf_iocost_unreg(void *kdata, struct bpf_link *link)
{
	struct iocost_model_ops *ops = kdata;
	struct iocost_bpf_model *m;

	mutex_lock(&iocost_bpf_reg_lock);
	m = iocost_bpf_model_lookup(ops);
	if (m) {
		/*
		 * keep the linkage queryable so model_put() can tell a
		 * still-registered node (one ref held by the registry)
		 * from one kept alive only by device bindings
		 */
		list_del_init(&m->list);
		if (refcount_dec_and_test(&m->refs))
			kfree(m);
	}
	mutex_unlock(&iocost_bpf_reg_lock);
}

void iocost_bpf_model_put(const struct iocost_model_ops *ops)
{
	struct iocost_bpf_model *m;

	mutex_lock(&iocost_bpf_reg_lock);
	list_for_each_entry(m, &iocost_bpf_lifecycle, lifecycle) {
		if (m->ops == ops)
			break;
	}
	if (&m->lifecycle != &iocost_bpf_lifecycle) {
		bool freed = refcount_dec_and_test(&m->refs);

		/*
		 * leave the notify list with the last binding: refs is
		 * now zero (node freed) or the registry's single one
		 */
		if (freed || (!list_empty(&m->list) &&
			      refcount_read(&m->refs) == 1))
			list_del_init(&m->lifecycle);
		mutex_unlock(&iocost_bpf_reg_lock);
		bpf_struct_ops_put(ops);
		if (freed)
			kfree(m);
		return;
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

static void bpf_iocost_blkcg_online_stub(struct blkcg *blkcg) { }
static void bpf_iocost_blkcg_offline_stub(struct blkcg *blkcg) { }

static struct iocost_model_ops __bpf_ops_iocost_model_ops = {
	.calc_cost = bpf_iocost_calc_cost_stub,
	.blkcg_online = bpf_iocost_blkcg_online_stub,
	.blkcg_offline = bpf_iocost_blkcg_offline_stub,
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
