// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BPF PSI event handlers
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/bpf_psi.h>
#include <linux/cgroup-defs.h>

struct bpf_struct_ops bpf_psi_bpf_ops;
static struct workqueue_struct *bpf_psi_wq;

static DEFINE_MUTEX(bpf_psi_lock);
static LIST_HEAD(bpf_psi_notify_list);
static DEFINE_STATIC_KEY_FALSE(bpf_psi_notify_key);

static struct bpf_psi *bpf_psi_create(struct bpf_psi_ops *ops)
{
	struct bpf_psi *bpf_psi;

	bpf_psi = kzalloc(sizeof(*bpf_psi), GFP_KERNEL);
	if (!bpf_psi)
		return NULL;

	if (init_srcu_struct(&bpf_psi->srcu)) {
		kfree(bpf_psi);
		return NULL;
	}

	spin_lock_init(&bpf_psi->lock);
	bpf_psi->ops = ops;
	INIT_LIST_HEAD(&bpf_psi->triggers);
	ops->bpf_psi = bpf_psi;

	if (ops->handle_cgroup_online) {
		mutex_lock(&bpf_psi_lock);
		list_add(&bpf_psi->node, &bpf_psi_notify_list);
		mutex_unlock(&bpf_psi_lock);
		static_branch_inc(&bpf_psi_notify_key);
	} else {
		INIT_LIST_HEAD(&bpf_psi->node);
	}

	return bpf_psi;
}

static void bpf_psi_handle_event_fn(struct work_struct *work)
{
	struct psi_trigger *t;
	struct bpf_psi *bpf_psi;
	int idx;

	t = container_of(work, struct psi_trigger, bpf_work);
	bpf_psi = READ_ONCE(t->bpf_psi);

	if (likely(bpf_psi)) {
		idx = srcu_read_lock(&bpf_psi->srcu);
		bpf_psi->ops->handle_psi_event(t);
		srcu_read_unlock(&bpf_psi->srcu, idx);
	}
}

void bpf_psi_add_trigger(struct psi_trigger *t,
			 const struct psi_trigger_params *params)
{
	t->bpf_psi = params->bpf_psi;
	t->pinned = false;
	INIT_WORK(&t->bpf_work, bpf_psi_handle_event_fn);

	spin_lock(&t->bpf_psi->lock);
	list_add(&t->bpf_psi_node, &t->bpf_psi->triggers);
	spin_unlock(&t->bpf_psi->lock);

	spin_lock(&t->group->bpf_triggers_lock);
	list_add(&t->bpf_group_node, &t->group->bpf_triggers);
	spin_unlock(&t->group->bpf_triggers_lock);
}

void bpf_psi_remove_trigger(struct psi_trigger *t)
{
	spin_lock(&t->group->bpf_triggers_lock);
	list_del(&t->bpf_group_node);
	spin_unlock(&t->group->bpf_triggers_lock);

	spin_lock(&t->bpf_psi->lock);
	list_del(&t->bpf_psi_node);
	spin_unlock(&t->bpf_psi->lock);
}

#ifdef CONFIG_CGROUPS
void bpf_psi_cgroup_online(struct cgroup *cgroup)
{
	struct bpf_psi *bpf_psi;
	int idx;

	if (!static_branch_likely(&bpf_psi_notify_key))
		return;

	mutex_lock(&bpf_psi_lock);
	list_for_each_entry(bpf_psi, &bpf_psi_notify_list, node) {
		idx = srcu_read_lock(&bpf_psi->srcu);
		if (bpf_psi->ops->handle_cgroup_online)
			bpf_psi->ops->handle_cgroup_online(cgroup_id(cgroup));
		srcu_read_unlock(&bpf_psi->srcu, idx);
	}
	mutex_unlock(&bpf_psi_lock);
}

void bpf_psi_cgroup_offline(struct cgroup *cgroup)
{
	struct psi_group *group = cgroup->psi;
	u64 cgrp_id = cgroup_id(cgroup);
	struct psi_trigger *t, *p;
	struct bpf_psi *bpf_psi;
	LIST_HEAD(to_destroy);
	int idx;

	spin_lock(&group->bpf_triggers_lock);
	list_for_each_entry_safe(t, p, &group->bpf_triggers, bpf_group_node) {
		if (!t->pinned) {
			t->pinned = true;
			list_move(&t->bpf_group_node, &to_destroy);
		}
	}
	spin_unlock(&group->bpf_triggers_lock);

	list_for_each_entry_safe(t, p, &to_destroy, bpf_group_node) {
		bpf_psi = READ_ONCE(t->bpf_psi);

		idx = srcu_read_lock(&bpf_psi->srcu);
		if (bpf_psi->ops->handle_cgroup_offline)
			bpf_psi->ops->handle_cgroup_offline(cgrp_id);
		srcu_read_unlock(&bpf_psi->srcu, idx);

		spin_lock(&bpf_psi->lock);
		list_del(&t->bpf_psi_node);
		spin_unlock(&bpf_psi->lock);

		WRITE_ONCE(t->bpf_psi, NULL);
		flush_workqueue(bpf_psi_wq);
		synchronize_srcu(&bpf_psi->srcu);
		psi_trigger_destroy(t);
	}
}
#endif

void bpf_psi_handle_event(struct psi_trigger *t)
{
	queue_work(bpf_psi_wq, &t->bpf_work);
}

/* BPF struct ops */

static int __bpf_psi_init(struct bpf_psi *bpf_psi) { return 0; }
static void __bpf_psi_handle_psi_event(struct psi_trigger *t) {}
static void __bpf_psi_handle_cgroup_online(u64 cgroup_id) {}
static void __bpf_psi_handle_cgroup_offline(u64 cgroup_id) {}

static struct bpf_psi_ops __bpf_psi_ops = {
	.init = __bpf_psi_init,
	.handle_psi_event = __bpf_psi_handle_psi_event,
	.handle_cgroup_online = __bpf_psi_handle_cgroup_online,
	.handle_cgroup_offline = __bpf_psi_handle_cgroup_offline,
};

static const struct bpf_func_proto *
bpf_psi_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return tracing_prog_func_proto(func_id, prog);
}

static bool bpf_psi_ops_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_psi_verifier_ops = {
	.get_func_proto = bpf_psi_func_proto,
	.is_valid_access = bpf_psi_ops_is_valid_access,
};

__bpf_kfunc_start_defs();

/**
 * bpf_psi_create_trigger - Create a PSI trigger
 * @bpf_psi: bpf_psi struct to attach the trigger to
 * @cgroup_id: cgroup Id to attach the trigger; 0 for system-wide scope
 * @resource: resource to monitor (PSI_MEM, PSI_IO, etc) and the full bit.
 * @threshold_us: threshold in us
 * @window_us: window in us
 *
 * Creates a PSI trigger and attached is to bpf_psi. The trigger will be
 * active unless bpf struct ops is unloaded or the corresponding cgroup
 * is deleted.
 *
 * Resource's most significant bit encodes whether "some" or "full"
 * PSI state should be tracked.
 *
 * Returns 0 on success and the error code on failure.
 */
__bpf_kfunc int bpf_psi_create_trigger(struct bpf_psi *bpf_psi,
				       u64 cgroup_id, u32 resource,
				       u32 threshold_us, u32 window_us)
{
	enum psi_res res = resource & ~BPF_PSI_FULL;
	bool full = resource & BPF_PSI_FULL;
	struct psi_trigger_params params;
	struct cgroup *cgroup __maybe_unused = NULL;
	struct psi_group *group;
	struct psi_trigger *t;
	int ret = 0;

	if (res >= NR_PSI_RESOURCES)
		return -EINVAL;

	if (IS_ENABLED(CONFIG_CGROUPS) && cgroup_id) {
		cgroup = cgroup_get_from_id(cgroup_id);
		if (IS_ERR_OR_NULL(cgroup))
			return PTR_ERR(cgroup);

		group = cgroup_psi(cgroup);
	} else {
		group = &psi_system;
	}

	params.type = PSI_BPF;
	params.bpf_psi = bpf_psi;
	params.privileged = capable(CAP_SYS_RESOURCE);
	params.res = res;
	params.full = full;
	params.threshold_us = threshold_us;
	params.window_us = window_us;

	t = psi_trigger_create(group, &params);
	if (IS_ERR(t))
		ret = PTR_ERR(t);
	else
		t->cgroup_id = cgroup_id;

#ifdef CONFIG_CGROUPS
	if (cgroup)
		cgroup_put(cgroup);
#endif

	return ret;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_psi_kfuncs)
BTF_ID_FLAGS(func, bpf_psi_create_trigger, KF_TRUSTED_ARGS)
BTF_KFUNCS_END(bpf_psi_kfuncs)

static int bpf_psi_kfunc_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	if (btf_id_set8_contains(&bpf_psi_kfuncs, kfunc_id) &&
	    prog->aux->st_ops != &bpf_psi_bpf_ops)
		return -EACCES;

	return 0;
}

static const struct btf_kfunc_id_set bpf_psi_kfunc_set = {
	.owner          = THIS_MODULE,
	.set            = &bpf_psi_kfuncs,
	.filter         = bpf_psi_kfunc_filter,
};

static int bpf_psi_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_psi_ops *ops = kdata;
	struct bpf_psi *bpf_psi;

	bpf_psi = bpf_psi_create(ops);
	if (!bpf_psi)
		return -ENOMEM;

	return ops->init(bpf_psi);
}

static void bpf_psi_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_psi_ops *ops = kdata;
	struct bpf_psi *bpf_psi = ops->bpf_psi;
	struct psi_trigger *t, *p;
	LIST_HEAD(to_destroy);

	spin_lock(&bpf_psi->lock);
	list_for_each_entry_safe(t, p, &bpf_psi->triggers, bpf_psi_node) {
		spin_lock(&t->group->bpf_triggers_lock);
		if (!t->pinned) {
			t->pinned = true;
			list_move(&t->bpf_group_node, &to_destroy);
			list_del(&t->bpf_psi_node);

			WRITE_ONCE(t->bpf_psi, NULL);
		}
		spin_unlock(&t->group->bpf_triggers_lock);
	}
	spin_unlock(&bpf_psi->lock);

	flush_workqueue(bpf_psi_wq);
	synchronize_srcu(&bpf_psi->srcu);

	list_for_each_entry_safe(t, p, &to_destroy, bpf_group_node)
		psi_trigger_destroy(t);

	if (!list_empty(&bpf_psi->node)) {
		mutex_lock(&bpf_psi_lock);
		list_del(&bpf_psi->node);
		mutex_unlock(&bpf_psi_lock);
		static_branch_dec(&bpf_psi_notify_key);
	}

	cleanup_srcu_struct(&bpf_psi->srcu);
	kfree(bpf_psi);
}

static int bpf_psi_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_psi_ops, init):
		fallthrough;
	case offsetof(struct bpf_psi_ops, handle_psi_event):
		if (!prog)
			return -EINVAL;
		break;
	}

	return 0;
}

static int bpf_psi_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	return 0;
}

static int bpf_psi_ops_init(struct btf *btf)
{
	return 0;
}

struct bpf_struct_ops bpf_psi_bpf_ops = {
	.verifier_ops = &bpf_psi_verifier_ops,
	.reg = bpf_psi_ops_reg,
	.unreg = bpf_psi_ops_unreg,
	.check_member = bpf_psi_ops_check_member,
	.init_member = bpf_psi_ops_init_member,
	.init = bpf_psi_ops_init,
	.name = "bpf_psi_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_psi_ops
};

static int __init bpf_psi_struct_ops_init(void)
{
	int wq_flags = WQ_MEM_RECLAIM | WQ_UNBOUND | WQ_HIGHPRI;
	int err;

	bpf_psi_wq = alloc_workqueue("bpf_psi_wq", wq_flags, 0);
	if (!bpf_psi_wq)
		return -ENOMEM;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&bpf_psi_kfunc_set);
	if (err) {
		pr_warn("error while registering bpf psi kfuncs: %d", err);
		goto err;
	}

	err = register_bpf_struct_ops(&bpf_psi_bpf_ops, bpf_psi_ops);
	if (err) {
		pr_warn("error while registering bpf psi struct ops: %d", err);
		goto err;
	}

	return 0;

err:
	destroy_workqueue(bpf_psi_wq);
	return err;
}
late_initcall(bpf_psi_struct_ops_init);
