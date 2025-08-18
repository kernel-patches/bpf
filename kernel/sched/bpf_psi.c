// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BPF PSI event handlers
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/bpf_psi.h>
#include <linux/cgroup-defs.h>

static struct workqueue_struct *bpf_psi_wq;

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

	return bpf_psi;
}

static void bpf_psi_free(struct bpf_psi *bpf_psi)
{
	cleanup_srcu_struct(&bpf_psi->srcu);
	kfree(bpf_psi);
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
		if (bpf_psi->ops->handle_psi_event)
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
void bpf_psi_cgroup_free(struct cgroup *cgroup)
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
		if (bpf_psi->ops->handle_cgroup_free)
			bpf_psi->ops->handle_cgroup_free(cgrp_id);
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

// bpf struct ops

static int __bpf_psi_init(struct bpf_psi *bpf_psi) { return 0; }
static void __bpf_psi_handle_psi_event(struct psi_trigger *t) {}
static void __bpf_psi_handle_cgroup_free(u64 cgroup_id) {}

static struct bpf_psi_ops __bpf_psi_ops = {
	.init = __bpf_psi_init,
	.handle_psi_event = __bpf_psi_handle_psi_event,
	.handle_cgroup_free = __bpf_psi_handle_cgroup_free,
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

	bpf_psi_free(bpf_psi);
}

static int bpf_psi_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
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

static struct bpf_struct_ops bpf_psi_bpf_ops = {
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
