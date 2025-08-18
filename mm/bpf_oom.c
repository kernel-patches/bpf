// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BPF-driven OOM killer customization
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/bpf.h>
#include <linux/oom.h>
#include <linux/bpf_oom.h>
#include <linux/srcu.h>

DEFINE_STATIC_SRCU(bpf_oom_srcu);
static DEFINE_SPINLOCK(bpf_oom_lock);
static LIST_HEAD(bpf_oom_handlers);

struct bpf_oom {
	struct bpf_oom_ops *ops;
	struct list_head node;
	struct srcu_struct srcu;
};

bool bpf_handle_oom(struct oom_control *oc)
{
	struct bpf_oom_ops *ops;
	struct bpf_oom *bpf_oom;
	int list_idx, idx, ret = 0;

	oc->bpf_memory_freed = false;

	list_idx = srcu_read_lock(&bpf_oom_srcu);
	list_for_each_entry_srcu(bpf_oom, &bpf_oom_handlers, node, false) {
		ops = READ_ONCE(bpf_oom->ops);
		if (!ops || !ops->handle_out_of_memory)
			continue;
		idx = srcu_read_lock(&bpf_oom->srcu);
		oc->bpf_policy_name = ops->name[0] ? &ops->name[0] :
			"bpf_defined_policy";
		ret = ops->handle_out_of_memory(oc);
		oc->bpf_policy_name = NULL;
		srcu_read_unlock(&bpf_oom->srcu, idx);

		if (ret && oc->bpf_memory_freed)
			break;
	}
	srcu_read_unlock(&bpf_oom_srcu, list_idx);

	return ret && oc->bpf_memory_freed;
}

static int __handle_out_of_memory(struct oom_control *oc)
{
	return 0;
}

static struct bpf_oom_ops __bpf_oom_ops = {
	.handle_out_of_memory = __handle_out_of_memory,
};

static const struct bpf_func_proto *
bpf_oom_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return tracing_prog_func_proto(func_id, prog);
}

static bool bpf_oom_ops_is_valid_access(int off, int size,
					enum bpf_access_type type,
					const struct bpf_prog *prog,
					struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_oom_verifier_ops = {
	.get_func_proto = bpf_oom_func_proto,
	.is_valid_access = bpf_oom_ops_is_valid_access,
};

static int bpf_oom_ops_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_oom_ops *ops = kdata;
	struct bpf_oom *bpf_oom;
	int ret;

	bpf_oom = kmalloc(sizeof(*bpf_oom), GFP_KERNEL_ACCOUNT);
	if (!bpf_oom)
		return -ENOMEM;

	ret = init_srcu_struct(&bpf_oom->srcu);
	if (ret) {
		kfree(bpf_oom);
		return ret;
	}

	WRITE_ONCE(bpf_oom->ops, ops);
	ops->bpf_oom = bpf_oom;

	spin_lock(&bpf_oom_lock);
	list_add_rcu(&bpf_oom->node, &bpf_oom_handlers);
	spin_unlock(&bpf_oom_lock);

	return 0;
}

static void bpf_oom_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_oom_ops *ops = kdata;
	struct bpf_oom *bpf_oom = ops->bpf_oom;

	WRITE_ONCE(bpf_oom->ops, NULL);

	spin_lock(&bpf_oom_lock);
	list_del_rcu(&bpf_oom->node);
	spin_unlock(&bpf_oom_lock);

	synchronize_srcu(&bpf_oom->srcu);

	kfree(bpf_oom);
}

static int bpf_oom_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct bpf_oom_ops *uops = (const struct bpf_oom_ops *)udata;
	struct bpf_oom_ops *ops = (struct bpf_oom_ops *)kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_oom_ops, name):
		strscpy_pad(ops->name, uops->name, sizeof(ops->name));
		return 1;
	}
	return 0;
}

static int bpf_oom_ops_init(struct btf *btf)
{
	return 0;
}

static struct bpf_struct_ops bpf_oom_bpf_ops = {
	.verifier_ops = &bpf_oom_verifier_ops,
	.reg = bpf_oom_ops_reg,
	.unreg = bpf_oom_ops_unreg,
	.init_member = bpf_oom_ops_init_member,
	.init = bpf_oom_ops_init,
	.name = "bpf_oom_ops",
	.owner = THIS_MODULE,
	.cfi_stubs = &__bpf_oom_ops
};

static int __init bpf_oom_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_oom_bpf_ops, bpf_oom_ops);
}
late_initcall(bpf_oom_struct_ops_init);
