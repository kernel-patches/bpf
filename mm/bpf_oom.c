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
#include <linux/cgroup.h>
#include <linux/memcontrol.h>

DEFINE_STATIC_SRCU(bpf_oom_srcu);
static struct bpf_oom_ops *system_bpf_oom;

static int bpf_ops_handle_oom(struct bpf_oom_ops *bpf_oom_ops,
			      struct mem_cgroup *memcg,
			      struct oom_control *oc)
{
	struct bpf_oom_ctx exec_ctx;
	int ret;

	if (memcg)
		exec_ctx.cgroup_id = cgroup_id(memcg->css.cgroup);
	else
		exec_ctx.cgroup_id = 0;

	oc->bpf_policy_name = &bpf_oom_ops->name[0];
	oc->bpf_memory_freed = false;
	ret = bpf_oom_ops->handle_out_of_memory(oc, &exec_ctx);
	oc->bpf_policy_name = NULL;

	return ret;
}

bool bpf_handle_oom(struct oom_control *oc)
{
	struct bpf_oom_ops *bpf_oom_ops = NULL;
	struct mem_cgroup *memcg;
	int idx, ret = 0;

	/* All bpf_oom_ops structures are protected using bpf_oom_srcu */
	idx = srcu_read_lock(&bpf_oom_srcu);

	/* Find the nearest bpf_oom_ops traversing the cgroup tree upwards */
	for (memcg = oc->memcg; memcg; memcg = parent_mem_cgroup(memcg)) {
		bpf_oom_ops = READ_ONCE(memcg->bpf_oom);
		if (!bpf_oom_ops)
			continue;

		/* Call BPF OOM handler */
		ret = bpf_ops_handle_oom(bpf_oom_ops, memcg, oc);
		if (ret && oc->bpf_memory_freed)
			goto exit;
	}
	/*
	 * System-wide OOM or per-memcg BPF OOM handler wasn't successful?
	 * Try system_bpf_oom.
	 */
	bpf_oom_ops = READ_ONCE(system_bpf_oom);
	if (!bpf_oom_ops)
		goto exit;

	/* Call BPF OOM handler */
	ret = bpf_ops_handle_oom(bpf_oom_ops, NULL, oc);
exit:
	srcu_read_unlock(&bpf_oom_srcu, idx);
	return ret && oc->bpf_memory_freed;
}

static int __handle_out_of_memory(struct oom_control *oc,
				  struct bpf_oom_ctx *exec_ctx)
{
	return 0;
}

static void __handle_cgroup_offline(u64 cgroup_id, struct bpf_oom_ctx *exec_ctx)
{
}

static struct bpf_oom_ops __bpf_oom_ops = {
	.handle_out_of_memory = __handle_out_of_memory,
	.handle_cgroup_offline = __handle_cgroup_offline,
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
	struct bpf_struct_ops_link *ops_link = container_of(link, struct bpf_struct_ops_link, link);
	struct bpf_oom_ops **bpf_oom_ops_ptr = NULL;
	struct bpf_oom_ops *bpf_oom_ops = kdata;
	struct mem_cgroup *memcg = NULL;
	int err = 0;

	if (ops_link->cgroup_id) {
		/* Attach to a memory cgroup? */
		memcg = mem_cgroup_get_from_ino(ops_link->cgroup_id);
		if (IS_ERR_OR_NULL(memcg))
			return PTR_ERR(memcg);
		bpf_oom_ops_ptr = &memcg->bpf_oom;
	} else {
		/* System-wide OOM handler */
		bpf_oom_ops_ptr = &system_bpf_oom;
	}

	/* Another struct ops attached? */
	if (READ_ONCE(*bpf_oom_ops_ptr)) {
		err = -EBUSY;
		goto exit;
	}

	/* Expose bpf_oom_ops structure */
	WRITE_ONCE(*bpf_oom_ops_ptr, bpf_oom_ops);
exit:
	mem_cgroup_put(memcg);
	return err;
}

static void bpf_oom_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *ops_link = container_of(link, struct bpf_struct_ops_link, link);
	struct bpf_oom_ops **bpf_oom_ops_ptr = NULL;
	struct bpf_oom_ops *bpf_oom_ops = kdata;
	struct mem_cgroup *memcg = NULL;

	if (ops_link->cgroup_id) {
		/* Detach from a memory cgroup? */
		memcg = mem_cgroup_get_from_ino(ops_link->cgroup_id);
		if (IS_ERR_OR_NULL(memcg))
			goto exit;
		bpf_oom_ops_ptr = &memcg->bpf_oom;
	} else {
		/* System-wide OOM handler */
		bpf_oom_ops_ptr = &system_bpf_oom;
	}

	/* Hide bpf_oom_ops from new callers */
	if (!WARN_ON(READ_ONCE(*bpf_oom_ops_ptr) != bpf_oom_ops))
		WRITE_ONCE(*bpf_oom_ops_ptr, NULL);

	mem_cgroup_put(memcg);

exit:
	/* Release bpf_oom_ops after a srcu grace period */
	synchronize_srcu(&bpf_oom_srcu);
}

void bpf_oom_memcg_offline(struct mem_cgroup *memcg)
{
	struct bpf_oom_ops *bpf_oom_ops;
	struct bpf_oom_ctx exec_ctx;
	u64 cgrp_id;
	int idx;

	/* All bpf_oom_ops structures are protected using bpf_oom_srcu */
	idx = srcu_read_lock(&bpf_oom_srcu);

	bpf_oom_ops = READ_ONCE(memcg->bpf_oom);
	WRITE_ONCE(memcg->bpf_oom, NULL);

	if (bpf_oom_ops && bpf_oom_ops->handle_cgroup_offline) {
		cgrp_id = cgroup_id(memcg->css.cgroup);
		exec_ctx.cgroup_id = cgrp_id;
		bpf_oom_ops->handle_cgroup_offline(cgrp_id, &exec_ctx);
	}

	srcu_read_unlock(&bpf_oom_srcu, idx);
}

static int bpf_oom_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_oom_ops, handle_out_of_memory):
		if (!prog)
			return -EINVAL;
		break;
	}

	return 0;
}

static int bpf_oom_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct bpf_oom_ops *uops = udata;
	struct bpf_oom_ops *ops = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct bpf_oom_ops, name):
		if (uops->name[0])
			strscpy_pad(ops->name, uops->name, sizeof(ops->name));
		else
			strscpy_pad(ops->name, "bpf_defined_policy");
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
	.check_member = bpf_oom_ops_check_member,
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
