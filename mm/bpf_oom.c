// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BPF-driven OOM killer customization
 *
 * Author: Roman Gushchin <roman.gushchin@linux.dev>
 */

#include <linux/bpf.h>
#include <linux/oom.h>
#include <linux/bpf_oom.h>
#include <linux/bpf-cgroup.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/uaccess.h>

static int bpf_ops_handle_oom(struct bpf_oom_ops *bpf_oom_ops,
			      struct bpf_struct_ops_link *st_link,
			      struct oom_control *oc)
{
	int ret;

	oc->bpf_handler_name = &bpf_oom_ops->name[0];
	oc->bpf_memory_freed = false;
	pagefault_disable();
	ret = bpf_oom_ops->handle_out_of_memory(oc, st_link);
	pagefault_enable();
	oc->bpf_handler_name = NULL;

	return ret;
}

bool bpf_handle_oom(struct oom_control *oc)
{
	struct bpf_struct_ops_link *st_link;
	struct bpf_oom_ops *bpf_oom_ops;
	struct mem_cgroup *memcg;
	struct bpf_map *map;
	int ret = 0;

	/*
	 * System-wide OOMs are handled by the struct ops attached
	 * to the root memory cgroup
	 */
	memcg = oc->memcg ? oc->memcg : root_mem_cgroup;

	rcu_read_lock_trace();

	/* Find the nearest bpf_oom_ops traversing the cgroup tree upwards */
	for (; memcg; memcg = parent_mem_cgroup(memcg)) {
		st_link = rcu_dereference_check(memcg->css.cgroup->bpf.bpf_oom_link,
						rcu_read_lock_trace_held());
		if (!st_link)
			continue;

		map = rcu_dereference_check((st_link->map),
					    rcu_read_lock_trace_held());
		if (!map)
			continue;

		/* Call BPF OOM handler */
		bpf_oom_ops = bpf_struct_ops_data(map);
		ret = bpf_ops_handle_oom(bpf_oom_ops, st_link, oc);
		if (ret && oc->bpf_memory_freed)
			break;
		ret = 0;
	}

	rcu_read_unlock_trace();

	return ret && oc->bpf_memory_freed;
}

static int __handle_out_of_memory(struct oom_control *oc,
				  struct bpf_struct_ops_link *st_link)
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
	struct bpf_struct_ops_link *st_link = (struct bpf_struct_ops_link *)link;
	struct cgroup *cgrp;

	/* The link is not yet fully initialized, but cgroup should be set */
	if (!link)
		return -EOPNOTSUPP;

	cgrp = st_link->cgroup;
	if (!cgrp)
		return -EINVAL;

	if (cmpxchg(&cgrp->bpf.bpf_oom_link, NULL, st_link))
		return -EEXIST;

	return 0;
}

static void bpf_oom_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_struct_ops_link *st_link = (struct bpf_struct_ops_link *)link;
	struct cgroup *cgrp;

	if (!link)
		return;

	cgrp = st_link->cgroup;
	if (!cgrp)
		return;

	WARN_ON(cmpxchg(&cgrp->bpf.bpf_oom_link, st_link, NULL) != st_link);
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
