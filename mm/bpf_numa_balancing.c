// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/memcontrol.h>
#include <linux/sched/numa_balancing.h>

typedef int numab_fn_t(struct task_struct *p);

struct bpf_numab_ops {
	numab_fn_t *numab_hook;

	/* TODO:
	 * The cgroup_id embedded in this struct is set at compile time
	 * and cannot be modified during BPF program attach time.
	 * Modifying it at attach time requires libbpf support,
	 * which is currently under development by Roman.
	 */
	int cgroup_id;
};

static DEFINE_SPINLOCK(numab_ops_lock);
DEFINE_STATIC_KEY_FALSE(bpf_numab_enabled_key);

int bpf_numab_hook(struct task_struct *p)
{
	struct bpf_numab_ops *bpf_numab;
	struct mem_cgroup *task_memcg;
	int ret = 0;

	if (!p->mm)
		return 0;

	/* We can cache memcg::bpf_numab to mm::bpf_numab if it becomes a bettleneck */
	rcu_read_lock();
	task_memcg = mem_cgroup_from_task(rcu_dereference(p->mm->owner));
	if (!task_memcg)
		goto out;

	/* Users can install BPF NUMA policies on leaf memory cgroups.
	 * This eliminates the need to traverse the cgroup hierarchy or
	 * propagate policies during registration, simplifying the kernel design.
	 */
	bpf_numab = rcu_dereference(task_memcg->bpf_numab);
	if (!bpf_numab || !bpf_numab->numab_hook)
		goto out;

	ret = bpf_numab->numab_hook(p);

out:
	rcu_read_unlock();
	return ret;
}

static const struct bpf_func_proto *
bpf_numab_get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool bpf_numab_ops_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_numab_verifier_ops = {
	.get_func_proto = bpf_numab_get_func_proto,
	.is_valid_access = bpf_numab_ops_is_valid_access,
};

static int bpf_numab_init(struct btf *btf)
{
	return 0;
}

static int bpf_numab_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	/* The call site operates under RCU protection. */
	if (prog->sleepable)
		return -EINVAL;
	return 0;
}

static int bpf_numab_init_member(const struct btf_type *t,
			       const struct btf_member *member,
			       void *kdata, const void *udata)
{
	const struct bpf_numab_ops *ubpf_numab;
	struct bpf_numab_ops *kbpf_numab;
	u32 moff;

	ubpf_numab = (const struct bpf_numab_ops *)udata;
	kbpf_numab = (struct bpf_numab_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct bpf_numab_ops, cgroup_id):
		/* bpf_struct_ops only handles func ptrs and zero-ed members.
		 * Return 1 to bypass the default handler.
		 */
		kbpf_numab->cgroup_id = ubpf_numab->cgroup_id;
		return 1;
	}
	return 0;
}

static int bpf_numab_reg(void *kdata, struct bpf_link *link)
{
	struct bpf_numab_ops *ops = kdata;
	struct mem_cgroup *memcg;
	int err = 0;

	/* Only the link mode is supported. */
	if (!link)
		return -EOPNOTSUPP;

	/* Depends on CONFIG_SHRINKER_DEBUG */
	memcg = mem_cgroup_get_from_ino(ops->cgroup_id);
	if (!memcg || IS_ERR(memcg))
		return -ENOENT;

	spin_lock(&numab_ops_lock);
	/* Each memory cgroup can have at most one attached BPF program to ensure
	 * exclusive control and avoid interference between different BPF policies.
	 */
	if (rcu_access_pointer(memcg->bpf_numab)) {
		err = -EBUSY;
		goto out;
	}
	rcu_assign_pointer(memcg->bpf_numab, ops);
	spin_unlock(&numab_ops_lock);
	static_branch_inc(&bpf_numab_enabled_key);

out:
	mem_cgroup_put(memcg);
	return err;
}

static void bpf_numab_unreg(void *kdata, struct bpf_link *link)
{
	struct bpf_numab_ops *ops = kdata;
	struct mem_cgroup *memcg;

	memcg = mem_cgroup_get_from_ino(ops->cgroup_id);
	if (!memcg)
		return;

	spin_lock(&numab_ops_lock);
	if (!rcu_access_pointer(memcg->bpf_numab)) {
		spin_unlock(&numab_ops_lock);
		return;
	}
	rcu_replace_pointer(memcg->bpf_numab, NULL, lockdep_is_held(&numab_ops_lock));
	spin_unlock(&numab_ops_lock);
	static_branch_dec(&bpf_numab_enabled_key);
	synchronize_rcu();
}

static int bpf_numab_update(void *kdata, void *old_kdata, struct bpf_link *link)
{
	struct bpf_numab_ops *ops = kdata;
	struct mem_cgroup *memcg;

	memcg = mem_cgroup_get_from_ino(ops->cgroup_id);
	if (!memcg)
		return -EINVAL;

	spin_lock(&numab_ops_lock);
	/* The update can proceed regardless of whether memcg->bpf_numab has been previously set. */
	rcu_replace_pointer(memcg->bpf_numab, ops, lockdep_is_held(&numab_ops_lock));
	spin_unlock(&numab_ops_lock);
	synchronize_rcu();
	return 0;
}

static int bpf_numab_validate(void *kdata)
{
	struct bpf_numab_ops *ops = kdata;

	if (!ops->numab_hook) {
		pr_err("bpf_numab: required ops isn't implemented\n");
		return -EINVAL;
	}
	return 0;
}

static int bpf_numa_balancing(struct task_struct *p)
{
	return 1;
}

static struct bpf_numab_ops __bpf_numab_ops = {
	.numab_hook = (numab_fn_t *)bpf_numa_balancing,
};

static struct bpf_struct_ops bpf_bpf_numab_ops = {
	.verifier_ops = &bpf_numab_verifier_ops,
	.init = bpf_numab_init,
	.check_member = bpf_numab_check_member,
	.init_member = bpf_numab_init_member,
	.reg = bpf_numab_reg,
	.unreg = bpf_numab_unreg,
	.update = bpf_numab_update,
	.validate = bpf_numab_validate,
	.cfi_stubs = &__bpf_numab_ops,
	.owner = THIS_MODULE,
	.name = "bpf_numab_ops",
};

static int __init bpf_numab_ops_init(void)
{
	int err;

	err = register_bpf_struct_ops(&bpf_bpf_numab_ops, bpf_numab_ops);
	if (err)
		pr_err("bpf_numab: Failed to register struct_ops (%d)\n", err);
	return err;
}
late_initcall(bpf_numab_ops_init);
