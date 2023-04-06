// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Support eBPF for Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Copyright IBM Corp. 2016, 2018
 *
 *  Author(s):  D. Wythe <alibuda@linux.alibaba.com>
 */

#include <linux/bpf_verifier.h>
#include <linux/btf_ids.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/smc.h>
#include <net/sock.h>
#include "smc.h"

struct bpf_struct_ops bpf_smc_sock_negotiator_ops;

static DEFINE_SPINLOCK(smc_sock_negotiator_list_lock);
static LIST_HEAD(smc_sock_negotiator_list);
static u32 smc_sock_id, sock_id;

/* required smc_sock_negotiator_list_lock locked */
static struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_key(u32 key)
{
	struct smc_sock_negotiator_ops *ops;

	list_for_each_entry_rcu(ops, &smc_sock_negotiator_list, list) {
		if (ops->key == key)
			return ops;
	}

	return NULL;
}

/* required smc_sock_negotiator_list_lock locked */
struct smc_sock_negotiator_ops *smc_negotiator_ops_get_by_name(const char *name)
{
	struct smc_sock_negotiator_ops *ops;

	list_for_each_entry_rcu(ops, &smc_sock_negotiator_list, list) {
		if (strcmp(ops->name, name) == 0)
			return ops;
	}

	return NULL;
}

static int smc_sock_validate_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	/* not required yet */
	return 0;
}

/* register ops */
int smc_sock_register_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	int ret;

	ret = smc_sock_validate_negotiator_ops(ops);
	if (ret)
		return ret;

	/* calt key by name hash */
	ops->key = jhash(ops->name, sizeof(ops->name), strlen(ops->name));

	spin_lock(&smc_sock_negotiator_list_lock);
	if (smc_negotiator_ops_get_by_key(ops->key)) {
		pr_notice("smc: %s negotiator already registered\n", ops->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ops->list, &smc_sock_negotiator_list);
	}
	spin_unlock(&smc_sock_negotiator_list_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(smc_sock_register_negotiator_ops);

/* unregister ops */
void smc_sock_unregister_negotiator_ops(struct smc_sock_negotiator_ops *ops)
{
	spin_lock(&smc_sock_negotiator_list_lock);
	list_del_rcu(&ops->list);
	spin_unlock(&smc_sock_negotiator_list_lock);

	/* Wait for outstanding readers to complete before the
	 * ops gets removed entirely.
	 */
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(smc_sock_unregister_negotiator_ops);

int smc_sock_update_negotiator_ops(struct smc_sock_negotiator_ops *ops,
				   struct smc_sock_negotiator_ops *old_ops)
{
	struct smc_sock_negotiator_ops *existing;
	int ret;

	ret = smc_sock_validate_negotiator_ops(ops);
	if (ret)
		return ret;

	ops->key = jhash(ops->name, sizeof(ops->name), strlen(ops->name));
	if (unlikely(!ops->key))
		return -EINVAL;

	spin_lock(&smc_sock_negotiator_list_lock);
	existing = smc_negotiator_ops_get_by_key(old_ops->key);
	if (!existing || strcmp(existing->name, ops->name)) {
		ret = -EINVAL;
	} else if (existing != old_ops) {
		pr_notice("invalid old negotiator to replace\n");
		ret = -EINVAL;
	} else {
		list_add_tail_rcu(&ops->list, &smc_sock_negotiator_list);
		list_del_rcu(&existing->list);
	}

	spin_unlock(&smc_sock_negotiator_list_lock);
	if (ret)
		return ret;

	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL_GPL(smc_sock_update_negotiator_ops);

/* assign ops to sock */
int smc_sock_assign_negotiator_ops(struct smc_sock *smc, const char *name)
{
	struct smc_sock_negotiator_ops *ops;
	int ret = -EINVAL;

	/* already set */
	if (READ_ONCE(smc->negotiator_ops))
		smc_sock_cleanup_negotiator_ops(smc, /* in release */ 0);

	/* Just for clear negotiator_ops */
	if (!name || !strlen(name))
		return 0;

	rcu_read_lock();
	ops = smc_negotiator_ops_get_by_name(name);
	if (likely(ops)) {
		if (unlikely(!bpf_try_module_get(ops, ops->owner))) {
			ret = -EACCES;
		} else {
			WRITE_ONCE(smc->negotiator_ops, ops);
			/* make sure ops can be seen */
			smp_wmb();
			if (ops->init)
				ops->init(&smc->sk);
			ret = 0;
		}
	}
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL_GPL(smc_sock_assign_negotiator_ops);

/* reset ops to sock */
void smc_sock_cleanup_negotiator_ops(struct smc_sock *smc, int in_release)
{
	const struct smc_sock_negotiator_ops *ops;

	ops = READ_ONCE(smc->negotiator_ops);

	/* not all smc sock has negotiator_ops */
	if (!ops)
		return;

	might_sleep();

	/* Just ensure data integrity */
	WRITE_ONCE(smc->negotiator_ops, NULL);
	/* make sure NULL can be seen */
	smp_wmb();
	/* If the cleanup was not caused by the release of the sock,
	 * it means that we may need to wait for the readers of ops
	 * to complete.
	 */
	if (unlikely(!in_release))
		synchronize_rcu();
	if (ops->release)
		ops->release(&smc->sk);
	bpf_module_put(ops, ops->owner);
}
EXPORT_SYMBOL_GPL(smc_sock_cleanup_negotiator_ops);

void smc_sock_clone_negotiator_ops(struct sock *parent, struct sock *child)
{
	const struct smc_sock_negotiator_ops *ops;

	rcu_read_lock();
	ops = READ_ONCE(smc_sk(parent)->negotiator_ops);
	if (ops && bpf_try_module_get(ops, ops->owner)) {
		smc_sk(child)->negotiator_ops = ops;
		if (ops->init)
			ops->init(child);
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(smc_sock_clone_negotiator_ops);

static int bpf_smc_negotiator_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "sock", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "smc_sock", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	smc_sock_id = type_id;

	return 0;
}

/* register ops */
static int bpf_smc_negotiator_reg(void *kdata)
{
	return smc_sock_register_negotiator_ops(kdata);
}

/* unregister ops */
static void bpf_smc_negotiator_unreg(void *kdata)
{
	smc_sock_unregister_negotiator_ops(kdata);
}

/* unregister ops */
static int bpf_smc_negotiator_update(void *kdata, void *old_kdata)
{
	return smc_sock_update_negotiator_ops(kdata, old_kdata);
}

static int bpf_smc_negotiator_validate(void *kdata)
{
	return smc_sock_validate_negotiator_ops(kdata);
}

static int bpf_smc_negotiator_check_member(const struct btf_type *t,
					   const struct btf_member *member,
					   const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_smc_negotiator_init_member(const struct btf_type *t,
					  const struct btf_member *member,
					  void *kdata, const void *udata)
{
	const struct smc_sock_negotiator_ops *uops;
	struct smc_sock_negotiator_ops *ops;
	u32 moff;

	uops = (const struct smc_sock_negotiator_ops *)udata;
	ops = (struct smc_sock_negotiator_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;

	/* init name */
	if (moff ==  offsetof(struct smc_sock_negotiator_ops, name)) {
		if (bpf_obj_name_cpy(ops->name, uops->name,
				     sizeof(uops->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

BPF_CALL_1(bpf_smc_skc_to_tcp_sock, struct sock *, sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_family == AF_SMC)
		return (unsigned long)((struct smc_sock *)(sk))->clcsock->sk;

	return (unsigned long)NULL;
}

const struct bpf_func_proto bpf_smc_skc_to_tcp_sock_proto = {
	.func			= bpf_smc_skc_to_tcp_sock,
	.gpl_only		= false,
	.ret_type		= RET_PTR_TO_BTF_ID_OR_NULL,
	.arg1_type		= ARG_PTR_TO_BTF_ID_SOCK_COMMON,
	.ret_btf_id		= &btf_sock_ids[BTF_SOCK_TYPE_TCP],
};

static const struct bpf_func_proto *
smc_negotiator_prog_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	const struct btf_member *m;
	const struct btf_type *t;
	u32 midx, moff;

	midx = prog->expected_attach_type;
	t = bpf_smc_sock_negotiator_ops.type;
	m = &btf_type_member(t)[midx];

	moff = __btf_member_bit_offset(t, m) / 8;

	switch (func_id) {
	case BPF_FUNC_setsockopt:
		switch (moff) {
		/* Avoid potential deadloop risk */
		case offsetof(struct smc_sock_negotiator_ops, init):
			fallthrough;
		/* Avoid potential leak risk */
		case offsetof(struct smc_sock_negotiator_ops, release):
			return NULL;
		}
		return &bpf_sk_setsockopt_proto;
	case BPF_FUNC_getsockopt:
		return &bpf_sk_getsockopt_proto;
	case BPF_FUNC_skc_to_tcp_sock:
		return &bpf_smc_skc_to_tcp_sock_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool smc_negotiator_prog_is_valid_access(int off, int size, enum bpf_access_type type,
						const struct bpf_prog *prog,
						struct bpf_insn_access_aux *info)
{
	if (!bpf_tracing_btf_ctx_access(off, size, type, prog, info))
		return false;

	/* promote it to smc_sock */
	if (base_type(info->reg_type) == PTR_TO_BTF_ID &&
	    !bpf_type_has_unsafe_modifiers(info->reg_type) &&
	    info->btf_id == sock_id)
		info->btf_id = smc_sock_id;

	return true;
}

static const struct bpf_verifier_ops bpf_smc_negotiator_verifier_ops = {
	.get_func_proto  = smc_negotiator_prog_func_proto,
	.is_valid_access = smc_negotiator_prog_is_valid_access,
};

struct bpf_struct_ops bpf_smc_sock_negotiator_ops = {
	.verifier_ops = &bpf_smc_negotiator_verifier_ops,
	.init = bpf_smc_negotiator_init,
	.check_member = bpf_smc_negotiator_check_member,
	.init_member = bpf_smc_negotiator_init_member,
	.reg = bpf_smc_negotiator_reg,
	.update = bpf_smc_negotiator_update,
	.unreg = bpf_smc_negotiator_unreg,
	.validate = bpf_smc_negotiator_validate,
	.name = "smc_sock_negotiator_ops",
};

