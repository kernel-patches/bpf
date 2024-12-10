// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  Generic hook for SMC subsystem.
 *
 *  Copyright IBM Corp. 2016
 *  Copyright (c) 2024, Alibaba Inc.
 *
 *  Author: D. Wythe <alibuda@linux.alibaba.com>
 */

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>

#include "smc_ops.h"

static DEFINE_SPINLOCK(smc_ops_list_lock);
static LIST_HEAD(smc_ops_list);

static int smc_ops_reg(struct smc_ops *ops)
{
	int ret = 0;

	spin_lock(&smc_ops_list_lock);
	/* already exist or duplicate name */
	if (smc_ops_find_by_name(ops->name))
		ret = -EEXIST;
	else
		list_add_tail_rcu(&ops->list, &smc_ops_list);
	spin_unlock(&smc_ops_list_lock);
	return ret;
}

static void smc_ops_unreg(struct smc_ops *ops)
{
	spin_lock(&smc_ops_list_lock);
	list_del_rcu(&ops->list);
	spin_unlock(&smc_ops_list_lock);

	/* Ensure that all readers to complete */
	synchronize_rcu();
}

struct smc_ops *smc_ops_find_by_name(const char *name)
{
	struct smc_ops *ops;

	list_for_each_entry_rcu(ops, &smc_ops_list, list) {
		if (strcmp(ops->name, name) == 0)
			return ops;
	}
	return NULL;
}

static int __bpf_smc_stub_set_tcp_option(struct tcp_sock *tp) { return 1; }
static int __bpf_smc_stub_set_tcp_option_cond(const struct tcp_sock *tp,
					      struct inet_request_sock *ireq)
{
	return 1;
}

static struct smc_ops __bpf_smc_bpf_ops = {
	.set_option		= __bpf_smc_stub_set_tcp_option,
	.set_option_cond	= __bpf_smc_stub_set_tcp_option_cond,
};

static int smc_bpf_ops_init(struct btf *btf) { return 0; }

static int smc_bpf_ops_reg(void *kdata, struct bpf_link *link)
{
	return smc_ops_reg(kdata);
}

static void smc_bpf_ops_unreg(void *kdata, struct bpf_link *link)
{
	smc_ops_unreg(kdata);
}

static int smc_bpf_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	const struct smc_ops *u_ops;
	struct smc_ops *k_ops;
	u32 moff;

	u_ops = (const struct smc_ops *)udata;
	k_ops = (struct smc_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct smc_ops, name):
		if (bpf_obj_name_cpy(k_ops->name, u_ops->name,
				     sizeof(u_ops->name)) <= 0)
			return -EINVAL;
		return 1;
	case offsetof(struct smc_ops, flags):
		if (u_ops->flags & ~SMC_OPS_ALL_FLAGS)
			return -EINVAL;
		k_ops->flags = u_ops->flags;
		return 1;
	default:
		break;
	}

	return 0;
}

static int smc_bpf_ops_check_member(const struct btf_type *t,
				    const struct btf_member *member,
				    const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	switch (moff) {
	case offsetof(struct smc_ops, name):
	case offsetof(struct smc_ops, flags):
	case offsetof(struct smc_ops, set_option):
	case offsetof(struct smc_ops, set_option_cond):
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct bpf_verifier_ops smc_bpf_verifier_ops = {
	.get_func_proto		= bpf_base_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
};

static struct bpf_struct_ops bpf_smc_bpf_ops = {
	.name		= "smc_ops",
	.init		= smc_bpf_ops_init,
	.reg		= smc_bpf_ops_reg,
	.unreg		= smc_bpf_ops_unreg,
	.cfi_stubs	= &__bpf_smc_bpf_ops,
	.verifier_ops	= &smc_bpf_verifier_ops,
	.init_member	= smc_bpf_ops_init_member,
	.check_member	= smc_bpf_ops_check_member,
	.owner		= THIS_MODULE,
};

int smc_bpf_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_smc_bpf_ops, smc_ops);
}
