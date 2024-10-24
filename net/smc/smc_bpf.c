// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Shared Memory Communications over RDMA (SMC-R) and RoCE
 *
 *  support for eBPF programs in SMC subsystem.
 *
 *  Copyright IBM Corp. 2016
 *  Copyright (c) 2024, Alibaba Inc.
 *
 *  Author: D. Wythe <alibuda@linux.alibaba.com>
 */

#include <linux/bpf_verifier.h>
#include <linux/spinlock.h>
#include <linux/module.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <net/smc.h>

#include "smc_bpf.h"

static DEFINE_SPINLOCK(smc_bpf_ops_list_lock);
static LIST_HEAD(smc_bpf_ops_list);

static u32 tcp_sock_id, smc_bpf_ops_ctx_id;
static const struct btf_type *smc_bpf_ops_type;
static const struct btf *saved_btf;

static int smc_bpf_ops_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "tcp_sock", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tcp_sock_id = type_id;

	type_id = btf_find_by_name_kind(btf, "smc_bpf_ops_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	smc_bpf_ops_ctx_id = type_id;

	type_id = btf_find_by_name_kind(btf, "smc_bpf_ops", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	smc_bpf_ops_type = btf_type_by_id(btf, type_id);

	saved_btf = btf;
	return 0;
}

static int smc_bpf_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	struct smc_bpf_ops *k_ops;
	u32 moff;

	k_ops = (struct smc_bpf_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct smc_bpf_ops, list):
		INIT_LIST_HEAD(&k_ops->list);
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
	case offsetof(struct smc_bpf_ops, set_option):
	case offsetof(struct smc_bpf_ops, set_option_cond):
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int smc_bpf_ops_reg(void *kdata, struct bpf_link *link)
{
	struct smc_bpf_ops *ops = kdata;

	/* Prevent the same ops from being registered repeatedly. */
	if (!list_empty(&ops->list))
		return -EINVAL;

	spin_lock(&smc_bpf_ops_list_lock);
	list_add_tail_rcu(&ops->list, &smc_bpf_ops_list);
	spin_unlock(&smc_bpf_ops_list_lock);

	return 0;
}

static void smc_bpf_ops_unreg(void *kdata, struct bpf_link *link)
{
	struct smc_bpf_ops *ops = kdata;

	spin_lock(&smc_bpf_ops_list_lock);
	list_del_rcu(&ops->list);
	spin_unlock(&smc_bpf_ops_list_lock);

	/* Ensure that all readers to complete */
	synchronize_rcu();
}

static void __bpf_smc_stub_set_tcp_option(struct smc_bpf_ops_ctx *ops_ctx) {}
static void __bpf_smc_stub_set_tcp_option_cond(struct smc_bpf_ops_ctx *ops_ctx) {}

static struct smc_bpf_ops __bpf_smc_bpf_ops = {
	.set_option = __bpf_smc_stub_set_tcp_option,
	.set_option_cond = __bpf_smc_stub_set_tcp_option_cond,
};

static int smc_bpf_ops_btf_struct_access(struct bpf_verifier_log *log,
					 const struct bpf_reg_state *reg,
					 const struct bpf_prog *prog,
					 int off, int size)
{
	const struct btf_member *member;
	const char *mname;
	int member_idx;

	member_idx = prog->expected_attach_type;
	if (member_idx >= btf_type_vlen(smc_bpf_ops_type))
		goto out_err;

	member = &btf_type_member(smc_bpf_ops_type)[member_idx];
	mname = btf_str_by_offset(saved_btf, member->name_off);

	if (!strcmp(mname, "set_option")) {
		/* only support to modify tcp_sock->syn_smc */
		if (reg->btf_id == tcp_sock_id &&
		    off == offsetof(struct tcp_sock, syn_smc) &&
		    off + size == offsetofend(struct tcp_sock, syn_smc))
			return 0;
	} else if (!strcmp(mname, "set_option_cond")) {
		/* only support to modify smc_bpf_ops_ctx->smc_ok */
		if (reg->btf_id == smc_bpf_ops_ctx_id &&
		    off == offsetof(struct smc_bpf_ops_ctx, set_option_cond.smc_ok) &&
		    off + size == offsetofend(struct smc_bpf_ops_ctx, set_option_cond.smc_ok))
			return 0;
	}

out_err:
	return -EACCES;
}

static const struct bpf_verifier_ops smc_bpf_verifier_ops = {
	.get_func_proto = bpf_base_func_proto,
	.is_valid_access = bpf_tracing_btf_ctx_access,
	.btf_struct_access = smc_bpf_ops_btf_struct_access,
};

static struct bpf_struct_ops bpf_smc_bpf_ops = {
	.init = smc_bpf_ops_init,
	.name = "smc_bpf_ops",
	.reg = smc_bpf_ops_reg,
	.unreg = smc_bpf_ops_unreg,
	.cfi_stubs = &__bpf_smc_bpf_ops,
	.verifier_ops = &smc_bpf_verifier_ops,
	.init_member = smc_bpf_ops_init_member,
	.check_member = smc_bpf_ops_check_member,
	.owner = THIS_MODULE,
};

int smc_bpf_struct_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_smc_bpf_ops, smc_bpf_ops);
}

void bpf_smc_set_tcp_option(struct tcp_sock *tp)
{
	struct smc_bpf_ops_ctx ops_ctx = {};
	struct smc_bpf_ops *ops;

	ops_ctx.set_option.tp = tp;

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &smc_bpf_ops_list, list) {
		ops->set_option(&ops_ctx);
	}
	rcu_read_unlock();
}

void bpf_smc_set_tcp_option_cond(const struct tcp_sock *tp, struct inet_request_sock *ireq)
{
	struct smc_bpf_ops_ctx ops_ctx = {};
	struct smc_bpf_ops *ops;

	ops_ctx.set_option_cond.tp = tp;
	ops_ctx.set_option_cond.ireq = ireq;
	ops_ctx.set_option_cond.smc_ok = ireq->smc_ok;

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &smc_bpf_ops_list, list) {
		ops->set_option_cond(&ops_ctx);
	}
	rcu_read_unlock();

	ireq->smc_ok = ops_ctx.set_option_cond.smc_ok;
}
