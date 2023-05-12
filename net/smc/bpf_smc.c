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
#include "smc_negotiator.h"

extern struct bpf_struct_ops bpf_smc_sock_negotiator_ops;
static u32 smc_sock_id, sock_id;

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

static const struct bpf_func_proto bpf_smc_skc_to_tcp_sock_proto = {
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