// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/bpf_verifier.h>
#include <net/bpf_sk_storage.h>
#include <net/tcp.h>

static int timeout_init_stub(struct sock *sk, struct request_sock *req__nullable)
{
	struct bpf_cg_run_ctx *ctx =
		container_of(current->bpf_ctx, struct bpf_cg_run_ctx, run_ctx);

	return ctx->retval;
}

static int rwnd_init_stub(struct sock *sk, struct request_sock *req__nullable)
{
	struct bpf_cg_run_ctx *ctx =
		container_of(current->bpf_ctx, struct bpf_cg_run_ctx, run_ctx);

	return ctx->retval;
}

static void rtt_stub(struct sock *sk, long mrtt, u32 srtt)
{
}

static void set_state_stub(struct sock *sk, int state)
{
}

static void retrans_stub(struct sock *sk, int type)
{
}

static void connect_stub(struct sock *sk)
{
}

static void listen_stub(struct sock *sk)
{
}

static struct bpf_tcp_ops __bpf_tcp_ops = {
	.timeout_init = timeout_init_stub,
	.rwnd_init = rwnd_init_stub,
	.rtt = rtt_stub,
	.set_state = set_state_stub,
	.retrans = retrans_stub,
	.connect = connect_stub,
	.listen = listen_stub,
};

static const struct bpf_func_proto *
get_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	u32 moff = prog->aux->attach_st_ops_member_off;

	switch (func_id) {
	case BPF_FUNC_sk_storage_get:
		return &bpf_sk_storage_get_proto;
	case BPF_FUNC_sk_storage_delete:
		return &bpf_sk_storage_delete_proto;
	case BPF_FUNC_setsockopt:
		/* The listener is not locked. */
		if (moff == offsetof(struct bpf_tcp_ops, rwnd_init) ||
		    moff == offsetof(struct bpf_tcp_ops, timeout_init))
			return NULL;
		return &bpf_sk_setsockopt_proto;
	case BPF_FUNC_getsockopt:
		if (moff == offsetof(struct bpf_tcp_ops, rwnd_init) ||
		    moff == offsetof(struct bpf_tcp_ops, timeout_init))
			return NULL;
		return &bpf_sk_getsockopt_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool is_valid_access(int off, int size, enum bpf_access_type type,
			    const struct bpf_prog *prog, struct bpf_insn_access_aux *info)
{
	if (!bpf_tracing_btf_ctx_access(off, size, type, prog, info))
		return false;

	if (base_type(info->reg_type) == PTR_TO_BTF_ID &&
	    !bpf_type_has_unsafe_modifiers(info->reg_type) &&
	    info->btf_id == btf_sock_ids[BTF_SOCK_TYPE_SOCK])
		/* promote it to tcp_sock */
		info->btf_id = btf_sock_ids[BTF_SOCK_TYPE_TCP];

	return true;
}

static int bpf_tcp_ops_init_member(const struct btf_type *t,
				   const struct btf_member *member,
				   void *kdata, const void *udata)
{
	return 0;
}

static int bpf_tcp_ops_init(struct btf *btf)
{
	return 0;
}

static int bpf_tcp_ops_validate(void *kdata)
{
	return 0;
}

static const struct bpf_verifier_ops bpf_tcp_ops_verifier = {
	.get_func_proto		= get_func_proto,
	.is_valid_access	= is_valid_access,
};

static struct bpf_struct_ops bpf_tcp_ops = {
	.verifier_ops = &bpf_tcp_ops_verifier,
	.init_member = bpf_tcp_ops_init_member,
	.init = bpf_tcp_ops_init,
	.validate = bpf_tcp_ops_validate,
	.name = "bpf_tcp_ops",
	.cgroup_atype = CGROUP_TCP_SOCK_OPS,
	.cfi_stubs = &__bpf_tcp_ops,
	.owner = THIS_MODULE,
};

static int __init __bpf_tcp_ops_init(void)
{
	return register_bpf_struct_ops(&bpf_tcp_ops, bpf_tcp_ops);
}
late_initcall(__bpf_tcp_ops_init)
