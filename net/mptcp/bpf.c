// SPDX-License-Identifier: GPL-2.0
/* Multipath TCP
 *
 * Copyright (c) 2020, Tessares SA.
 * Copyright (c) 2022, SUSE.
 *
 * Author: Nicolas Rybowski <nicolas.rybowski@tessares.net>
 */

#define pr_fmt(fmt) "MPTCP: " fmt

#include <linux/bpf.h>
#include "protocol.h"

struct mptcp_sock *bpf_mptcp_sock_from_subflow(struct sock *sk)
{
	if (sk && sk_fullsock(sk) && sk->sk_protocol == IPPROTO_TCP && sk_is_mptcp(sk))
		return mptcp_sk(mptcp_subflow_ctx(sk)->conn);

	return NULL;
}

BPF_CALL_3(bpf_mptcpify, int *, family, int *, type, int *, protocol)
{
	if ((*family == AF_INET || *family == AF_INET6) &&
	    *type == SOCK_STREAM &&
	    (!*protocol || *protocol == IPPROTO_TCP)) {
		*protocol = IPPROTO_MPTCP;
	}

	return 0;
}

const struct bpf_func_proto bpf_mptcpify_proto = {
	.func		= bpf_mptcpify,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};
