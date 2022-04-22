// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Tessares SA. */

#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_mptcp_helpers.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;

struct mptcp_storage {
	__u32 invoked;
	__u32 is_mptcp;
	__u32 token;
	char ca_name[TCP_CA_NAME_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct mptcp_storage);
} socket_storage_map SEC(".maps");

SEC("sockops")
int _sockops(struct bpf_sock_ops *ctx)
{
	struct mptcp_storage *storage;
	struct bpf_tcp_sock *tcp_sk;
	struct mptcp_sock *msk;
	int op = (int)ctx->op;
	struct bpf_sock *sk;

	if (op != BPF_SOCK_OPS_TCP_CONNECT_CB)
		return 1;

	sk = ctx->sk;
	if (!sk)
		return 1;

	tcp_sk = bpf_tcp_sock(sk);
	if (!tcp_sk)
		return 1;

	if (!tcp_sk->is_mptcp) {
		storage = bpf_sk_storage_get(&socket_storage_map, sk, 0,
					     BPF_SK_STORAGE_GET_F_CREATE);
		if (!storage)
			return 1;

		storage->token = 0;
		bzero(storage->ca_name, TCP_CA_NAME_MAX);
	} else {
		msk = bpf_skc_to_mptcp_sock(sk);
		if (!msk)
			return 1;

		storage = bpf_sk_storage_get(&socket_storage_map, msk, 0,
					     BPF_SK_STORAGE_GET_F_CREATE);
		if (!storage)
			return 1;

		storage->token = msk->token;
		memcpy(storage->ca_name, msk->ca_name, TCP_CA_NAME_MAX);
	}
	storage->invoked++;
	storage->is_mptcp = tcp_sk->is_mptcp;

	return 1;
}
