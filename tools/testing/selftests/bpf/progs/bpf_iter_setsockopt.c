// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include "bpf_iter.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, int);
} sk_map SEC(".maps");

#define bpf_tcp_sk(skc)	({				\
	struct sock_common *_skc = skc;			\
	sk = NULL;					\
	tp = NULL;					\
	if (_skc) {					\
		tp = bpf_skc_to_tcp_sock(_skc);		\
		sk = (struct sock *)tp;			\
	}						\
	tp;						\
})

unsigned short reuse_listen_hport = 0;
unsigned short listen_hport = 0;
char cubic_cc[TCP_CA_NAME_MAX] = "bpf_cubic";
char dctcp_cc[TCP_CA_NAME_MAX] = "bpf_dctcp";
bool random_retry = false;
bool cong = false;

static bool tcp_cc_eq(const char *a, const char *b)
{
	int i;

	for (i = 0; i < TCP_CA_NAME_MAX; i++) {
		if (a[i] != b[i])
			return false;
		if (!a[i])
			break;
	}

	return true;
}

/* This program is used to intercept getsockopt() calls, providing
 * the value of bpf_sock_ops_cb_flags for the socket; this value
 * has been saved in per-socket storage earlier via the iterator
 * program.
 */
SEC("cgroup/getsockopt")
int _getsockopt(struct bpf_sockopt *ctx)
{
	struct bpf_sock *sk = ctx->sk;
	int *optval = ctx->optval;
	int *sk_storage = 0;

	if (!sk || ctx->level != SOL_TCP || ctx->optname != TCP_BPF_SOCK_OPS_CB_FLAGS)
		return 1;
	sk_storage = bpf_sk_storage_get(&sk_map, sk, 0, 0);
	if (sk_storage) {
		if (ctx->optval + sizeof(int) <= ctx->optval_end)
			*optval = *sk_storage;
		ctx->retval = 0;
	}
	return 1;
}

SEC("iter/tcp")
int change_tcp_val(struct bpf_iter__tcp *ctx)
{
	struct tcp_sock *tp;
	struct sock *sk;

	if (!bpf_tcp_sk(ctx->sk_common))
		return 0;

	if (sk->sk_family != AF_INET6 ||
	    (sk->sk_state != TCP_LISTEN &&
	     sk->sk_state != TCP_ESTABLISHED) ||
	    (sk->sk_num != reuse_listen_hport &&
	     sk->sk_num != listen_hport &&
	     bpf_ntohs(sk->sk_dport) != listen_hport))
		return 0;

	if (cong) {
		char cur_cc[TCP_CA_NAME_MAX];

		if (bpf_getsockopt(tp, SOL_TCP, TCP_CONGESTION,
				   cur_cc, sizeof(cur_cc)))
			return 0;

		if (!tcp_cc_eq(cur_cc, cubic_cc))
			return 0;

		if (random_retry && bpf_get_prandom_u32() % 4 == 1)
			return 1;

		bpf_setsockopt(tp, SOL_TCP, TCP_CONGESTION, dctcp_cc, sizeof(dctcp_cc));
	} else {
		int val, newval = BPF_SOCK_OPS_ALL_CB_FLAGS;
		int *sk_storage;

		if (bpf_getsockopt(tp, SOL_TCP, TCP_BPF_SOCK_OPS_CB_FLAGS,
				   &val, sizeof(val)))
			return 0;

		if (val == newval)
			return 0;

		if (random_retry && bpf_get_prandom_u32() % 4 == 1)
			return 1;

		if (bpf_setsockopt(tp, SOL_TCP, TCP_BPF_SOCK_OPS_CB_FLAGS,
				   &newval, sizeof(newval)))
			return 0;
		/* store flags value for retrieval in cgroup/getsockopt prog */
		sk_storage = bpf_sk_storage_get(&sk_map, sk, 0,
						BPF_SK_STORAGE_GET_F_CREATE);
		if (sk_storage)
			*sk_storage = newval;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
