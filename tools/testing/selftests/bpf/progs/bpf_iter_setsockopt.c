// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include "bpf_iter.h"
#include "bpf_tracing_net.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define sk_num			__sk_common.skc_num
#define sk_dport		__sk_common.skc_dport
#define sk_state		__sk_common.skc_state
#define sk_family		__sk_common.skc_family

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
char old_cc[TCP_CA_NAME_MAX] = "bpf_cubic";
char new_cc[TCP_CA_NAME_MAX] = "bpf_dctcp";
bool random_retry = false;

static bool tcp_ca_eq(const char *a, const char *b)
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

SEC("iter/tcp")
int change_tcp_cc(struct bpf_iter__tcp *ctx)
{
	struct bpf_iter_meta *meta = ctx->meta;
	struct inet_connection_sock *icsk;
	struct seq_file *seq = meta->seq;
	struct tcp_sock *tp;
	struct sock *sk;
	int ret;

	if (!bpf_tcp_sk(ctx->sk_common))
		return 0;

	if (sk->sk_family != AF_INET6 ||
	    (sk->sk_state != TCP_LISTEN &&
	     sk->sk_state != TCP_ESTABLISHED) ||
	    (sk->sk_num != reuse_listen_hport &&
	     sk->sk_num != listen_hport &&
	     bpf_ntohs(sk->sk_dport) != listen_hport))
		return 0;

	icsk = (struct inet_connection_sock *)tp;
	if (!tcp_ca_eq(icsk->icsk_ca_ops->name, old_cc))
		return 0;

	if (random_retry && bpf_get_prandom_u32() % 4 == 1)
		return 1;

	bpf_setsockopt(tp, SOL_TCP, TCP_CONGESTION, new_cc, sizeof(new_cc));
	return 0;
}

char _license[] SEC("license") = "GPL";
