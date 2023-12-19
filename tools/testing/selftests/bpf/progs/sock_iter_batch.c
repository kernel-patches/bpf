// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2023 Meta

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_tracing_net.h"
#include "bpf_kfuncs.h"

volatile const __u16 local_port;
volatile const char expected_char;

SEC("iter/tcp")
int iter_tcp_soreuse(struct bpf_iter__tcp *ctx)
{
	struct sock *sk = (struct sock *)ctx->sk_common;

	if (!sk)
		return 0;

	sk = bpf_rdonly_cast(sk, bpf_core_type_id_kernel(struct sock));
	if (sk->sk_family == AF_INET6 && sk->sk_num == local_port)
		bpf_seq_write(ctx->meta->seq, (void *)&expected_char, 1);

	return 0;
}

SEC("iter/udp")
int iter_udp_soreuse(struct bpf_iter__udp *ctx)
{
	struct sock *sk = (struct sock *)ctx->udp_sk;

	if (!sk)
		return 0;

	sk = bpf_rdonly_cast(sk, bpf_core_type_id_kernel(struct sock));
	if (sk->sk_family == AF_INET6 && sk->sk_num == local_port)
		bpf_seq_write(ctx->meta->seq, (void *)&expected_char, 1);

	return 0;
}

char _license[] SEC("license") = "GPL";
