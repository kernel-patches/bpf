// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

extern __u64 bpf_kfunc_call_test1(struct sock *sk, __u32 a, __u64 b,
				  __u32 c, __u64 d) __ksym;

__attribute__ ((noinline))
int f1(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;

	if (!sk)
		return -1;

	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return -1;

	return (__u32)bpf_kfunc_call_test1((struct sock *)sk, 1, 2, 3, 4);
}

SEC("classifier/test1_subprog")
int kfunc_call_test1(struct __sk_buff *skb)
{
	return f1(skb);
}

char _license[] SEC("license") = "GPL";
