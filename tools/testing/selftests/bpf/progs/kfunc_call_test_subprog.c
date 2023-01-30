// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_tcp_helpers.h"

/*
 * We can't include vmlinux.h, because it conflicts with bpf_tcp_helpers.h,
 * but we need refcount_t typedef for bpf_testmod_kfunc.h.
 * Adding it directly.
 */
typedef struct {
	int counter;
} atomic_t;
typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;

#include "bpf_testmod/bpf_testmod_kfunc.h"

extern const int bpf_prog_active __ksym;
int active_res = -1;
int sk_state_res = -1;

int __noinline f1(struct __sk_buff *skb)
{
	struct bpf_sock *sk = skb->sk;
	int *active;

	if (!sk)
		return -1;

	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return -1;

	active = (int *)bpf_per_cpu_ptr(&bpf_prog_active,
					bpf_get_smp_processor_id());
	if (active)
		active_res = *active;

	sk_state_res = bpf_kfunc_call_test3((struct sock *)sk)->sk_state;

	return (__u32)bpf_kfunc_call_test1((struct sock *)sk, 1, 2, 3, 4);
}

SEC("tc")
int kfunc_call_test1(struct __sk_buff *skb)
{
	return f1(skb);
}

char _license[] SEC("license") = "GPL";
