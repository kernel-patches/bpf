// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Justin Suess */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

/* bpf_kfunc_call_test3() returns its __derives_ret argument. */

SEC("tc")
__success
int derived_sock_used_before_release(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct sock *derived;
	struct bpf_sock *sk;
	int state;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return 0;

	derived = bpf_kfunc_call_test3((struct sock *)sk);
	state = derived->__sk_common.skc_state;
	bpf_sk_release(sk);
	return state;
}

SEC("tc")
__failure __msg("invalid mem access 'scalar'")
int derived_sock_outlives_release(struct __sk_buff *skb)
{
	struct bpf_sock_tuple tuple = {};
	struct sock *derived;
	struct bpf_sock *sk;

	sk = bpf_sk_lookup_tcp(skb, &tuple, sizeof(tuple.ipv4), BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return 0;

	derived = bpf_kfunc_call_test3((struct sock *)sk);
	bpf_sk_release(sk);

	/* derived was pinned by sk's reference and died with it. */
	return derived->__sk_common.skc_state;
}

char _license[] SEC("license") = "GPL";
