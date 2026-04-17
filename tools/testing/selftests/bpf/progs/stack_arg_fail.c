// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

#if defined(__BPF_FEATURE_STACK_ARGUMENT)

const volatile bool has_stack_arg = true;

SEC("tc")
int test_stack_arg_big(struct __sk_buff *skb)
{
	struct prog_test_big_arg s = { .a = 1, .b = 2 };

	return bpf_kfunc_call_stack_arg_big(1, 2, 3, 4, 5, s);
}

#else

const volatile bool has_stack_arg = false;

SEC("tc")
int test_stack_arg_big(struct __sk_buff *skb)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
