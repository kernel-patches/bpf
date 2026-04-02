// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "../test_kmods/bpf_testmod_kfunc.h"

#if defined(__TARGET_ARCH_x86) && defined(__BPF_FEATURE_STACK_ARGUMENT)

const volatile bool has_stack_arg = true;

SEC("tc")
int test_stack_arg_scalar(struct __sk_buff *skb)
{
	return bpf_kfunc_call_stack_arg(1, 2, 3, 4, 5, 6, 7, 8);
}

SEC("tc")
int test_stack_arg_ptr(struct __sk_buff *skb)
{
	struct prog_test_pass1 p = { .x0 = 10, .x1 = 20 };

	return bpf_kfunc_call_stack_arg_ptr(1, 2, 3, 4, 5, &p);
}

SEC("tc")
int test_stack_arg_mix(struct __sk_buff *skb)
{
	struct prog_test_pass1 p = { .x0 = 10 };
	struct prog_test_pass1 q = { .x1 = 20 };

	return bpf_kfunc_call_stack_arg_mix(1, 2, 3, 4, 5, &p, 6, &q);
}

#else

const volatile bool has_stack_arg = false;

SEC("tc")
int test_stack_arg_scalar(struct __sk_buff *skb)
{
	return 0;
}

SEC("tc")
int test_stack_arg_ptr(struct __sk_buff *skb)
{
	return 0;
}

SEC("tc")
int test_stack_arg_mix(struct __sk_buff *skb)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
