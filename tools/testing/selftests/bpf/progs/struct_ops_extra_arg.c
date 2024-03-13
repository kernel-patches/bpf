// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

int test_1_result = 0;
int test_2_result = 0;

SEC("struct_ops/test_1")
int BPF_PROG(test_1)
{
	test_1_result = 0xdeadbeef;
	return 0;
}

SEC("?struct_ops/test_2")
void BPF_PROG(test_2, int a, int b)
{
	test_2_result = a + b;
}

SEC("?struct_ops/test_extra_arg")
void BPF_PROG(test_extra_arg, int a, int b, int extra_arg)
{
	/* Accessing extra_arg will cause a verifier error since it
	 * accesses the context data beyond the size of the context.
	 */
	test_2_result = a + b + extra_arg + 3;
}

SEC("?struct_ops/test_extra_arg_unused")
void BPF_PROG(test_extra_arg_unused, int a, int b, int extra_arg)
{
	/* The extra_arg is not used, so it should not cause a verifier
	 * error.
	 */
	test_2_result = a + b + 3;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_1 = {
	.test_1 = (void *)test_1,
	.test_2 = (void *)test_extra_arg,
	.data = 0x1,
};
