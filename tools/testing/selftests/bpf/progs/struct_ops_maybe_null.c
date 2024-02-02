// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

u64 tgid = 0;
u32 scalar_value = 0;

/* This is a test BPF program that uses struct_ops to access an argument
 * that may be NULL. This is a test for the verifier to ensure that it can
 * rip PTR_MAYBE_NULL correctly. There are tree pointers; task, scalar, and
 * ar. They are used to test the cases of PTR_TO_BTF_ID, PTR_TO_BUF, and array.
 */
SEC("struct_ops/test_maybe_null")
int BPF_PROG(test_maybe_null, int dummy,
	     struct task_struct *task,
	     u32 *scalar,
	     u32 (*ar)[2],
	     u32 (*ar2)[])
{
	if (task)
		tgid = task->tgid;

	if (scalar)
		scalar_value = *scalar;

	if (*ar)
		scalar_value += (*ar)[0];

	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_1 = {
	.test_maybe_null = (void *)test_maybe_null,
};

