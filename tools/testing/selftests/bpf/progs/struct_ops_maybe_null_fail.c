// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../bpf_testmod/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

int tgid = 0;
u32 scalar_value = 0;

/* These are test BPF struct_ops programs that demonstrates the access of
 * an argument that may be NULL.  These test programs are used to ensure
 * that the verifier correctly catches the case where a pointer is not
 * checked for NULL before dereferencing it.
 */

/* Test for pointer to a struct type. */
SEC("struct_ops/test_maybe_null_struct_ptr")
int BPF_PROG(test_maybe_null_struct_ptr, int dummy,
	     struct task_struct *task,
	     u32 *scalar,
	     u32 (*ar)[2],
	     u32 (*ar2)[])
{
	tgid = task->tgid;

	return 0;
}

/* Test for pointer to a scalar type. */
SEC("struct_ops/test_maybe_null_scalar_ptr")
int BPF_PROG(test_maybe_null_scalar_ptr, int dummy,
	     struct task_struct *task,
	     u32 *scalar,
	     u32 (*ar)[2],
	     u32 (*ar2)[])
{
	scalar_value = *scalar;

	return 0;
}

/* Test for pointer to an array type. */
SEC("struct_ops/test_maybe_null_array_ptr")
int BPF_PROG(test_maybe_null_array_ptr, int dummy,
	     struct task_struct *task,
	     u32 *scalar,
	     u32 (*ar)[2],
	     u32 (*ar2)[])
{
	scalar_value += (*ar)[0];
	scalar_value += (*ar)[1];

	return 0;
}

/* Test for pointer to a variable length array type.
 *
 * This test program is used to ensure that the verifier correctly rejects
 * the case that access the content of a variable length array even
 * checking the pointer for NULL beforhand since the verifier doesn't know
 * the exact size of the array.
 */
SEC("struct_ops/test_maybe_null_var_array_ptr")
int BPF_PROG(test_maybe_null_var_array_ptr, int dummy,
	     struct task_struct *task,
	     u32 *scalar,
	     u32 (*ar)[2],
	     u32 (*ar2)[])
{
	if (ar2)
		scalar_value += (*ar2)[0];

	return 0;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_struct_ptr = {
	.test_maybe_null = (void *)test_maybe_null_struct_ptr,
};

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_scalar_ptr = {
	.test_maybe_null = (void *)test_maybe_null_scalar_ptr,
};

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_array_ptr = {
	.test_maybe_null = (void *)test_maybe_null_array_ptr,
};

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_var_array_ptr = {
	.test_maybe_null = (void *)test_maybe_null_var_array_ptr,
};

