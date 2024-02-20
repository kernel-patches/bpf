// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 ByteDance */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct bpf_testmod_struct_arg_1 {
	int a;
};
struct bpf_testmod_struct_arg_2 {
	long a;
	long b;
};

__u64 fentry_test1_result = 0;
SEC("fentry/bpf_testmod_test_struct_arg_1")
int BPF_PROG2(fentry_test1, struct bpf_testmod_struct_arg_2, a)
{
	fentry_test1_result = a.a + a.b;
	return 0;
}

__u64 fentry_test2_result = 0;
SEC("fentry/bpf_testmod_test_struct_arg_2")
int BPF_PROG2(fentry_test2, int, a, struct bpf_testmod_struct_arg_2, b)
{
	fentry_test2_result = a + b.a + b.b;
	return 0;
}

__u64 fentry_test3_result = 0;
SEC("fentry/bpf_testmod_test_arg_ptr_2")
int BPF_PROG(fentry_test3, struct bpf_testmod_struct_arg_2 *a)
{
	fentry_test3_result = a->a + a->b;
	return 0;
}

__u64 fentry_test4_result = 0;
SEC("fentry/bpf_testmod_test_struct_arg_1")
int BPF_PROG2(fentry_test4, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c)
{
	fentry_test3_result = c;
	return 0;
}

__u64 fexit_test1_result = 0;
SEC("fexit/bpf_testmod_test_struct_arg_1")
int BPF_PROG2(fexit_test1, struct bpf_testmod_struct_arg_2, a, int, b,
	      int, c, int, retval)
{
	fexit_test1_result = retval;
	return 0;
}

__u64 fexit_test2_result = 0;
SEC("fexit/bpf_testmod_test_struct_arg_2")
int BPF_PROG2(fexit_test2, int, a, struct bpf_testmod_struct_arg_2, b,
	      int, c, int, retval)
{
	fexit_test2_result = a + b.a + b.b + retval;
	return 0;
}

SEC("fmod_ret/bpf_modify_return_test")
int BPF_PROG(fmod_ret_test1, int a, int *b)
{
	return 0;
}
