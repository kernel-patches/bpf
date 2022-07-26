// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

struct bpf_testmod_struct_arg_1 {
        int a;
};
struct bpf_testmod_struct_arg_2 {
        long a;
        long b;
};

long t1_a_a, t1_a_b, t1_b, t1_c;
long t2_a, t2_b_a, t2_b_b, t2_c;
long t3_a, t3_b, t3_c_a, t3_c_b;
long t4_a_a, t4_b, t4_c, t4_d, t4_e_a, t4_e_b;

SEC("fentry/bpf_testmod_test_struct_arg_1")
int BPF_PROG(test_struct_arg_1, struct bpf_testmod_struct_arg_2 *a, int b, int c)
{
	t1_a_a = a->a;
	t1_a_b = a->b;
	t1_b = b;
	t1_c = c;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_2")
int BPF_PROG(test_struct_arg_2, int a, struct bpf_testmod_struct_arg_2 *b, int c)
{
	t2_a = a;
	t2_b_a = b->a;
	t2_b_b = b->b;
	t2_c = c;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_3")
int BPF_PROG(test_struct_arg_3, int a, int b, struct bpf_testmod_struct_arg_2 *c)
{
	t3_a = a;
	t3_b = b;
	t3_c_a = c->a;
	t3_c_b = c->b;
	return 0;
}

SEC("fentry/bpf_testmod_test_struct_arg_4")
int BPF_PROG(test_struct_arg_4, struct bpf_testmod_struct_arg_1 *a, int b,
	     int c, int d, struct bpf_testmod_struct_arg_2 *e)
{
	t4_a_a = a->a;
	t4_b = b;
	t4_c = c;
	t4_d = d;
	t4_e_a = e->a;
	t4_e_b = e->b;
	return 0;
}

char _license[] SEC("license") = "GPL";
