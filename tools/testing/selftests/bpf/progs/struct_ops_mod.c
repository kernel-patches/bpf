// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../test_kmods/bpf_testmod.h"

char _license[] SEC("license") = "GPL";

int test_1_cnt = 0;
int testmod_1_result = 0;
int testmod_2_result = 0;

SEC("struct_ops/test_1")
int BPF_PROG(test_1)
{
	test_1_cnt++;
	return 0;
}

SEC("struct_ops/test_2")
void BPF_PROG(test_2, int a, int b)
{
	testmod_1_result = a + b;
}

SEC("struct_ops/test_2_v2")
void BPF_PROG(test_2_v2, int a, int b)
{
	testmod_2_result = a * b;
}

SEC(".struct_ops.link")
struct bpf_testmod_ops testmod_1 = {
	.test_1 = (void *)test_1,
	.test_2 = (void *)test_2,
	.data = 13,
};

struct bpf_testmod_ops___v2 {
	int data;
	void (*test_2)(int a, int b);
	int (*test_1)(void);
};

SEC(".struct_ops.link")
struct bpf_testmod_ops___v2 testmod_2 = {
	.data = 7,
	.test_2 = (void *)test_2_v2,
	.test_1 = (void *)test_1,
};
