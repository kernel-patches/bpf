// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test1_result = 0;
SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	test1_result = 1;
	return 0;
}

__u64 test2_result = 0;
SEC("fentry/bpf_fentry_test2")
int BPF_PROG(test2, int a, __u64 b)
{
	test2_result = 1;
	return 0;
}

__u64 test3_result = 0;
SEC("fentry/bpf_fentry_test3")
int BPF_PROG(test3, char a, int b, __u64 c)
{
	test3_result = 1;
	return 0;
}

__u64 test4_result = 0;
SEC("fentry/bpf_fentry_test4")
int BPF_PROG(test4, void *a, char b, int c, __u64 d)
{
	test4_result = 1;
	return 0;
}

__u64 test5_result = 0;
SEC("fentry/bpf_fentry_test5")
int BPF_PROG(test5, __u64 a, void *b, short c, int d, __u64 e)
{
	test5_result = 1;
	return 0;
}

__u64 test6_result = 0;
SEC("fentry/bpf_fentry_test6")
int BPF_PROG(test6, __u64 a, void *b, short c, int d, void * e, __u64 f)
{
	test6_result = 1;
	return 0;
}

struct bpf_fentry_test_t {
	struct bpf_fentry_test_t *a;
};

__u64 test7_result = 0;
SEC("fentry/bpf_fentry_test7")
int BPF_PROG(test7, struct bpf_fentry_test_t *arg)
{
	test7_result = 1;
	return 0;
}

__u64 test8_result = 0;
SEC("fentry/bpf_fentry_test8")
int BPF_PROG(test8, struct bpf_fentry_test_t *arg)
{
	test8_result = 1;
	return 0;
}
