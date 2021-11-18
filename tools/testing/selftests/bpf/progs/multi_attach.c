// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__hidden extern void multi_arg_check(__u64 *ctx, __u64 *test_result);
__hidden extern void multi_ret_check(void *ctx, __u64 *test_result);

__u64 test_result1 = 0;

SEC("fentry.multi/bpf_fentry_test1-5")
int BPF_PROG(test1, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	multi_arg_check(ctx, &test_result1);
	return 0;
}

__u64 test_result2 = 0;

SEC("fentry.multi/bpf_fentry_test4-8")
int BPF_PROG(test2, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	multi_arg_check(ctx, &test_result2);
	return 0;
}

__u64 test_result3 = 0;

SEC("fexit.multi/bpf_fentry_test1-5")
int BPF_PROG(test3, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	__u64 arg_result = 0, ret_result = 0;

	multi_arg_check(ctx, &arg_result);
	multi_ret_check(ctx, &ret_result);

	if (arg_result && ret_result)
		test_result3 += 1;
	return 0;
}

__u64 test_result4 = 0;

SEC("fexit.multi/bpf_fentry_test4-8")
int BPF_PROG(test4, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	__u64 arg_result = 0, ret_result = 0;

	multi_arg_check(ctx, &arg_result);
	multi_ret_check(ctx, &ret_result);

	if (arg_result && ret_result)
		test_result4 += 1;
	return 0;
}

__u64 test_result5 = 0;

SEC("fentry.multi/bpf_fentry_test1-8")
int BPF_PROG(test5, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f)
{
	multi_arg_check(ctx, &test_result5);
	return 0;
}

__u64 test_result6 = 0;

SEC("fexit.multi/bpf_fentry_test1-8")
int BPF_PROG(test6, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f)
{
	__u64 arg_result = 0, ret_result = 0;

	multi_arg_check(ctx, &arg_result);
	multi_ret_check(ctx, &ret_result);

	if (arg_result && ret_result)
		test_result6 += 1;
	return 0;
}

__u64 test_result7 = 0;

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test7, int a)
{
	multi_arg_check(ctx, &test_result7);
	return 0;
}

__u64 test_result8 = 0;

SEC("fexit/bpf_fentry_test2")
int BPF_PROG(test8, int a, __u64 b, int ret)
{
	__u64 arg_result = 0, ret_result = 0;

	multi_arg_check(ctx, &arg_result);
	multi_ret_check(ctx, &ret_result);

	if (arg_result && ret_result)
		test_result8 += 1;
	return 0;
}
