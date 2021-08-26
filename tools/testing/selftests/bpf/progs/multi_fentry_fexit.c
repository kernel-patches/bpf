// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test1_arg_result = 0;
__u64 test2_arg_result = 0;
__u64 test2_ret_result = 0;

__hidden extern void multi_arg_check(__u64 *ctx, __u64 *test_result);
__hidden extern void multi_ret_check(void *ctx, int ret, __u64 *test_result);

SEC("fentry.multi/bpf_fentry_test*")
int BPF_PROG(test1, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f)
{
	multi_arg_check(ctx, &test1_arg_result);
	return 0;
}

SEC("fexit.multi/bpf_fentry_test*")
int BPF_PROG(test2, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	multi_arg_check(ctx, &test2_arg_result);
	multi_ret_check(ctx, ret, &test2_ret_result);
	return 0;
}
