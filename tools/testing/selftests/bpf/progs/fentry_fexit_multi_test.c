// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "multi_check.h"

char _license[] SEC("license") = "GPL";

MULTI_ARG_CHECK(fentry)
MULTI_ARG_CHECK(fexit)

unsigned long long bpf_fentry_test[8];

__u64 test1_arg_result = 0;
__u64 test2_arg_result = 0;
__u64 test2_ret_result = 0;

SEC("fentry.multi/bpf_fentry_test*")
int BPF_PROG(test1, unsigned long ip, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f)
{
	fentry_multi_arg_check(ip, a, b, c, d, e, f, &test1_arg_result);
	return 0;
}

SEC("fexit.multi/")
int BPF_PROG(test2, unsigned long ip, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	fexit_multi_arg_check(ip, a, b, c, d, e, f, &test2_arg_result);
	multi_ret_check(ip, ret, &test2_ret_result);
	return 0;
}
