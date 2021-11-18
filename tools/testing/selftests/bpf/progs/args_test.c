// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test1_result = 0;
SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1)
{
	__u64 a = bpf_arg(ctx, 0);
	__u64 x = bpf_arg(ctx, 1);

	test1_result = (int) a == 1 && x == 0;
	return 0;
}

__u64 test2_result = 0;
SEC("fexit/bpf_fentry_test2")
int BPF_PROG(test2)
{
	__u64 ret = bpf_ret_value(ctx);
	__u64 a = bpf_arg(ctx, 0);
	__u64 b = bpf_arg(ctx, 1);
	__u64 x = bpf_arg(ctx, 2);

	test2_result = (int) a == 2 && b == 3 && ret == 5 && x == 0;
	return 0;
}
