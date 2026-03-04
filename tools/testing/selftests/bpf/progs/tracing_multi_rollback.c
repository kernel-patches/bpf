// SPDX-License-Identifier: GPL-2.0
#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 test_result_fentry = 0;
__u64 test_result_fexit = 0;

SEC("?fentry.multi")
int BPF_PROG(test_fentry)
{
	test_result_fentry++;
	return 0;
}

SEC("?fexit.multi")
int BPF_PROG(test_fexit)
{
	test_result_fexit++;
	return 0;
}

SEC("?fentry/bpf_fentry_test10")
int BPF_PROG(filler)
{
	return 0;
}
