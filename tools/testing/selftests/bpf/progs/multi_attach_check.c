// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(test1, int a)
{
	return 0;
}

SEC("fexit/bpf_fentry_test2")
int BPF_PROG(test2, int a, __u64 b, int ret)
{
	return 0;
}

SEC("fentry.multi/bpf_fentry_test*")
int BPF_PROG(test3, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f)
{
	return 0;
}

SEC("fentry.multi/bpf_fentry_test1-7")
int BPF_PROG(test4, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	return 0;
}

SEC("fexit.multi/bpf_fentry_test1-7")
int BPF_PROG(test5, __u64 a, __u64 b, __u64 c, __u64 d, __u64 e, __u64 f, int ret)
{
	return 0;
}
