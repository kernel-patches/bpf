// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("fexit/bpf_fentry_test3")
int BPF_PROG(test3, int a, __u64 b, int ret)
{
	return 0;
}
