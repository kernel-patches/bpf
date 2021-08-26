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
