// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 ips[9] = { };
unsigned int idx = 0;

SEC("fentry.ftrace/bpf_fentry_test*")
int BPF_PROG(test, __u64 ip, __u64 parent_ip)
{
	if (idx >= 0 && idx < 8)
		ips[idx++] = ip;
	return 0;
}
