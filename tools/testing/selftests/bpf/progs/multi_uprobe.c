// SPDX-License-Identifier: GPL-2.0

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

__u64 test_uprobe_result = 0;

SEC("uprobe/trigger_func")
int handle_uprobe(struct pt_regs *ctx)
{
	test_uprobe_result++;
	return 0;
}

__u64 test_uretprobe_result = 0;

SEC("uretprobe/trigger_func")
int handle_uretprobe(struct pt_regs *ctx)
{
	test_uretprobe_result++;
	return 0;
}

char _license[] SEC("license") = "GPL";
