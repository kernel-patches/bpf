// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("uprobe.session")
int uprobe_session_0(struct pt_regs *ctx)
{
	return 0;
}

SEC("uprobe.session")
int uprobe_session_1(struct pt_regs *ctx)
{
	return 1;
}

SEC("uprobe.multi")
int uprobe(struct pt_regs *ctx)
{
	return 0;
}

SEC("uprobe.multi")
int uretprobe(struct pt_regs *ctx)
{
	return 0;
}
