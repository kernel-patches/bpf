// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("uretprobe.multi/./uprobe_compat:main")
int uretprobe_compat(struct pt_regs *ctx)
{
	bpf_printk("uretprobe compat\n");
	return 0;
}
