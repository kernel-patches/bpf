// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

char _license[] SEC("license") = "GPL";
unsigned long executed = 0;

SEC("uprobe")
int BPF_UPROBE(test_1)
{
	executed++;
	return 0;
}

SEC("uprobe.multi")
int BPF_UPROBE(test_2)
{
	executed++;
	return 0;
}

SEC("usdt")
int test_3(struct pt_regs *ctx)
{
	executed++;
	return 0;
}
