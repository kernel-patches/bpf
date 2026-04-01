// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe.multi")
int handle_kprobe_multi_sleepable(struct pt_regs *ctx)
{
	return 0;
}

char _license[] SEC("license") = "GPL";
