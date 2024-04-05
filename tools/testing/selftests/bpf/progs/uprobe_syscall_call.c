// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

struct pt_regs regs;

char _license[] SEC("license") = "GPL";

SEC("uretprobe//proc/self/exe:uretprobe_syscall_call")
int uretprobe(struct pt_regs *regs)
{
	bpf_printk("uretprobe called");
	return 0;
}
