// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(void *ctx)
{
	static const char msg[] = "Hello, BPF World!\n";

	bpf_trace_printk(msg, sizeof(msg));
	return 0;
}

char _license[] SEC("license") = "GPL";
