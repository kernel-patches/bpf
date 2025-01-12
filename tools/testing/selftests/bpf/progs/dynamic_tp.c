// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

#define MAX_STACK_TRACE_DEPTH 32
unsigned long entries[MAX_STACK_TRACE_DEPTH] = {};
#define SIZE_OF_ULONG (sizeof(unsigned long))

int result, pid;

SEC("kprobe/kprobes/my_dynamic_tp")
int dynamic_tp(struct pt_regs *ctx)
{
	int ret;

	ret = bpf_get_stack(ctx, entries, MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG, 0);
	if (ret < 0) {
		result = -1;
		return ret;
	}
	if (bpf_get_current_pid_tgid() >> 32 == pid)
		result = 1;
	return 0;
}
