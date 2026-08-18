// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

volatile int ready;
volatile int release;
volatile int executions;
volatile int corruptions;
int loop_exhausted;

static long wait_for_release(__u32 index, void *ctx)
{
	return release ? 1 : 0;
}

static __always_inline int run_private_stack_test(void)
{
	/* A 64-byte frame makes the JIT select a private stack. */
	volatile __u64 stack[8] = {};
	__u64 id = bpf_get_current_pid_tgid();
	int seq;

	stack[0] = id;
	seq = executions;
	executions = seq + 1;
	/* An unguarded second invocation overwrites the first invocation's frame. */
	if (seq) {
		stack[0] = ~id;
		return 0;
	}

	ready = 1;
	bpf_loop(1 << 23, wait_for_release, NULL, 0);
	if (!release)
		loop_exhausted = 1;
	if (stack[0] != id)
		corruptions++;

	return 0;
}

SEC("uprobe")
int uprobe_private_stack(struct pt_regs *ctx)
{
	return run_private_stack_test();
}

SEC("uprobe.multi")
int uprobe_multi_private_stack(struct pt_regs *ctx)
{
	return run_private_stack_test();
}

char LICENSE[] SEC("license") = "GPL";
