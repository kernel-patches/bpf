// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

extern bool CONFIG_PREEMPTION __kconfig __weak;

volatile int ready;
volatile int release;
volatile int executions;
volatile int corruptions;
int loop_exhausted;

static long wait_for_release(__u32 index, void *ctx)
{
	return release ? 1 : 0;
}

/*
 * Test that preemptible uprobes don't use private stack. A 64-byte frame would
 * normally trigger private stack selection, but programs whose invocation can
 * be preempted must not use it. Both invocations must execute without
 * corruption.
 */
static __always_inline int run_stack_test(volatile __u64 *stack)
{
	__u64 id = bpf_get_current_pid_tgid();
	int seq;

	if (!CONFIG_PREEMPTION)
		return 0;

	stack[0] = id;
	seq = executions;
	executions = seq + 1;
	/*
	 * If private stack were used, an unguarded second invocation would
	 * overwrite the first invocation's frame. With regular stack, each task
	 * has its own stack frame.
	 */
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

SEC("uprobe.s//proc/self/exe:uprobe_sleepable_stack_trigger")
int uprobe_sleepable_large_stack(struct pt_regs *ctx)
{
	/* A 64-byte frame would select private stack for non-sleepable progs */
	volatile __u64 stack[8] = {};

	return run_stack_test(stack);
}

SEC("uprobe.s//proc/self/exe:uprobe_sleepable_stack_trigger")
int uprobe_sleepable_small_stack(struct pt_regs *ctx)
{
	/* Small stack as control - never triggers private stack */
	volatile __u64 stack[1] = {};

	return run_stack_test(stack);
}

SEC("uprobe.multi.s//proc/self/exe:uprobe_sleepable_stack_trigger")
int uprobe_multi_sleepable_large_stack(struct pt_regs *ctx)
{
	volatile __u64 stack[8] = {};

	return run_stack_test(stack);
}

SEC("uprobe.multi.s//proc/self/exe:uprobe_sleepable_stack_trigger")
int uprobe_multi_sleepable_small_stack(struct pt_regs *ctx)
{
	volatile __u64 stack[1] = {};

	return run_stack_test(stack);
}

char LICENSE[] SEC("license") = "GPL";
