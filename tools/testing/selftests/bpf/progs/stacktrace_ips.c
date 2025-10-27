// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH         127
#endif

typedef __u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stackmap SEC(".maps");

extern bool CONFIG_UNWINDER_ORC __kconfig __weak;

/*
 * This function is here to have CONFIG_UNWINDER_ORC
 * used and added to object BTF.
 */
int unused(void)
{
	return CONFIG_UNWINDER_ORC ? 0 : 1;
}

__u32 stack_key;

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run.
 */
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(trigger)
{
       return 0;
}

SEC("kprobe.multi")
int kprobe_multi_stack_test(struct pt_regs *ctx)
{
	stack_key = bpf_get_stackid(ctx, &stackmap, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
