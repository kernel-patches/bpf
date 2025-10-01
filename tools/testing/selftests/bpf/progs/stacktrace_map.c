// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Facebook

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH         127
#endif

extern bool CONFIG_UNWINDER_ORC __kconfig __weak;

/* This function is here to have CONFIG_X86_KERNEL_IBT
 * used and added to object BTF.
 */
int unused(void)
{
	return CONFIG_UNWINDER_ORC ? 0 : 1;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} control_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u32);
} stackid_hmap SEC(".maps");

typedef __u64 stack_trace_t[PERF_MAX_STACK_DEPTH];

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stack_amap SEC(".maps");

/* taken from /sys/kernel/tracing/events/sched/sched_switch/format */
struct sched_switch_args {
	unsigned long long pad;
	char prev_comm[TASK_COMM_LEN];
	int prev_pid;
	int prev_prio;
	long long prev_state;
	char next_comm[TASK_COMM_LEN];
	int next_pid;
	int next_prio;
};

__u32 stack_id;
static inline void test_stackmap(void *ctx, int skip)
{
	__u32 max_len = PERF_MAX_STACK_DEPTH * sizeof(__u64);
	__u32 key = 0, val = 0, *value_p;
	void *stack_p;

	value_p = bpf_map_lookup_elem(&control_map, &key);
	if (value_p && *value_p)
		return; /* skip if non-zero *value_p */

	/* The size of stackmap and stackid_hmap should be the same */
	key = bpf_get_stackid(ctx, &stackmap, (u64) skip);
	if ((int)key >= 0) {
		stack_id = key;
		bpf_map_update_elem(&stackid_hmap, &key, &val, 0);
		stack_p = bpf_map_lookup_elem(&stack_amap, &key);
		if (stack_p)
			bpf_get_stack(ctx, stack_p, max_len, (u64) skip);
	}
}

/*
 * No tests in here, just to trigger 'bpf_fentry_test*'
 * through tracing test_run.
 */
SEC("fentry/bpf_modify_return_test")
int BPF_PROG(trigger)
{
	return 0;
}

SEC("tracepoint/sched/sched_switch")
int tp(struct sched_switch_args *ctx)
{
	test_stackmap(ctx, 0);
	return 0;
}

SEC("raw_tp/sched/sched_switch")
int raw_tp(struct sched_switch_args *ctx)
{
	test_stackmap(ctx, 1);
	return 0;
}

SEC("kprobe.multi")
int kprobe_multi_test(struct pt_regs *ctx)
{
	test_stackmap(ctx, 1);
	return 0;
}

SEC("kprobe")
int kprobe_test(struct pt_regs *ctx)
{
	test_stackmap(ctx, 1);
	return 0;
}

SEC("fentry/bpf_fentry_test1")
int BPF_PROG(fentry)
{
	test_stackmap(ctx, 1);
	return 0;
}

SEC("fexit/bpf_fentry_test1")
int BPF_PROG(fexit)
{
	test_stackmap(ctx, 1);
	return 0;
}

char _license[] SEC("license") = "GPL";
