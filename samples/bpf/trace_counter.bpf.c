// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, u32);
	__uint(max_entries, 1);
} counters SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} values_begin SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 1);
} task_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, 4);
} func_stat SEC(".maps");

#define TRACE_MODE_FUNCTION	(1 << 0)

const volatile int trace_mode;

static volatile bool func_trace_enabled;
static u64 func_duration;

static bool trace_is_enabled(void)
{
	/* The trace_mode is zero, traces for whole program. */
	if (!trace_mode)
		return true;

	/* Tracing for the function will wait until the function is hit. */
	if ((trace_mode & TRACE_MODE_FUNCTION) && func_trace_enabled)
		return true;

	return false;
}

static bool task_is_traced(u32 pid)
{
	u32 *pid_filter;
	int key = 0;

	pid_filter = bpf_map_lookup_elem(&task_filter, &key);
	if (!pid_filter)
		return false;

	if (*pid_filter == pid)
		return true;

	return false;
}

static int record_begin_values(void)
{
	u64 count, *start;
	u32 cpu = bpf_get_smp_processor_id();
	s64 error;

	count = bpf_perf_event_read(&counters, 0);
	error = (s64)count;
	if (error <= -2 && error >= -22)
		return 0;

	start = bpf_map_lookup_elem(&values_begin, &cpu);
	if (start)
		*start = count;
	else
		bpf_map_update_elem(&values_begin, &cpu, &count, BPF_NOEXIST);

	return 0;
}

static int record_end_values(void)
{
	u64 count, *start, *value, interval;
	u32 cpu = bpf_get_smp_processor_id();
	s64 error;

	count = bpf_perf_event_read(&counters, 0);
	error = (s64)count;
	if (error <= -2 && error >= -22)
		return 0;

	start = bpf_map_lookup_elem(&values_begin, &cpu);
	/* It must be wrong if failed to read out start values, bail out. */
	if (!start || *start == -1)
		return 0;

	interval = count - *start;
	if (!interval)
		return 0;

	/* Record the interval */
	value = bpf_map_lookup_elem(&values, &cpu);
	if (value)
		*value = *value + interval;
	else
		bpf_map_update_elem(&values, &cpu, &interval, BPF_NOEXIST);

	if (func_trace_enabled)
		func_duration += interval;

	*start = -1;
	return 0;
}

static int stat_function(void)
{
	int key;
	u64 *count, *min, *max, init = 1;

	/* Update function entering count */
	key = 0;
	count = bpf_map_lookup_elem(&func_stat, &key);
	if (count)
		*count += 1;
	else
		bpf_map_update_elem(&func_stat, &key, &init, BPF_NOEXIST);

	/* Update function minimum duration */
	key = 1;
	min = bpf_map_lookup_elem(&func_stat, &key);
	if (min) {
		if (func_duration < *min)
			*min = func_duration;
	} else {
		bpf_map_update_elem(&func_stat, &key, &func_duration, BPF_NOEXIST);
	}

	/* Update function maximum duration */
	key = 2;
	max = bpf_map_lookup_elem(&func_stat, &key);
	if (max) {
		if (func_duration > *max)
			*max = func_duration;
	} else {
		bpf_map_update_elem(&func_stat, &key, &func_duration, BPF_NOEXIST);
	}

	return 0;
}

SEC("kretprobe/finish_task_switch")
int schedule_in(struct pt_regs *ctx)
{
	if (!trace_is_enabled())
		return 0;

	if (!task_is_traced(bpf_get_current_pid_tgid()))
		return 0;

	return record_begin_values();
}

SEC("tracepoint/sched/sched_switch")
int schedule_out(struct trace_event_raw_sched_switch *ctx)
{
	if (!trace_is_enabled())
		return 0;

	if (!task_is_traced(ctx->prev_pid))
		return 0;

	return record_end_values();
}

SEC("uprobe/func")
int BPF_PROG(func_begin)
{
	int key = 0;
	u32 *trace_mode;

	if (!task_is_traced(bpf_get_current_pid_tgid()))
		return 0;

	func_trace_enabled = true;
	func_duration = 0;
	return record_begin_values();
}

SEC("uretprobe/func")
int BPF_PROG(func_exit)
{
	int key = 0;
	u32 *trace_mode;

	if (!task_is_traced(bpf_get_current_pid_tgid()))
		return 0;

	record_end_values();
	func_trace_enabled = false;
	return stat_function();
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
