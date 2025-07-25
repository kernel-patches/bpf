// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Copyright 2025 Arm Limited
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(max_entries, 1);
} cpu_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u8));
	__uint(max_entries, 1);
} task_filter SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1);
} events SEC(".maps");

int enabled = 0;

const volatile int has_cpu = 0;
const volatile int has_task = 0;
const volatile int per_thread = 0;

int bpf_perf_event_aux_pause(void *map, u64 flags, bool pause) __ksym;

static int event_aux_pause(void)
{
	__u64 flag;
	__u32 cpu = bpf_get_smp_processor_id();

	if (!enabled)
		return 0;

	if (has_cpu) {
		__u8 *ok;

		ok = bpf_map_lookup_elem(&cpu_filter, &cpu);
		if (!ok)
			return 0;
	}

	if (has_task) {
		__u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
		__u8 *ok;

		ok = bpf_map_lookup_elem(&task_filter, &pid);
		if (!ok)
			return 0;
	}

	flag = per_thread ? 0 : BPF_F_CURRENT_CPU;
	bpf_perf_event_aux_pause(&events, flag, true);
	return 0;
}

static int event_aux_resume(void)
{
	__u64 flag;
	__u32 cpu = bpf_get_smp_processor_id();

	if (!enabled)
		return 0;

	if (has_cpu) {
		__u8 *ok;

		ok = bpf_map_lookup_elem(&cpu_filter, &cpu);
		if (!ok)
			return 0;
	}

	if (has_task) {
		__u32 pid = bpf_get_current_pid_tgid() & 0xffffffff;
		__u8 *ok;

		ok = bpf_map_lookup_elem(&task_filter, &pid);
		if (!ok)
			return 0;
	}

	flag = per_thread ? 0 : BPF_F_CURRENT_CPU;
	bpf_perf_event_aux_pause(&events, flag, false);
	return 0;
}

SEC("kprobe/func_pause")
int BPF_PROG(kprobe_event_pause)
{
	return event_aux_pause();
}

SEC("kprobe/func_resume")
int BPF_PROG(kprobe_event_resume)
{
	return event_aux_resume();
}

SEC("kretprobe/func_pause")
int BPF_PROG(kretprobe_event_pause)
{
	return event_aux_pause();
}

SEC("kretprobe/func_resume")
int BPF_PROG(kretprobe_event_resume)
{
	return event_aux_resume();
}

SEC("uprobe/func_pause")
int BPF_PROG(uprobe_event_pause)
{
	return event_aux_pause();
}

SEC("uprobe/func_resume")
int BPF_PROG(uprobe_event_resume)
{
	return event_aux_resume();
}

SEC("uretprobe/func_pause")
int BPF_PROG(uretprobe_event_pause)
{
	return event_aux_pause();
}

SEC("uretprobe/func_resume")
int BPF_PROG(uretprobe_event_resume)
{
	return event_aux_resume();
}

SEC("tp/func_pause")
int BPF_PROG(tp_event_pause)
{
	return event_aux_pause();
}

SEC("tp/func_resume")
int BPF_PROG(tp_event_resume)
{
	return event_aux_resume();
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
