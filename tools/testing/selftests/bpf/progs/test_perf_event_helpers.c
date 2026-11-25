// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Facebook
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} array_1 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
	__uint(map_flags, BPF_F_PRESERVE_ELEMS);
} array_2 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} array_3 SEC(".maps");

SEC("raw_tp/sched_switch")
int BPF_PROG(read_array_1)
{
	struct bpf_perf_event_value val;

	return bpf_perf_event_read_value(&array_1, 0, &val, sizeof(val));
}

SEC("raw_tp/task_rename")
int BPF_PROG(read_array_2)
{
	struct bpf_perf_event_value val;

	return bpf_perf_event_read_value(&array_2, 0, &val, sizeof(val));
}

SEC("raw_tp/sched_switch")
int BPF_PROG(read_array_1_legacy)
{
	return bpf_perf_event_read(&array_3, 0);
}

long read_prog_value_ret = 1;
long read_prog_value_enabled = 0;
long read_prog_value_running = 0;

SEC("perf_event")
int read_prog_value(struct bpf_perf_event_data *ctx)
{
	struct bpf_perf_event_value value;

	read_prog_value_ret =
		bpf_perf_prog_read_value(ctx, &value, sizeof(value));
	bpf_printk("retval: %d\n", read_prog_value_ret);
	if (!read_prog_value_ret) {
		read_prog_value_enabled = value.enabled;
		read_prog_value_running = value.running;
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
