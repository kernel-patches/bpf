// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2022 Kylin
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/version.h>
#include <linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_CPUS		128

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, u64);
	__uint(max_entries, MAX_CPUS);
} irq_ts SEC(".maps");

SEC("tracepoint/irq/irq_handler_entry")
int on_irq_entry(struct pt_regs *ctx)
{
	int cpu = bpf_get_smp_processor_id();
	u64 *ts = bpf_map_lookup_elem(&irq_ts, &cpu);

	if (ts)
		*ts = bpf_ktime_get_ns();

	return 0;
}

struct datares {
	u64 entries;
	u64 total;
	u64 max;
	u64 min;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct datares);
	__uint(max_entries, MAX_CPUS);
} irq_lat SEC(".maps");

SEC("tracepoint/irq/irq_handler_exit")
int on_irq_exit(struct pt_regs *ctx)
{
	u64 *ts, cur_ts, delta, *val;
	int cpu;
	struct datares *res;

	cpu = bpf_get_smp_processor_id();
	ts = bpf_map_lookup_elem(&irq_ts, &cpu);
	if (!ts)
		return 0;

	cur_ts = bpf_ktime_get_ns();
	delta = cur_ts - *ts;

	res = bpf_map_lookup_elem(&irq_lat, &cpu);
	if (!res)
		return 0;

	res->entries++;
	res->total += delta;
	if (res->max < delta)
		res->max = delta;
	if (res->min == 0 || res->min > delta)
		res->min = delta;

	if (res->total >= U64_MAX)
		__builtin_memset(res, 0, sizeof(struct datares));

	return 0;
}

char _license[] SEC("license") = "GPL";
