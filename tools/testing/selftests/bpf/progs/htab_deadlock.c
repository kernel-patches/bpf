// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 DiDi Global Inc. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_ZERO_SEED);
	__type(key, unsigned int);
	__type(value, unsigned int);
} htab SEC(".maps");

SEC("fentry/perf_event_overflow")
int bpf_nmi_handle(struct pt_regs *regs)
{
	unsigned int val = 0, key = 4;

	bpf_map_update_elem(&htab, &key, &val, BPF_ANY);
	return 0;
}

SEC("perf_event")
int bpf_empty(struct pt_regs *regs)
{
	return 0;
}
