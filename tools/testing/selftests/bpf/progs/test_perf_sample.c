// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Google

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

unsigned long long sample_flag;
unsigned long long sample_size;

SEC("perf_event")
int perf_sample_filter(void *ctx)
{
	long size;
	unsigned long long buf[1] = {};

	size = bpf_perf_event_read_sample(ctx, NULL, 0, sample_flag);
	if (size != sample_size)
		return 0;

	if (bpf_perf_event_read_sample(ctx, buf, sizeof(buf), sample_flag) < 0)
		return 0;

	/* generate sample data */
	return 1;
}

char _license[] SEC("license") = "GPL";
