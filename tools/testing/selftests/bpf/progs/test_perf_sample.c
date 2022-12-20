// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 Google

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

unsigned long long sample_ip;
unsigned long long sample_pid;
unsigned long long sample_addr;

void *bpf_cast_to_kern_ctx(void *) __ksym;

#define SAMPLE_FLAGS  (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_ADDR)

SEC("perf_event")
int perf_sample_filter(void *ctx)
{
	struct bpf_perf_event_data_kern *kctx;

	kctx = bpf_cast_to_kern_ctx(ctx);

	if ((kctx->event->attr.sample_type & SAMPLE_FLAGS) != SAMPLE_FLAGS)
		return 0;

	sample_ip = kctx->data->ip;
	sample_pid = kctx->data->tid_entry.pid;
	sample_addr = kctx->data->addr;

	/* generate sample data */
	return 1;
}

char _license[] SEC("license") = "GPL";
