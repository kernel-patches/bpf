// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

unsigned long hits = 0;
const volatile int batch_iters = 0;

SEC("raw_tp")
int trigger_driver(void *ctx)
{
	int i;

	for (i = 0; i < batch_iters; i++)
		(void)bpf_get_numa_node_id(); /* attach point for benchmarking */

	return 0;
}

__attribute__((weak)) int func1(void) {
	return 0;
}

SEC("fentry/bpf_get_numa_node_id")
int bench_trigger_fentry_batch(void *ctx)
{
	hits++;
	(void)func1();
	(void)func1();
	(void)func1();
	return 0;
}

