// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

extern struct bpf_cpumask *bpf_cpumask_create(void) __ksym;
extern void bpf_cpumask_set_cpu(u32 cpu, struct bpf_cpumask *cpumask) __ksym;
extern bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *cpumask) __ksym;
extern void bpf_cpumask_release(struct bpf_cpumask *cpumask) __ksym;

int result = -1;

/* call arbitrary kfuncs within a tracepoint program */
SEC("tp/syscalls/sys_enter_getpid")
int handle_tp(struct trace_event_raw_ipi_send_cpumask *ctx)
{
	struct bpf_cpumask *cpumask;
	const u32 cpu = bpf_get_smp_processor_id();

	cpumask = bpf_cpumask_create();
	if (!cpumask)
		return 0;

	bpf_cpumask_set_cpu(cpu, cpumask);
	if (bpf_cpumask_test_cpu(cpu, (struct cpumask *)cpumask))
		bpf_printk("match\n");

	bpf_cpumask_release(cpumask);
	result = 0;

	return 0;
}
