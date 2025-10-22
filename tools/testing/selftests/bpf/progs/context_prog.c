// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

int in_hardirq = 0;
int in_softriq = 0;
int in_task = 0;

SEC("tp/irq/irq_handler_entry")
int trace_irq_handler_entry(const void *ctx)
{
	in_hardirq = bpf_in_hardirq_context();
	return 0;
}

SEC("tp/irq/softirq_entry")
int trace_softirq_entry(const void *ctx)
{
	in_softriq = bpf_in_softirq_context();
	return 0;
}

SEC("tp/syscalls/sys_enter_getuid")
int trace_syscall(const void *ctx)
{
	in_task = bpf_in_task_context();
	return 0;
}

char _license[] SEC("license") = "GPL";
