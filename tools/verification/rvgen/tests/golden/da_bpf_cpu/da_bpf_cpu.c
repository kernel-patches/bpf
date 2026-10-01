// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#define RV_MON_TYPE RV_MON_PER_CPU
#include "da_bpf_cpu.h"
#include <rv/da_monitor.h>

/*
 * This is the instrumentation part of the monitor.
 *
 * This is the section where manual work is required. Here the kernel events
 * are translated into model's event.
 */
SEC(/* XXX: tracepoint or other probe */)
int BPF_PROG(handle_event_1, /* XXX: fill header */)
{
	da_handle_event(event_1_da_bpf_cpu);
	return 0;
}

SEC(/* XXX: tracepoint or other probe */)
int BPF_PROG(handle_event_2, /* XXX: fill header */)
{
	/* XXX: validate that this event always leads to the initial state */
	da_handle_start_event(event_2_da_bpf_cpu);
	return 0;
}

static struct rv_monitor rv_this = {
	.enabled = 0,
};

char LICENSE[] SEC("license") = "GPL";
char DESCRIPTION[] SEC(".rodata.description") = "auto-generated";
