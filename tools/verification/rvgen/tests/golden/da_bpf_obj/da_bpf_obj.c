// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#define RV_MON_TYPE RV_MON_PER_OBJ
typedef /* XXX: define the target type */ *monitor_target_bpf;
#include "da_bpf_obj.h"
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
	int id = /* XXX: how do I get the id? */;
	monitor_target_bpf t = /* XXX: how do I get t? */;
	da_handle_event(id, t, event_1_da_bpf_obj);
	return 0;
}

SEC(/* XXX: tracepoint or other probe */)
int BPF_PROG(handle_event_2, /* XXX: fill header */)
{
	/* XXX: validate that this event always leads to the initial state */
	int id = /* XXX: how do I get the id? */;
	monitor_target_bpf t = /* XXX: how do I get t? */;
	da_handle_start_event(id, t, event_2_da_bpf_obj);
	return 0;
}

/* XXX: obj is being destroyed, remove if not required (e.g. obj is static) */
SEC(/* XXX: tracepoint or other probe */)
int BPF_PROG(handle_obj_cleanup, /* XXX: fill header */)
{
	int id = /* XXX: how do I get the id? */;
	da_destroy_storage(id);
	return 0;
}

static struct rv_monitor rv_this = {
	.enabled = 0,
};

char LICENSE[] SEC("license") = "GPL";
char DESCRIPTION[] SEC(".rodata.description") = "auto-generated";
