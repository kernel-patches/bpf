// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#define RV_MON_TYPE RV_MON_PER_CPU
#include "nohz.h"
#include <rv/da_monitor.h>

/*
 * This monitor is broken on purpose to test errors, sched_tick can run with
 * stopped ticks for one last time (deferred tick reprogram).
 * A way to fix this monitor is to handle the sched_tick event only when
 * tick_nohz_handler returns HRTIMER_RESTART (i.e. it isn't stopping the tick).
 */
SEC("fentry/sched_tick")
int BPF_PROG(handle_sched_tick)
{
	da_handle_start_event(sched_tick_nohz);
	return 0;
}

SEC("fentry/tick_nohz_restart_sched_tick")
int BPF_PROG(handle_tick_restart)
{
	da_handle_start_event(tick_restart_nohz);
	return 0;
}

SEC("tp_btf/tick_stop")
int BPF_PROG(handle_tick_stop, int success, int dependency)
{
	if (success)
		da_handle_event(tick_stop_nohz);
	return 0;
}

static struct rv_monitor rv_this = {
	.enabled = 0,
};

char LICENSE[] SEC("license") = "GPL";
char DESCRIPTION[] SEC(".rodata.description") = "tick does not run when stopped.";
