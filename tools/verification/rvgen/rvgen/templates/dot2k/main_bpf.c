// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#define RV_MON_TYPE RV_MON_%%MONITOR_TYPE%%
#include "%%MODEL_NAME%%.h"
#include <rv/da_monitor.h>

/*
 * This is the instrumentation part of the monitor.
 *
 * This is the section where manual work is required. Here the kernel events
 * are translated into model's event.
 */
%%TRACEPOINT_HANDLERS_SKEL%%
static struct rv_monitor rv_this = {
	.enabled = 0,
};

char LICENSE[] SEC("license") = "GPL";
char DESCRIPTION[] SEC(".rodata.description") = "%%DESCRIPTION%%";
