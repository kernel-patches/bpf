// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"

#define RV_MON_TYPE RV_MON_PER_TASK
#include "tqueue.h"
#include <rv/da_monitor.h>
#define PF_EXITING 0x00000004

SEC("tp_btf/sched_dequeue_tp")
int BPF_PROG(handle_sched_dequeue, struct task_struct *tsk, int cpu)
{
	if (!(BPF_CORE_READ(tsk, flags) & PF_EXITING))
		da_handle_start_event(tsk, sched_dequeue_tqueue);
	return 0;
}

SEC("tp_btf/sched_enqueue_tp")
int BPF_PROG(handle_sched_enqueue, struct task_struct *tsk, int cpu)
{
	da_handle_event(tsk, sched_enqueue_tqueue);
	return 0;
}

static struct rv_monitor rv_this = {
	.enabled = 0,
};

char LICENSE[] SEC("license") = "GPL";
char DESCRIPTION[] SEC(".rodata.description") = "enqueue and dequeue tasks.";
