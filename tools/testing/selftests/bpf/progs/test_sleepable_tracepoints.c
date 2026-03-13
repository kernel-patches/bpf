// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <asm/unistd.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

int target_pid;
int triggered;
long err;
long copied_tv_nsec;

static int copy_nanosleep_arg(struct __kernel_timespec *ts)
{
	long tv_nsec;

	err = bpf_copy_from_user(&tv_nsec, sizeof(tv_nsec), &ts->tv_nsec);
	if (err)
		return err;

	copied_tv_nsec = tv_nsec;
	triggered = 1;
	return 0;
}

SEC("tp_btf.s/sys_enter")
int BPF_PROG(handle_sys_enter_tp_btf, struct pt_regs *regs, long id)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (task->pid != target_pid)
		return 0;

	if (id != __NR_nanosleep)
		return 0;

	return copy_nanosleep_arg((void *)PT_REGS_PARM1_SYSCALL(regs));
}

SEC("raw_tp.s/sys_enter")
int BPF_PROG(handle_sys_enter_raw_tp, struct pt_regs *regs, long id)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (task->pid != target_pid)
		return 0;

	if (id != __NR_nanosleep)
		return 0;

	return copy_nanosleep_arg((void *)PT_REGS_PARM1_CORE_SYSCALL(regs));
}

SEC("tp.s/syscalls/sys_enter_nanosleep")
int handle_sys_enter_tp(struct syscall_trace_enter *args)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	return copy_nanosleep_arg((void *)args->args[0]);
}

/* Sleepable program on a non-faultable tracepoint should fail to load */
SEC("tp_btf.s/sched_switch")
__failure __msg("Sleepable program cannot attach to non-faultable tracepoint")
int BPF_PROG(handle_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	return 0;
}
