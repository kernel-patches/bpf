// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <asm/unistd.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int target_pid;
int prog_triggered;
long err;
long copied_tv_nsec;

static int copy_nanosleep_arg(struct __kernel_timespec *ts)
{
	long tv_nsec;

	err = bpf_copy_from_user(&tv_nsec, sizeof(tv_nsec), &ts->tv_nsec);
	if (err)
		return err;

	copied_tv_nsec = tv_nsec;
	prog_triggered = 1;
	return 0;
}

/* Primary functional tests: full bpf_copy_from_user exercise */

SEC("tp_btf.s/sys_enter")
int BPF_PROG(handle_sys_enter_tp_btf, struct pt_regs *regs, long id)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid ||
	    id != __NR_nanosleep)
		return 0;

	return copy_nanosleep_arg((void *)PT_REGS_PARM1_SYSCALL(regs));
}

SEC("raw_tp.s/sys_enter")
int BPF_PROG(handle_sys_enter_raw_tp, struct pt_regs *regs, long id)
{
	if ((bpf_get_current_pid_tgid() >> 32) != target_pid ||
	    id != __NR_nanosleep)
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

SEC("tp.s/syscalls/sys_exit_nanosleep")
int handle_sys_exit_tp(struct syscall_trace_exit *args)
{
	struct pt_regs *regs;

	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	regs = (struct pt_regs *)bpf_task_pt_regs(bpf_get_current_task_btf());
	return copy_nanosleep_arg((void *)PT_REGS_PARM1_CORE_SYSCALL(regs));
}

/* Bare SEC variants: test manual attach without tracepoint in section name */

SEC("raw_tp.s")
int BPF_PROG(handle_raw_tp_bare, struct pt_regs *regs, long id)
{
	return 0;
}

SEC("tp.s")
int handle_tp_bare(void *ctx)
{
	return 0;
}

/* Alias SEC variants: test libbpf prefix parsing for long-form names */

SEC("tracepoint.s/syscalls/sys_enter_nanosleep")
int handle_sys_enter_tp_alias(struct syscall_trace_enter *args)
{
	return 0;
}

SEC("raw_tracepoint.s/sys_enter")
int BPF_PROG(handle_sys_enter_raw_tp_alias, struct pt_regs *regs, long id)
{
	return 0;
}

/* BPF_PROG_TEST_RUN: sleepable raw_tp invoked via bpf_prog_test_run_raw_tp */

SEC("raw_tp.s/sys_enter")
int BPF_PROG(handle_test_run, struct pt_regs *regs, long id)
{
	if ((__u64)regs == 0x1234ULL && (__u64)id == 0x5678ULL)
		return (__u64)regs + (__u64)id;

	return 0;
}

/* Negative: sleepable on non-faultable tracepoint (attach-time rejection) */

SEC("raw_tp.s/sched_switch")
int BPF_PROG(handle_raw_tp_non_faultable, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	return 0;
}

SEC("tp.s/sched/sched_switch")
int handle_tp_non_syscall(void *ctx)
{
	return 0;
}
