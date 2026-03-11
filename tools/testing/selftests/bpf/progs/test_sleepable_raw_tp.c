// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <asm/unistd.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

int target_pid;
int triggered;
long err;
long copied_tv_nsec;

SEC("tp_btf.s/sys_enter")
int BPF_PROG(test_sleepable_sys_enter, struct pt_regs *regs, long id)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct __kernel_timespec *ts;
	long tv_nsec;

	if (task->pid != target_pid)
		return 0;

	if (id != __NR_nanosleep)
		return 0;

	ts = (void *)PT_REGS_PARM1_CORE_SYSCALL(regs);

	/*
	 * Use bpf_copy_from_user() - a sleepable helper - to read user memory.
	 * This exercises the sleepable execution path of raw tracepoints.
	 */
	err = bpf_copy_from_user(&tv_nsec, sizeof(tv_nsec), &ts->tv_nsec);
	if (err)
		return err;

	copied_tv_nsec = tv_nsec;
	triggered = 1;
	return 0;
}
