// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Abhishek Khade */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"

bool bpf_task_is_init_net(const struct task_struct *task) __ksym;
u32 bpf_task_get_netns_inum(const struct task_struct *task) __ksym;

pid_t target_pid;
int inv_is_init_net = -1;
u32 inv_netns_inum;

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *task, u64 old_pid,
	     struct linux_binprm *bprm)
{
	pid_t pid = task->tgid;

	if (pid != target_pid)
		return 0;

	inv_is_init_net = bpf_task_is_init_net(task) ? 1 : 0;
	inv_netns_inum = bpf_task_get_netns_inum(task);

	return 0;
}

char _license[] SEC("license") = "GPL";
