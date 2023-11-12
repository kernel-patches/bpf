// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2023 Yafang Shao <laoar.shao@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

int target_pid;

static int mem_policy_adjustment(u64 mode)
{
	struct task_struct *task = bpf_get_current_task_btf();

	if (task->pid != target_pid)
		return 0;

	if (mode != MPOL_BIND)
		return 0;
	return -1;
}

SEC("lsm/mbind")
int BPF_PROG(mbind_run, u64 start, u64 len, u64 mode, const u64 *nmask, u64 maxnode, u32 flags)
{
	return mem_policy_adjustment(mode);
}

char _license[] SEC("license") = "GPL";
