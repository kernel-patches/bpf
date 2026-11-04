// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_stack_build_id stack_sleepable[128];
int res_sleepable;

struct bpf_stack_build_id stack_nofault[128];
int res_nofault;

SEC("uprobe.multi/./uprobe_multi:uprobe")
int uprobe_nofault(struct pt_regs *ctx)
{
	res_nofault = bpf_get_stack(ctx, stack_nofault, sizeof(stack_nofault),
				    BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);

	return 0;
}

SEC("uprobe.multi.s/./uprobe_multi:uprobe")
int uprobe_sleepable(struct pt_regs *ctx)
{
	res_sleepable = bpf_get_stack(ctx, stack_sleepable, sizeof(stack_sleepable),
				      BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);

	return 0;
}

struct bpf_stack_build_id stack_rawtp_sleepable[128];
int res_rawtp_sleepable;

struct bpf_stack_build_id stack_rawtp_nofault[128];
int res_rawtp_nofault;

int target_tgid;
int target_syscall;

SEC("raw_tp/sys_enter")
int BPF_PROG(rawtp_nofault, struct pt_regs *regs, long id)
{
	if ((u32)(bpf_get_current_pid_tgid() >> 32) != (u32)target_tgid ||
	    id != target_syscall)
		return 0;

	res_rawtp_nofault = bpf_get_stack(ctx, stack_rawtp_nofault,
					  sizeof(stack_rawtp_nofault),
					  BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);

	return 0;
}

SEC("raw_tp.s/sys_enter")
int BPF_PROG(rawtp_sleepable, struct pt_regs *regs, long id)
{
	if ((u32)(bpf_get_current_pid_tgid() >> 32) != (u32)target_tgid ||
	    id != target_syscall)
		return 0;

	res_rawtp_sleepable = bpf_get_stack(ctx, stack_rawtp_sleepable,
					    sizeof(stack_rawtp_sleepable),
					    BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);

	return 0;
}

char _license[] SEC("license") = "GPL";
