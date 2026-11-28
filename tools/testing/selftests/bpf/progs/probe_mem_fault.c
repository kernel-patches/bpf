// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

int target_pid;
bool use_current_task;
__u64 addr;
int runs;
__u64 val_dw;
__u32 val_w;
__u8 val_b;

SEC("fentry/" SYS_PREFIX "sys_nanosleep")
int probe_mem_fault(void *ctx)
{
	struct task_struct *task;
	__u64 p = addr;

	if ((bpf_get_current_pid_tgid() >> 32) != target_pid)
		return 0;

	if (use_current_task)
		p = (__u64)bpf_get_current_task_btf();
	/*
	 * bpf_core_cast() yields an untrusted pointer, so every load through it
	 * is a PROBE_MEM load. Whatever the address is, the load must either
	 * read the field or produce zero; the kernel must not oops.
	 */
	task = bpf_core_cast((void *)p, struct task_struct);
	val_dw = task->start_time;
	val_w = task->pid;
	val_b = task->comm[0];
	runs++;
	return 0;
}
