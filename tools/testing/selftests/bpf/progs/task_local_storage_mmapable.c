// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Google */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_MMAPABLE);
	__type(key, int);
	__type(value, long);
} mmapable_map SEC(".maps");

#define MAGIC_VALUE 0xabcd1234

pid_t target_pid = 0;

SEC("tp_btf/sys_enter")
int BPF_PROG(on_enter, struct pt_regs *regs, long id)
{
	struct task_struct *task;
	long *ptr;

	task = bpf_get_current_task_btf();
	if (task->pid != target_pid)
		return 0;

	ptr = bpf_task_storage_get(&mmapable_map, task, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!ptr)
		return 0;

	*ptr = MAGIC_VALUE;
	return 0;
}
