// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "task_local_storage__mmap.h"

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_MMAPABLE);
	__type(key, int);
	__type(value, long);
} mmapable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_MMAPABLE);
	__type(key, int);
	__type(value, struct two_page_struct);
} mmapable_two_pages SEC(".maps");

long mmaped_mapval = 0;
int read_and_incr = 0;
int create_flag = 0;
int use_big_mapval = 0;

SEC("tp_btf/sys_enter")
int BPF_PROG(on_enter, struct pt_regs *regs, long id)
{
	struct two_page_struct *big_mapval;
	struct task_struct *task;
	long *ptr;

	task = bpf_get_current_task_btf();
	if (!task)
		return 1;

	if (use_big_mapval) {
		big_mapval = bpf_task_storage_get(&mmapable_two_pages, task, 0,
						  create_flag);
		if (!big_mapval)
			return 2;
		ptr = &big_mapval->val;
	} else {
		ptr = bpf_task_storage_get(&mmapable, task, 0, create_flag);
	}

	if (!ptr)
		return 3;

	if (read_and_incr)
		*ptr = *ptr + 1;

	mmaped_mapval = *ptr;
	return 0;
}
