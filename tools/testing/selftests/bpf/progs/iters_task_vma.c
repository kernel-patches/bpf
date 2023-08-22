// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <limits.h>
#include <linux/errno.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

pid_t target_pid = 0;
unsigned int vmas_seen = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, unsigned long);
} vm_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1000);
	__type(key, int);
	__type(value, unsigned long);
} vm_end SEC(".maps");

SEC("?raw_tp/sys_enter")
int iter_task_vma_for_each(const void *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct vm_area_struct *vma;
	unsigned long *start, *end;

	if (task->pid != target_pid)
		return 0;

	bpf_for_each(task_vma, vma, task, 0) {
		if (vmas_seen >= 1000)
			break;

		start = bpf_map_lookup_elem(&vm_start, &vmas_seen);
		if (!start)
			break;
		*start = vma->vm_start;

		end = bpf_map_lookup_elem(&vm_end, &vmas_seen);
		if (!end)
			break;
		*end = vma->vm_end;

		vmas_seen++;
	}
	return 0;
}

char _license[] SEC("license") = "GPL";
