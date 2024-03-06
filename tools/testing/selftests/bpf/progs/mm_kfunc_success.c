// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include "mm_kfunc_common.h"

SEC("lsm.s/task_alloc")
int BPF_PROG(task_mm_grab_drop_from_argument, struct task_struct *task)
{
	struct mm_struct *acquired;

	acquired = bpf_task_mm_grab(task);
	if (!acquired)
		return 0;
	bpf_mm_drop(acquired);

	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(task_mm_acquire_release_from_current)
{
	struct mm_struct *acquired;

	acquired = bpf_task_mm_grab(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	bpf_mm_drop(acquired);

	return 0;
}
