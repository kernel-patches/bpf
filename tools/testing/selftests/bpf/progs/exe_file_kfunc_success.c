// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include "exe_file_kfunc_common.h"

SEC("lsm.s/file_open")
int BPF_PROG(get_task_exe_file_and_put_kfunc_from_current)
{
	struct file *acquired;

	acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/task_alloc")
int BPF_PROG(get_task_exe_file_and_put_kfunc_from_argument,
	     struct task_struct *task)
{
	struct file *acquired;

	acquired = bpf_get_task_exe_file(task);
	if (!acquired)
		return 0;
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(get_mm_exe_file_and_put_kfunc_from_current)
{
	struct file *acquired;
	struct mm_struct *mm;

	mm = bpf_task_mm_grab(bpf_get_current_task_btf());
	if (!mm)
		return 0;

	acquired = bpf_get_mm_exe_file(mm);
	if (!acquired) {
		bpf_mm_drop(mm);
		return 0;
	}
	bpf_put_file(acquired);
	bpf_mm_drop(mm);

	return 0;
}
