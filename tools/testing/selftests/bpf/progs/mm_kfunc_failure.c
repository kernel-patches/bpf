// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include "mm_kfunc_common.h"

SEC("lsm.s/file_open")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int BPF_PROG(task_mm_grab_null_kfunc)
{
	struct mm_struct *acquired;

	/* Can't pass a NULL pointer to bpf_task_mm_grab(). */
	acquired = bpf_task_mm_grab(NULL);
	if (!acquired)
		return 0;
	bpf_mm_drop(acquired);

	return 0;
}

SEC("lsm/task_free")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(task_mm_grab_from_lsm_task_free_kfunc, struct task_struct *task)
{
	struct mm_struct *acquired;

	/* The task_struct supplied to this LSM hook isn't trusted. */
	acquired = bpf_task_mm_grab(task);
	if (!acquired)
		return 0;
	bpf_mm_drop(acquired);

	return 0;
}

SEC("lsm.s/task_alloc")
__failure __msg("arg#0 pointer type STRUCT task_struct must point")
int BPF_PROG(task_mm_grab_fp_kfunc, struct task_struct *task, u64 clone_flags)
{
	struct task_struct *fp;
	struct mm_struct *acquired;

	fp = (struct task_struct *)&clone_flags;
	/* Can't pass random frame pointer to bpf_task_mm_grab(). */
	acquired = bpf_task_mm_grab(fp);
	if (!acquired)
		return 0;
	bpf_mm_drop(acquired);

	return 0;
}

SEC("lsm.s/task_alloc")
__failure __msg("Unreleased reference")
int BPF_PROG(task_mm_grab_unreleased_kfunc, struct task_struct *task)
{
	struct mm_struct *acquired;

	acquired = bpf_task_mm_grab(task);
	__sink(acquired);

	/* Acquired but never released. */
	return 0;
}

SEC("lsm.s/task_alloc")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(task_mm_drop_untrusted_kfunc, struct task_struct *task)
{
	struct mm_struct *acquired;

	/* task->mm from struct task_struct yields an untrusted pointer. */
	acquired = task->mm;
	if (!acquired)
		return 0;
	bpf_mm_drop(acquired);

	return 0;
}

SEC("lsm/vm_enough_memory")
__failure __msg("release kernel function bpf_mm_drop expects")
int BPF_PROG(mm_drop_unacquired_kfunc, struct mm_struct *mm)
{
	/* Can't release an unacquired pointer. */
	bpf_mm_drop(mm);

	return 0;
}

SEC("lsm/vm_enough_memory")
__failure __msg("arg#0 pointer type STRUCT mm_struct must point")
int BPF_PROG(mm_drop_fp_kfunc, struct mm_struct *mm, long pages)
{
	struct mm_struct *fp;

	fp = (struct mm_struct *)&pages;

	/* Can't release random frame pointer. */
	bpf_mm_drop(fp);

	return 0;
}
