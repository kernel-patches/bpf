// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include "exe_file_kfunc_common.h"

SEC("lsm.s/file_open")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int BPF_PROG(get_task_exe_file_kfunc_null)
{
	struct file *acquired;

	/* Can't pass a NULL pointer to bpf_get_task_exe_file(). */
	acquired = bpf_get_task_exe_file(NULL);
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int BPF_PROG(get_mm_exe_file_kfunc_null)
{
	struct file *acquired;

	/* Can't pass a NULL pointer to bpf_get_mm_exe_file(). */
	acquired = bpf_get_mm_exe_file(NULL);
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/inode_getxattr")
__failure __msg("arg#0 pointer type STRUCT task_struct must point to scalar, or struct with scalar")
int BPF_PROG(get_task_exe_file_kfunc_fp)
{
	u64 x;
	struct file *acquired;
	struct task_struct *fp;

	fp = (struct task_struct *)&x;
	/* Can't pass random frame pointer to bpf_get_task_exe_file(). */
	acquired = bpf_get_task_exe_file(fp);
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/inode_getxattr")
__failure __msg("arg#0 pointer type STRUCT mm_struct must point to scalar, or struct with scalar")
int BPF_PROG(get_mm_exe_file_kfunc_fp)
{
	int x;
	struct file *acquired;
	struct mm_struct *fp;

	fp = (struct mm_struct *)&x;
	/* Can't pass random frame pointer to bpf_get_mm_exe_file(). */
	acquired = bpf_get_mm_exe_file(fp);
	if (!acquired)
		return 0;
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(get_task_exe_file_kfunc_untrusted)
{
	struct file *acquired;
	struct task_struct *parent;

	/* Walking a trusted struct task_struct returned from
	 * bpf_get_current_task_btf() yields an untrusted pointer. */
	parent = bpf_get_current_task_btf()->parent;
	/* Can't pass untrusted pointer to bpf_get_task_exe_file(). */
	acquired = bpf_get_task_exe_file(parent);
	if (!acquired)
		return 0;
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(get_mm_exe_file_kfunc_untrusted)
{
	struct file *acquired;
	struct mm_struct *mm;

	/* Walking a struct task_struct obtained from bpf_get_current_task_btf()
	 * yields an untrusted pointer. */
	mm = bpf_get_current_task_btf()->mm;
	/* Can't pass untrusted pointer to bpf_get_mm_exe_file(). */
	acquired = bpf_get_mm_exe_file(mm);
	if (!acquired)
		return 0;
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(get_task_exe_file_kfunc_unreleased)
{
	struct file *acquired;

	acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	__sink(acquired);

	/* Acquired but never released. */
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(get_mm_exe_file_kfunc_unreleased)
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
	__sink(acquired);
	bpf_mm_drop(mm);

	/* Acquired but never released. */
	return 0;
}

SEC("lsm/file_open")
__failure __msg("program must be sleepable to call sleepable kfunc bpf_put_file")
int BPF_PROG(put_file_kfunc_not_sleepable, struct file *f)
{
	struct file *acquired;

	acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!acquired)
		return 0;

	/* Can't call bpf_put_file() from non-sleepable BPF program. */
	bpf_put_file(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("release kernel function bpf_put_file expects")
int BPF_PROG(put_file_kfunc_unacquired, struct file *f)
{
	/* Can't release an unacquired pointer. */
	bpf_put_file(f);

	return 0;
}

SEC("tp_btf/task_newtask")
__failure __msg("calling kernel function bpf_get_task_exe_file is not allowed")
int BPF_PROG(get_task_exe_file_kfunc_not_lsm_prog, struct task_struct *task)
{
	struct file *acquired;

	/* bpf_get_task_exe_file() can only be called from BPF LSM program. */
	acquired = bpf_get_task_exe_file(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	bpf_put_file(acquired);

	return 0;
}
