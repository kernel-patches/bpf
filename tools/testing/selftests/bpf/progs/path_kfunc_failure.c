// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */

#include "path_kfunc_common.h"

SEC("lsm.s/file_open")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int BPF_PROG(get_task_fs_root_kfunc_null)
{
	struct path *acquired;

	/* Can't pass a NULL pointer to bpf_get_task_fs_root(). */
	acquired = bpf_get_task_fs_root(NULL);
	if (!acquired)
		return 0;
	bpf_put_path(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int BPF_PROG(get_task_fs_pwd_kfunc_null)
{
	struct path *acquired;

	/* Can't pass a NULL pointer to bpf_get_task_fs_pwd(). */
	acquired = bpf_get_task_fs_pwd(NULL);
	if (!acquired)
		return 0;
	bpf_put_path(acquired);

	return 0;
}

SEC("lsm.s/task_alloc")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(get_task_fs_root_kfunc_untrusted, struct task_struct *task)
{
	struct path *acquired;
	struct task_struct *parent;

	/* Walking the struct task_struct will yield an untrusted pointer. */
	parent = task->parent;
	if (!parent)
		return 0;

	acquired = bpf_get_task_fs_root(parent);
	if (!acquired)
		return 0;
	bpf_put_path(acquired);

	return 0;
}

SEC("lsm.s/task_alloc")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(get_task_fs_pwd_kfunc_untrusted, struct task_struct *task)
{
	struct path *acquired;
	struct task_struct *parent;

	/* Walking the struct task_struct will yield an untrusted pointer. */
	parent = task->parent;
	if (!parent)
		return 0;

	acquired = bpf_get_task_fs_pwd(parent);
	if (!acquired)
		return 0;
	bpf_put_path(acquired);

	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(get_task_fs_root_kfunc_unreleased)
{
	struct path *acquired;

	acquired = bpf_get_task_fs_root(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	__sink(acquired);

	/* Acquired but never released. */
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(get_task_fs_pwd_kfunc_unreleased)
{
	struct path *acquired;

	acquired = bpf_get_task_fs_pwd(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	__sink(acquired);

	/* Acquired but never released. */
	return 0;
}

SEC("lsm.s/inode_getattr")
__failure __msg("release kernel function bpf_put_path expects refcounted PTR_TO_BTF_ID")
int BPF_PROG(put_path_kfunc_unacquired, struct path *path)
{
	/* Can't release an unacquired pointer. */
	bpf_put_path(path);

	return 0;
}
