// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include "d_path_common.h"

char buf[MAX_PATH_LEN] = {};

SEC("lsm.s/file_open")
__failure __msg("Possibly NULL pointer passed to trusted arg0")
int BPF_PROG(path_d_path_kfunc_null)
{
	/* Can't pass NULL value to bpf_path_d_path() kfunc. */
	bpf_path_d_path(NULL, buf, sizeof(buf));
	return 0;
}

SEC("fentry/vfs_open")
__failure __msg("calling kernel function bpf_path_d_path is not allowed")
int BPF_PROG(path_d_path_kfunc_non_lsm, struct path *path, struct file *f)
{
	/* Calling bpf_path_d_path() kfunc from a non-sleepable and non-LSM
	 * based program isn't permitted.
	 */
	bpf_path_d_path(path, buf, sizeof(buf));
	return 0;
}

SEC("lsm.s/task_alloc")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(path_d_path_kfunc_untrusted_from_argument, struct task_struct *task)
{
	struct path *root;

	/* Walking a trusted argument yields an untrusted pointer. */
	root = &task->fs->root;
	bpf_path_d_path(root, buf, sizeof(buf));
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("R1 must be referenced or trusted")
int BPF_PROG(path_d_path_kfunc_untrusted_from_current)
{
	struct path *pwd;
	struct task_struct *current;

	current = bpf_get_current_task_btf();
	/* Walking a trusted pointer returned from bpf_get_current_task_btf()
	 * yields and untrusted pointer. */
	pwd = &current->fs->pwd;
	bpf_path_d_path(pwd, buf, sizeof(buf));
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("R1 must have zero offset when passed to release func or trusted arg to kfunc")
int BPF_PROG(path_d_path_kfunc_trusted_variable_offset, struct file *file)
{
	/* Passing variable offsets from a trusted aren't supported just yet,
	 * despite being perfectly OK i.e. file->f_path. Once the BPF verifier
	 * has been updated to handle this case, this test can be removed. For
	 * now, ensure we reject the BPF program upon load if this is attempted.
	 */
	bpf_path_d_path(&file->f_path, buf, sizeof(buf));
	return 0;
}
