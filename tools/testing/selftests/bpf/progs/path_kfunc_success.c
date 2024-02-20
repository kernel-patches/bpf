// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Google LLC. */

#include "path_kfunc_common.h"

SEC("lsm.s/file_open")
int BPF_PROG(get_task_fs_root_and_put_from_current)
{
	struct path *acquired;

	acquired = bpf_get_task_fs_root(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	bpf_put_path(acquired);

	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(get_task_fs_pwd_and_put_from_current)
{
	struct path *acquired;

	acquired = bpf_get_task_fs_pwd(bpf_get_current_task_btf());
	if (!acquired)
		return 0;
	bpf_put_path(acquired);

	return 0;
}
