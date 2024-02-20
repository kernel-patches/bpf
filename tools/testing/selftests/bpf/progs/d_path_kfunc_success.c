// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Google LLC. */

#include "d_path_common.h"

SEC("lsm.s/inode_getattr")
int BPF_PROG(path_d_path_from_path_argument, struct path *path)
{
	u32 cnt = cnt_stat;
	int ret;
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != my_pid)
		return 0;

	if (cnt >= MAX_FILES)
		return 0;

	ret = bpf_path_d_path(path, paths_stat[cnt], MAX_PATH_LEN);
	rets_stat[cnt] = ret;
	cnt_stat++;

	return 0;
}
