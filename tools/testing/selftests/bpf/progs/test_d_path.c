// SPDX-License-Identifier: GPL-2.0

#include "d_path_common.h"

SEC("fentry/security_inode_getattr")
int BPF_PROG(prog_stat, struct path *path, struct kstat *stat,
	     __u32 request_mask, unsigned int query_flags)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u32 cnt = cnt_stat;
	int ret;

	called_stat = 1;

	if (pid != my_pid)
		return 0;

	if (cnt >= MAX_FILES)
		return 0;
	ret = bpf_d_path(path, paths_stat[cnt], MAX_PATH_LEN);

	rets_stat[cnt] = ret;
	cnt_stat++;
	return 0;
}

SEC("fentry/filp_close")
int BPF_PROG(prog_close, struct file *file, void *id)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	__u32 cnt = cnt_close;
	int ret;

	called_close = 1;

	if (pid != my_pid)
		return 0;

	if (cnt >= MAX_FILES)
		return 0;
	ret = bpf_d_path(&file->f_path,
			 paths_close[cnt], MAX_PATH_LEN);

	rets_close[cnt] = ret;
	cnt_close++;
	return 0;
}
