// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

#define MAX_PATH_LEN 256

char buf[MAX_PATH_LEN];
int path_len = 0;
u32 monitored_pid = 0;

SEC("lsm.s/file_open")
int BPF_PROG(test_kern_path_basic, struct file *file)
{
	struct path *p;
	int ret;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;

	p = bpf_kern_path("/proc/self/exe", 0);
	if (p) {
		ret = bpf_path_d_path(p, buf, MAX_PATH_LEN);
		if (ret > 0)
			path_len = ret;
		bpf_path_put(p);
	}

	return 0;
}

SEC("lsm.s/sb_mount")
int BPF_PROG(test_kern_path_from_sb_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data)
{
	struct path *p;
	int ret;

	if (bpf_get_current_pid_tgid() >> 32 != monitored_pid)
		return 0;

	p = bpf_kern_path(dev_name, 0);
	if (p) {
		ret = bpf_path_d_path(p, buf, MAX_PATH_LEN);
		if (ret > 0)
			path_len = ret;
		bpf_path_put(p);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
