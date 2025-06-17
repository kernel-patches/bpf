// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;

#define BUF_SIZE 1024
char parent_path_buf[BUF_SIZE] = {};
char parent_xattr_buf[BUF_SIZE] = {};
char grand_parent_path_buf[BUF_SIZE] = {};
char grand_parent_xattr_buf[BUF_SIZE] = {};

static __always_inline void d_path_and_read_xattr(struct path *p, char *path, char *xattr)
{
	struct bpf_dynptr ptr;
	struct dentry *dentry;

	if (!p)
		return;
	bpf_path_d_path(p, path, BUF_SIZE);
	bpf_dynptr_from_mem(xattr, BUF_SIZE, 0, &ptr);
	dentry = p->dentry;
	if (dentry)
		bpf_get_dentry_xattr(dentry, "user.bpf.selftests", &ptr);
}

SEC("lsm.s/file_open")
int BPF_PROG(test_file_open, struct file *f)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	struct bpf_iter_path path_it;
	struct path *p;

	if (pid != monitored_pid)
		return 0;

	bpf_iter_path_new(&path_it, &f->f_path, 0);

	/* Get d_path and xattr for the parent directory */
	p = bpf_iter_path_next(&path_it);
	d_path_and_read_xattr(p, parent_path_buf, parent_xattr_buf);

	/* Get d_path and xattr for the grand parent directory */
	p = bpf_iter_path_next(&path_it);
	d_path_and_read_xattr(p, grand_parent_path_buf, grand_parent_xattr_buf);

	bpf_iter_path_destroy(&path_it);

	return 0;
}
