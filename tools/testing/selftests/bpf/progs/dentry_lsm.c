// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 David Windsor <dwindsor@gmail.com> */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

extern struct dentry *bpf_dget(struct dentry *dentry) __ksym;
extern void bpf_dput(struct dentry *dentry) __ksym;
extern struct dentry *bpf_dget_parent(struct dentry *dentry) __ksym;
extern struct dentry *bpf_d_find_alias(struct inode *inode) __ksym;
extern struct dentry *bpf_file_dentry(struct file *file) __ksym;
extern struct vfsmount *bpf_file_vfsmount(struct file *file) __ksym;

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file)
{
	struct dentry *dentry, *parent, *alias, *dentry_ref;
	struct vfsmount *vfs_mnt;

	if (!file)
		return 0;

	dentry = bpf_file_dentry(file);
	if (dentry) {
		dentry_ref = bpf_dget(dentry);
		if (dentry_ref)
			bpf_dput(dentry_ref);

		parent = bpf_dget_parent(dentry);
		if (parent)
			bpf_dput(parent);
	}

	if (file->f_inode) {
		alias = bpf_d_find_alias(file->f_inode);
		if (alias)
			bpf_dput(alias);
	}

	vfs_mnt = bpf_file_vfsmount(file);
	if (vfs_mnt) {
		/* Test that we can access vfsmount */
		(void)vfs_mnt;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
