// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

const char xattr_foo[] = "security.bpf.foo";
char _license[] SEC("license") = "GPL";

__u32 monitored_pid;

char read_value[64];
int read_value_len;

char label_check_buf[64];
char name_buf[64];

static __always_inline bool name_is_foo(const char *name)
{
	bpf_probe_read_kernel(name_buf, sizeof(name_buf), name);
	return !bpf_strncmp(name_buf, sizeof(xattr_foo), xattr_foo);
}

static __always_inline bool has_label(struct dentry *dentry)
{
	struct bpf_dynptr ptr;

	bpf_dynptr_from_mem(label_check_buf, sizeof(label_check_buf), 0, &ptr);
	return bpf_get_dentry_xattr(dentry, xattr_foo, &ptr) >= 0;
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(label_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	if (!name_is_foo(name))
		return 0;
	if (has_label(dentry))
		return -EPERM;
	return 0;
}

SEC("lsm.s/inode_removexattr")
int BPF_PROG(label_removexattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	if (!name_is_foo(name))
		return 0;
	return -EPERM;
}

SEC("lsm.s/inode_getxattr")
int BPF_PROG(label_getxattr, struct dentry *dentry, const char *name)
{
	struct bpf_dynptr ptr;
	int ret;

	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	if (!name_is_foo(name))
		return 0;

	bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &ptr);
	ret = bpf_get_dentry_xattr(dentry, xattr_foo, &ptr);
	if (ret >= 0)
		read_value_len = ret;
	return 0;
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(label_unlink, struct inode *dir, struct dentry *victim)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	return has_label(victim) ? -EPERM : 0;
}

SEC("lsm.s/inode_rmdir")
int BPF_PROG(label_rmdir, struct inode *dir, struct dentry *victim)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	return has_label(victim) ? -EPERM : 0;
}

SEC("lsm.s/inode_rename")
int BPF_PROG(label_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry,
	     unsigned int flags)
{
	if ((bpf_get_current_pid_tgid() >> 32) != monitored_pid)
		return 0;
	return has_label(old_dentry) ? -EPERM : 0;
}
