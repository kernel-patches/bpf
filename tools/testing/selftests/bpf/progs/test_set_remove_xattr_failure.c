// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

static const char xattr_bar[] = "security.bpf.bar";
char v[32];

SEC("lsm.s/inode_getxattr")
__failure __msg("calling kernel function bpf_set_dentry_xattr_locked is not allowed")
int BPF_PROG(test_getxattr_failure_a, struct dentry *dentry, char *name)
{
	struct bpf_dynptr value_ptr;

	bpf_dynptr_from_mem(v, sizeof(v), 0, &value_ptr);

	bpf_set_dentry_xattr_locked(dentry, xattr_bar, &value_ptr, 0);
	return 0;
}

SEC("lsm.s/inode_getxattr")
__failure __msg("calling kernel function bpf_remove_dentry_xattr_locked is not allowed")
int BPF_PROG(test_getxattr_failure_b, struct dentry *dentry, char *name)
{
	bpf_remove_dentry_xattr_locked(dentry, xattr_bar);
	return 0;
}

SEC("lsm.s/inode_setxattr")
__failure __msg("calling kernel function bpf_set_dentry_xattr is not allowed")
int BPF_PROG(test_inode_setxattr_failure_a, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name,
	     const void *value, size_t size, int flags)
{
	struct bpf_dynptr value_ptr;

	bpf_dynptr_from_mem(v, sizeof(v), 0, &value_ptr);

	bpf_set_dentry_xattr(dentry, xattr_bar, &value_ptr, 0);
	return 0;
}

SEC("lsm.s/inode_setxattr")
__failure __msg("calling kernel function bpf_remove_dentry_xattr is not allowed")
int BPF_PROG(test_inode_setxattr_failure_b, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name,
	     const void *value, size_t size, int flags)
{
	bpf_remove_dentry_xattr(dentry, xattr_bar);
	return 0;
}
