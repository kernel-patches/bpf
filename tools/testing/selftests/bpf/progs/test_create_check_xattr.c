// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;

const char xattr_bar[] = "security.bpf.bar";
char read_value[32];

bool create_get_dentry_xattr_fail;
bool create_set_dentry_xattr_fail;
bool create_remove_dentry_xattr_fail;

SEC("lsm.s/inode_create")
int BPF_PROG(test_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct bpf_dynptr value_ptr;
	__u32 pid;
	int ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	bpf_dynptr_from_mem(read_value, sizeof(read_value), 0, &value_ptr);

	/* read security.bpf.bar */
	ret = bpf_get_dentry_xattr(dentry, xattr_bar, &value_ptr);
	if (ret == -EINVAL)
		create_get_dentry_xattr_fail = true;

	/* set security.bpf.bar */
	ret = bpf_set_dentry_xattr(dentry, xattr_bar, &value_ptr, 0);
	if (ret == -EINVAL)
		create_set_dentry_xattr_fail = true;

	/* remove security.bpf.bar */
	ret = bpf_remove_dentry_xattr(dentry, xattr_bar);
	if (ret == -EINVAL)
		create_remove_dentry_xattr_fail = true;

	return 0;
}
