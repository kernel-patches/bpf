// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Cisco Systems, Inc. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
int init_result = -1;

static const char xattr_name[] = "bpf.test_label";
char xattr_value[] = "unconfined_u:object_r:user_home_t:s0";

SEC("lsm.s/inode_init_security")
int BPF_PROG(test_init_inode_xattr, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct lsm_xattrs *xattrs)
{
	struct bpf_dynptr value_ptr;
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	bpf_dynptr_from_mem(xattr_value, sizeof(xattr_value), 0, &value_ptr);
	init_result = bpf_init_inode_xattr(xattrs, xattr_name, &value_ptr);

	return 0;
}
