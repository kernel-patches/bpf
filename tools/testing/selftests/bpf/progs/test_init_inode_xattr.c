// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Isovalent, a Cisco company. */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
int init_result = -1;

const char xattr_name[] = "bpf.test_label";
char xattr_value[] = "test_value";

SEC("lsm.s/inode_init_security")
int BPF_PROG(test_init_inode_xattr, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct lsm_xattr_ctx *xattr_ctx)
{
	struct bpf_dynptr value_ptr;
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	bpf_dynptr_from_mem(xattr_value, sizeof(xattr_value), 0, &value_ptr);
	init_result = bpf_init_inode_xattr(xattr_ctx, xattr_name, &value_ptr);

	return 0;
}
