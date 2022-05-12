// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Google LLC.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

#define XATTR_NAME "security.bpf"
#define XATTR_VALUE "test_progs"

__u64 result = 0;

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(bprm_cc, struct linux_binprm *bprm)
{
	struct task_struct *current = bpf_get_current_task_btf();
	char dir_xattr_value[64];
	int xattr_sz;

	xattr_sz = bpf_getxattr(bprm->file->f_path.mnt->mnt_userns,
				bprm->file->f_path.dentry, XATTR_NAME,
				dir_xattr_value, 64);

	if (xattr_sz <= 0)
		return;

	if (!bpf_strncmp(dir_xattr_value, sizeof(XATTR_VALUE), XATTR_VALUE))
		result = 1;
}
