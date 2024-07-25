// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include "bpf_kfuncs.h"

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
__u32 number_of_xattr_found;

static const char expected_value[] = "hello";
char value[32];

SEC("lsm.s/file_open")
int BPF_PROG(test_file_open, struct file *f)
{
	struct bpf_dynptr value_ptr;
	struct dentry *dentry, *prev_dentry;
	__u32 pid, matches = 0;
	int i, ret;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	bpf_dynptr_from_mem(value, sizeof(value), 0, &value_ptr);

	dentry = bpf_file_dentry(f);

	for (i = 0; i < 10; i++) {
		ret = bpf_get_dentry_xattr(dentry, "user.kfunc", &value_ptr);
		if (ret == sizeof(expected_value) &&
		    !bpf_strncmp(value, ret, expected_value))
			matches++;

		prev_dentry = dentry;
		dentry = bpf_dget_parent(prev_dentry);
		bpf_dput(prev_dentry);
	}

	bpf_dput(dentry);
	number_of_xattr_found = matches;
	return 0;
}
