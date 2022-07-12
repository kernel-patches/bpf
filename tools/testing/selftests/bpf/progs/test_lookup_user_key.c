// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <errno.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u32 monitored_pid;
__u32 key_serial;
__u64 flags;

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct key *key;
	__u32 pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (pid != monitored_pid)
		return 0;

	key = bpf_lookup_user_key(key_serial, flags);
	if (key)
		bpf_key_put(key);

	return (key) ? 0 : -ENOENT;
}
