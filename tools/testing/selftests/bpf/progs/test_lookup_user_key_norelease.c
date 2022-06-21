// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 */

#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/keyctl.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("lsm.s/bpf")
int BPF_PROG(bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	bpf_lookup_user_key(KEY_SPEC_SESSION_KEYRING, 0);
	return 0;
}
