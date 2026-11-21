// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern int bpf_kfunc_variant___none(struct inode *p) __weak __ksym;

char _license[] SEC("license") = "GPL";

SEC("syscall")
__retval(1)
int unsuffixed_name(void *ctx)
{
	return bpf_kfunc_variant(NULL);
}

SEC("syscall")
__retval(2)
int kernel_variant(void *ctx)
{
	return bpf_kfunc_variant___v2(NULL);
}

SEC("syscall")
__retval(0)
int no_match(void *ctx)
{
	return bpf_ksym_exists(bpf_kfunc_variant___none);
}
