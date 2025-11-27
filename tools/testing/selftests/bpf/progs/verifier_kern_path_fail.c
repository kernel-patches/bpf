// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

static char buf[PATH_MAX];

SEC("lsm.s/file_open")
__failure __msg("Unreleased reference")
int BPF_PROG(kern_path_unreleased)
{
	struct path *p;

	p = bpf_kern_path("/proc/self/exe", 0);
	if (!p)
		return 0;

	/* Acquired but never released - should fail verification */
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("pointer type STRUCT path must point to scalar, or struct with scalar")
int BPF_PROG(path_put_unacquired)
{
	struct path p = {};

	/* Can't release an unacquired path - should fail verification */
	bpf_path_put(&p);
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("pointer type STRUCT path must point to scalar, or struct with scalar")
int BPF_PROG(path_use_after_put, struct file *file)
{
	struct path *p;

	p = bpf_kern_path("/proc/self/exe", 0);
	if (!p)
		return 0;

	bpf_path_put(p);

	/* Using path after put - should fail verification */
	bpf_path_d_path(p, buf, sizeof(buf));
	return 0;
}

SEC("lsm.s/file_open")
__failure __msg("pointer type STRUCT path must point to scalar, or struct with scalar")
int BPF_PROG(double_path_put)
{
	struct path *p;

	p = bpf_kern_path("/proc/self/exe", 0);
	if (!p)
		return 0;

	bpf_path_put(p);
	/* Double put - should fail verification */
	bpf_path_put(p);
	return 0;
}

SEC("fentry/vfs_open")
__failure __msg("calling kernel function bpf_kern_path is not allowed")
int BPF_PROG(kern_path_non_lsm)
{
	struct path *p;

	/* Calling bpf_kern_path() from a non-LSM BPF program isn't permitted */
	p = bpf_kern_path("/proc/self/exe", 0);
	if (p)
		bpf_path_put(p);
	return 0;
}

SEC("lsm.s/sb_eat_lsm_opts")
__failure __msg("arg#0 doesn't point to a const string")
int BPF_PROG(kern_path_non_const_str, char *options, void **mnt_opts)
{
	struct path *p;

	/* Calling bpf_kern_path() from a with non-const string isn't permitted */
	p = bpf_kern_path(options, 0);
	if (p)
		bpf_path_put(p);
	return 0;
}


char _license[] SEC("license") = "GPL";
