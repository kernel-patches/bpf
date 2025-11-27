// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. */

#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <linux/limits.h>
#include "bpf_misc.h"
#include "bpf_experimental.h"

static char buf[PATH_MAX];

SEC("lsm.s/file_open")
__success
int BPF_PROG(kern_path_success)
{
	struct path *p;

	p = bpf_kern_path("/proc/self/exe", 0);
	if (!p)
		return 0;

	bpf_path_d_path(p, buf, sizeof(buf));

	bpf_path_put(p);
	return 0;
}

SEC("lsm.s/file_open")
__success
int BPF_PROG(kern_path_multiple_paths)
{
	struct path *p1, *p2;

	p1 = bpf_kern_path("/proc/self/exe", 0);
	if (!p1)
		return 0;

	p2 = bpf_kern_path("/proc/self/cwd", 0);
	if (!p2) {
		bpf_path_put(p1);
		return 0;
	}

	bpf_path_d_path(p1, buf, sizeof(buf));
	bpf_path_d_path(p2, buf, sizeof(buf));

	bpf_path_put(p2);
	bpf_path_put(p1);
	return 0;
}

char _license[] SEC("license") = "GPL";
