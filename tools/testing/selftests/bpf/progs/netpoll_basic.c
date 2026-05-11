// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "errno.h"

SEC("syscall")
__success __retval(0)
int netpoll_release(void *ctx)
{
	struct bpf_netpoll_opts opts = { .dev_name = "dummy0" };
	struct bpf_netpoll *bnp;
	int err = 0;

	bnp = bpf_netpoll_create(&opts, sizeof(opts), &err);
	if (!bnp)
		return err;

	bpf_netpoll_release(bnp);

	return 0;
}

SEC("syscall")
__failure __msg("Unreleased reference")
int netpoll_acquire(void *ctx)
{
	struct bpf_netpoll_opts opts = { .dev_name = "dummy0" };
	struct bpf_netpoll *bnp;
	int err = 0;

	bnp = bpf_netpoll_create(&opts, sizeof(opts), &err);
	if (!bnp)
		return err;

	bnp = bpf_netpoll_acquire(bnp);
	if (!bnp)
		return -EINVAL;

	bpf_netpoll_release(bnp);

	return 0;
}

char __license[] SEC("license") = "GPL";
