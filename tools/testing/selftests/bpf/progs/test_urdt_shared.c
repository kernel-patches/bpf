// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/urdt.bpf.h>

int my_pid;

int urdt0_called;
int urdt0_cookie;
int urdt0_arg_cnt;
int urdt0_arg_ret;

SEC("urdt")
int BPF_URDT(urdt0)
{
	long tmp;

	if (my_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	__sync_fetch_and_add(&urdt0_called, 1);

	urdt0_cookie = bpf_urdt_cookie(ctx);
	urdt0_arg_cnt = bpf_urdt_arg_cnt(ctx);
	/* should return -ENOENT for any arg_num */
	urdt0_arg_ret = bpf_usdt_arg(ctx, bpf_get_prandom_u32(), &tmp);
	return 0;
}

int urdt4_called;
int urdt4_cookie;
int urdt4_arg_cnt;
long urdt4_arg1;
int urdt4_arg2;
int urdt4_arg3;
__u64 *urdt4_arg4;

SEC("urdt/./tools/build/libbpf/libbpf.so:4:dyn:urdt4")
int BPF_URDT(urdt4, long x, int y, int z, __u64 *bla)
{
	if (my_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	__sync_fetch_and_add(&urdt4_called, 1);

	__sync_fetch_and_add(&urdt4_cookie, bpf_urdt_cookie(ctx));
	__sync_fetch_and_add(&urdt4_arg_cnt, bpf_urdt_arg_cnt(ctx));

	__sync_fetch_and_add(&urdt4_arg1, x);
	__sync_fetch_and_add(&urdt4_arg2, y);
	__sync_fetch_and_add(&urdt4_arg3, z);
	__sync_fetch_and_add(&urdt4_arg4, bla);

	return 0;
}

char _license[] SEC("license") = "GPL";
