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

int urdt3_called;
int urdt3_cookie;
int urdt3_arg_cnt;
long urdt3_arg1;
int urdt3_arg2;
__u64 *urdt3_arg3;

SEC("urdt//proc/self/exe:3:dyn:urdt3")
int BPF_URDT(urdt3, long x, int y, __u64 *bla)
{
	if (my_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	__sync_fetch_and_add(&urdt3_called, 1);

	__sync_fetch_and_add(&urdt3_cookie, bpf_urdt_cookie(ctx));
	__sync_fetch_and_add(&urdt3_arg_cnt, bpf_urdt_arg_cnt(ctx));

	__sync_fetch_and_add(&urdt3_arg1, x);
	__sync_fetch_and_add(&urdt3_arg2, y);
	__sync_fetch_and_add(&urdt3_arg3, bla);

	return 0;
}

int urdt3alt_called;
int urdt3alt_cookie;
int urdt3alt_arg1;
__u64 *urdt3alt_arg2;
long urdt3alt_arg3;

SEC("urdt//proc/self/exe:3:dyn:urdt3alt")
int BPF_URDT(urdt3alt, int y, __u64 *bla, long x)
{
	__sync_fetch_and_add(&urdt3alt_called, 1);

	__sync_fetch_and_add(&urdt3alt_cookie, bpf_urdt_cookie(ctx));

	__sync_fetch_and_add(&urdt3alt_arg1, y);
	__sync_fetch_and_add(&urdt3alt_arg2, bla);
	__sync_fetch_and_add(&urdt3alt_arg3, x);

	return 0;
}

int urdt11_called;
int urdt11_args[11];

SEC("urdt//proc/self/exe:11:dyn:urdt11")
int BPF_URDT(urdt11, int arg1, int arg2, int arg3, int arg4, int arg5,
	     int arg6, int arg7, int arg8, int arg9, int arg10, int arg11)
{
	__sync_fetch_and_add(&urdt11_called, 1);
	__sync_fetch_and_add(&urdt11_args[0], arg1);
	__sync_fetch_and_add(&urdt11_args[1], arg2);
	__sync_fetch_and_add(&urdt11_args[2], arg3);
	__sync_fetch_and_add(&urdt11_args[3], arg4);
	__sync_fetch_and_add(&urdt11_args[4], arg5);
	__sync_fetch_and_add(&urdt11_args[5], arg6);
	__sync_fetch_and_add(&urdt11_args[6], arg7);
	__sync_fetch_and_add(&urdt11_args[7], arg8);
	__sync_fetch_and_add(&urdt11_args[8], arg9);
	__sync_fetch_and_add(&urdt11_args[9], arg10);
	__sync_fetch_and_add(&urdt11_args[10], arg11);

	return 0;
}

char _license[] SEC("license") = "GPL";
