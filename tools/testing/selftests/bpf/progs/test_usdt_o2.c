// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>

int my_pid;

int usdt1_called;
u64 usdt1_cookie;
int usdt1_arg_cnt;
int usdt1_arg_ret;
u64 usdt1_arg;
int usdt1_arg_size;

SEC("usdt")
int usdt1(struct pt_regs *ctx)
{
	long tmp;

	if (my_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;

	__sync_fetch_and_add(&usdt1_called, 1);

	usdt1_cookie = bpf_usdt_cookie(ctx);
	usdt1_arg_cnt = bpf_usdt_arg_cnt(ctx);

	usdt1_arg_ret = bpf_usdt_arg(ctx, 0, &tmp);
	usdt1_arg = (u64)tmp;
	usdt1_arg_size = bpf_usdt_arg_size(ctx, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
