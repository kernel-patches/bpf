// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

volatile const short val1 = -1;
volatile const int val2 = -1;
short val3 = -1;
int val4 = -1;
int done1, done2, ret1, ret2;

SEC("?raw_tp/sys_enter")
int rdonly_map_prog(const void *ctx)
{
	if (done1)
		return 0;

	done1 = 1;
	if (val1 == val2)
		ret1 = 1;
	return 0;

}

SEC("?raw_tp/sys_enter")
int map_val_prog(const void *ctx)
{
	if (done2)
		return 0;

	done2 = 1;
	if (val3 == val4)
		ret2 = 1;
	return 0;

}

struct bpf_testmod_struct_arg_1 {
	int a;
};

long long int_member;

SEC("?fentry/bpf_testmod_test_arg_ptr_to_struct")
int BPF_PROG2(test_ptr_struct_arg, struct bpf_testmod_struct_arg_1 *, p)
{
	int_member = p->a;
        return 0;
}

long long set_optlen, set_retval;

SEC("?cgroup/getsockopt")
int _getsockopt(volatile struct bpf_sockopt *ctx)
{
	int old_optlen, old_retval;

	old_optlen = ctx->optlen;
	old_retval = ctx->retval;

	ctx->optlen = -1;
	ctx->retval = -1;

	set_optlen = ctx->optlen;
	set_retval = ctx->retval;

	ctx->optlen = old_optlen;
	ctx->retval = old_retval;

	return 0;
}

char _license[] SEC("license") = "GPL";
