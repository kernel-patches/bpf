// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_misc.h"
#include "bpf_experimental.h"

__naked __noinline __used
unsigned __int128 exception_cb_bad_ret_type3(u64 cookie)
{
	asm volatile (
	"r0 = r1;"
	"r2 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("?tc")
__exception_cb(exception_cb_bad_ret_type3)
__failure __msg("exception cb cannot return value larger than 8 bytes")
__btf_func_path("btf__exceptions_ret_pair_fail.bpf.o")
int reject_exception_cb_ret_pair(void *ctx)
{
	bpf_throw(0);
	return 0;
}

char _license[] SEC("license") = "GPL";
