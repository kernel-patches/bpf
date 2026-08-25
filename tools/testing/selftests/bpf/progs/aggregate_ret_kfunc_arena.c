// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

void __kfunc_btf_root(void)
{
	asm volatile (""
	:
	: "r"(&bpf_kfunc_call_test_ret_arena),
	  "r"(&bpf_kfunc_call_test_ret_arena_mixed));
}

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
__naked int aggregate_ret_kfunc_arena(void)
{
	asm volatile (
	"call %[bpf_kfunc_call_test_ret_arena];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_ret_arena)
	: __clobber_all);
}

SEC("tc")
__arch_x86_64 __arch_arm64
__load_if_JITed()
__success __retval(0)
__naked int aggregate_ret_kfunc_arena_mixed(void)
{
	asm volatile (
	"r1 = 0;"
	"call %[bpf_kfunc_call_test_ret_arena_mixed];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_ret_arena_mixed)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
