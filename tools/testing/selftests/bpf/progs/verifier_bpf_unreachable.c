// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("bpf_unreachable with simple c code")
__failure __msg("unexpected bpf_unreachable() due to uninitialized variable?")
void bpf_unreachable_with_simple_c(void)
{
	bpf_unreachable();
}

SEC("socket")
__description("bpf_unreachable as the second-from-last insn")
__failure __msg("unexpected bpf_unreachable() due to uninitialized variable?")
__naked void bpf_unreachable_at_func_end(void)
{
	asm volatile (
	"r0 = 0;"
	"call %[bpf_unreachable];"
	"exit;"
	:
	: __imm(bpf_unreachable)
	: __clobber_all);
}

SEC("socket")
__description("dead code bpf_unreachable() in the middle of code")
__success
__naked void dead_bpf_unreachable_in_middle(void)
{
	asm volatile (
	"r0 = 0;"
	"if r0 == 0 goto +1;"
	"call %[bpf_unreachable];"
	"r0 = 2;"
	"exit;"
	:
	: __imm(bpf_unreachable)
	: __clobber_all);
}

SEC("socket")
__description("reachable bpf_unreachable() in the middle of code")
__failure __msg("unexpected bpf_unreachable() due to uninitialized variable?")
__naked void live_bpf_unreachable_in_middle(void)
{
	asm volatile (
	"r0 = 0;"
	"if r0 == 1 goto +1;"
	"call %[bpf_unreachable];"
	"r0 = 2;"
	"exit;"
	:
	: __imm(bpf_unreachable)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
