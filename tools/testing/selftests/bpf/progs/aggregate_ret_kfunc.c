// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

/*
 * Reference kfunc addresses to force those BTF to be emitted. Taking the address
 * (rather than calling) avoids any dependence on the compiler lowering an
 * __int128 or struct return value, which the BPF backend only supports from
 * LLVM 23 on.
 */
void __kfunc_btf_root(void)
{
	asm volatile (""
	:
	: "r"(&bpf_kfunc_call_test_i128),
	  "r"(&bpf_kfunc_call_test_ret_ptr),
	  "r"(&bpf_kfunc_call_test_ret_ii));
}

SEC("tc")
__success __retval(0)
__log_level(2)
__msg("mark_precise: frame0: last_idx 7 first_idx 0 subseq_idx -1")
__msg("mark_precise: frame0: regs=r6 stack= before 6: (07) r1 += -8")
__msg("mark_precise: frame0: regs=r6 stack= before 5: (bf) r1 = r10")
__msg("mark_precise: frame0: regs=r6 stack= before 4: (57) r6 &= 7")
__msg("mark_precise: frame0: regs=r6 stack= before 3: (bf) r6 = r2")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (85) call bpf_kfunc_call_test_i128")
__naked int aggregate_ret_kfunc_precise(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = 2;"
	"call %[bpf_kfunc_call_test_i128];"
	"r6 = r2;"		/* second return half */
	"r6 &= 7;"		/* keep it in [0, 7] to index the stack */
	"r1 = r10;"
	"r1 += -8;"
	"r1 += r6;"		/* ptr += scalar marks r6 (hence R2) precise */
	"r0 = 0;"
	"*(u8 *)(r1 + 0) = r0;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_i128)
	: __clobber_all);
}

SEC("tc")
__failure __msg("is not composed of scalars")
__naked int aggregate_ret_kfunc_ptr_fail(void)
{
	asm volatile (
	"r1 = 0;"
	"call %[bpf_kfunc_call_test_ret_ptr];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_ret_ptr)
	: __clobber_all);
}

SEC("tc")
__failure __msg("R2 !read_ok")
__naked int aggregate_ret_kfunc_small_no_r2(void)
{
	asm volatile (
	"r1 = 0;"
	"r2 = 0;"
	"call %[bpf_kfunc_call_test_ret_ii];"
	"r0 = r2;"	/* R2 is not a return register for a <=8 byte struct */
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_ret_ii)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
