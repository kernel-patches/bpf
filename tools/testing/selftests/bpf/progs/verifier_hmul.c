// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Tianci Cao */

#include <linux/bpf.h>
#include <limits.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../../../include/linux/filter.h"

#define BPF_UHMUL64_REG(DST, SRC) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MUL | BPF_X, DST, SRC, \
		     BPF_MUL_VARIANT_UHMUL, 0)

#define BPF_UHMUL64_IMM(DST, IMM) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MUL | BPF_K, DST, 0, \
		     BPF_MUL_VARIANT_UHMUL, IMM)

#define BPF_SHMUL64_REG(DST, SRC) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MUL | BPF_X, DST, SRC, \
		     BPF_MUL_VARIANT_SHMUL, 0)

#define BPF_SHMUL64_IMM(DST, IMM) \
	BPF_RAW_INSN(BPF_ALU64 | BPF_MUL | BPF_K, DST, 0, \
		     BPF_MUL_VARIANT_SHMUL, IMM)

/*
 * Inject UHMUL/SHMUL as raw instructions so these tests do not require
 * assembler support for the new mnemonics. All surrounding instructions use
 * existing BPF assembly syntax supported by the baseline selftests toolchain.
 */

#if defined(__BPF_FEATURE_ADDR_SPACE_CAST)

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

SEC("syscall")
__description("UHMUL64 with arena pointer dst")
__failure __msg("UHMUL/SHMUL with arena pointers are not supported")
__naked void uhmul64_arena_ptr(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r0 = 1;"
	"r0 = addr_space_cast(r0, 0x0, 0x1);"
	".8byte %[hmul];"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_insn(hmul, BPF_UHMUL64_IMM(BPF_REG_0, 2))
	: __clobber_all);
}

SEC("syscall")
__description("SHMUL64 with arena pointer src")
__failure __msg("UHMUL/SHMUL with arena pointers are not supported")
__naked void shmul64_arena_ptr(void)
{
	asm volatile (
	"r1 = %[arena] ll;"
	"r1 = 1;"
	"r1 = addr_space_cast(r1, 0x0, 0x1);"
	"r0 = 2;"
	".8byte %[hmul];"
	"exit;"
	:
	: __imm_addr(arena),
	  __imm_insn(hmul, BPF_SHMUL64_REG(BPF_REG_0, BPF_REG_1))
	: __clobber_all);
}

#endif

#if defined(__TARGET_ARCH_x86)

/*
 * BPF_PROG_TEST_RUN reports a 32-bit retval. Fold both halves of
 * (actual ^ expected) into w0 so retval == 0 checks the full 64-bit result.
 */

SEC("socket")
__description("UHMUL64, U64_MAX * U64_MAX, register source")
__success __success_unpriv __retval(0)
__naked void uhmul64_max_reg(void)
{
	asm volatile (
	"r0 = -1;"
	"r1 = -1;"
	".8byte %[hmul];"
	"r2 = -2;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_insn(hmul, BPF_UHMUL64_REG(BPF_REG_0, BPF_REG_1))
	: __clobber_all);
}

SEC("socket")
__description("UHMUL64, (1ULL << 63) * 2, register source")
__success __success_unpriv __retval(0)
__naked void uhmul64_pow2_reg(void)
{
	asm volatile (
	"r0 = 2;"
	"r1 = %[llong_min] ll;"
	".8byte %[hmul];"
	"r0 = r1;"
	"r2 = 1;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_const(llong_min, LLONG_MIN),
	  __imm_insn(hmul, BPF_UHMUL64_REG(BPF_REG_1, BPF_REG_0))
	: __clobber_all);
}

SEC("socket")
__description("UHMUL64, (1ULL << 63) * 2, R3 destination")
__success __success_unpriv __retval(0)
__naked void uhmul64_r3_dst(void)
{
	asm volatile (
	"r3 = %[llong_min] ll;"
	"r0 = 2;"
	".8byte %[hmul];"
	"r2 = 1;"
	"r3 ^= r2;"
	"r2 = r3;"
	"r2 >>= 32;"
	"w3 |= w2;"
	"r0 = r3;"
	"exit;"
	:
	: __imm_const(llong_min, LLONG_MIN),
	  __imm_insn(hmul, BPF_UHMUL64_REG(BPF_REG_3, BPF_REG_0))
	: __clobber_all);
}

SEC("socket")
__description("UHMUL64, (1ULL << 63) * 2, immediate source")
__success __success_unpriv __retval(0)
__naked void uhmul64_pow2_imm(void)
{
	asm volatile (
	"r0 = %[llong_min] ll;"
	".8byte %[hmul];"
	"r2 = 1;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_const(llong_min, LLONG_MIN),
	  __imm_insn(hmul, BPF_UHMUL64_IMM(BPF_REG_0, 2))
	: __clobber_all);
}

SEC("socket")
__description("UHMUL64, (1ULL << 63) * -2, immediate source")
__success __success_unpriv __retval(0)
__naked void uhmul64_neg_imm(void)
{
	asm volatile (
	"r0 = %[llong_min] ll;"
	".8byte %[hmul];"
	"r2 = %[llong_max] ll;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_const(llong_min, LLONG_MIN),
	  __imm_const(llong_max, LLONG_MAX),
	  __imm_insn(hmul, BPF_UHMUL64_IMM(BPF_REG_0, -2))
	: __clobber_all);
}

SEC("socket")
__description("SHMUL64, INT64_MAX * INT64_MAX, register source")
__success __success_unpriv __retval(0)
__naked void shmul64_max_reg(void)
{
	asm volatile (
	"r0 = %[llong_max] ll;"
	"r1 = %[llong_max] ll;"
	".8byte %[hmul];"
	"r2 = %[expected] ll;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_const(expected, 0x3fffffffffffffffULL),
	  __imm_const(llong_max, LLONG_MAX),
	  __imm_insn(hmul, BPF_SHMUL64_REG(BPF_REG_0, BPF_REG_1))
	: __clobber_all);
}

SEC("socket")
__description("SHMUL64, INT64_MIN * -2, register source")
__success __success_unpriv __retval(0)
__naked void shmul64_min_neg2_reg(void)
{
	asm volatile (
	"r0 = %[llong_min] ll;"
	"r1 = -2;"
	".8byte %[hmul];"
	"r2 = 1;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_const(llong_min, LLONG_MIN),
	  __imm_insn(hmul, BPF_SHMUL64_REG(BPF_REG_0, BPF_REG_1))
	: __clobber_all);
}

SEC("socket")
__description("SHMUL64, 1 * -2, immediate source")
__success __success_unpriv __retval(0)
__naked void shmul64_neg_imm(void)
{
	asm volatile (
	"r0 = 1;"
	".8byte %[hmul];"
	"r2 = -1;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_insn(hmul, BPF_SHMUL64_IMM(BPF_REG_0, -2))
	: __clobber_all);
}

SEC("socket")
__description("SHMUL64, INT64_MIN * 2, immediate source")
__success __success_unpriv __retval(0)
__naked void shmul64_min_imm(void)
{
	asm volatile (
	"r0 = %[llong_min] ll;"
	".8byte %[hmul];"
	"r2 = -1;"
	"r0 ^= r2;"
	"r2 = r0;"
	"r2 >>= 32;"
	"w0 |= w2;"
	"exit;"
	:
	: __imm_const(llong_min, LLONG_MIN),
	  __imm_insn(hmul, BPF_SHMUL64_IMM(BPF_REG_0, 2))
	: __clobber_all);
}

#else

SEC("socket")
__description("UHMUL/SHMUL are not supported by this JIT, use a dummy test")
__skip("UHMUL/SHMUL are not supported by this jit")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
