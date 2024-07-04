// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("raw_tp")
__arch_x86_64
__xlated("4: r5 = 5")
__xlated("5: w0 = ")
__xlated("6: r0 = &(void __percpu *)(r0)")
__xlated("7: r0 = *(u32 *)(r0 +0)")
__xlated("8: exit")
__success
__naked void simple(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = 2;"
	"r3 = 3;"
	"r4 = 4;"
	"r5 = 5;"
	"*(u64 *)(r10 - 16) = r1;"
	"*(u64 *)(r10 - 24) = r2;"
	"*(u64 *)(r10 - 32) = r3;"
	"*(u64 *)(r10 - 40) = r4;"
	"*(u64 *)(r10 - 48) = r5;"
	"call %[bpf_get_smp_processor_id];"
	"r5 = *(u64 *)(r10 - 48);"
	"r4 = *(u64 *)(r10 - 40);"
	"r3 = *(u64 *)(r10 - 32);"
	"r2 = *(u64 *)(r10 - 24);"
	"r1 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

/* The logic for detecting and verifying nocsr pattern is the same for
 * any arch, however x86 differs from arm64 or riscv64 in a way
 * bpf_get_smp_processor_id is rewritten:
 * - on x86 it is done by verifier
 * - on arm64 and riscv64 it is done by jit
 *
 * Which leads to different xlated patterns for different archs:
 * - on x86 the call is expanded as 3 instructions
 * - on arm64 and riscv64 the call remains as is
 *   (but spills/fills are still removed)
 *
 * It is really desirable to check instruction indexes in the xlated
 * patterns, so add this canary test to check that function rewrite by
 * jit is correctly processed by nocsr logic, keep the rest of the
 * tests as x86.
 */
SEC("raw_tp")
__arch_arm64
__arch_riscv64
__xlated("0: r1 = 1")
__xlated("1: call bpf_get_smp_processor_id")
__xlated("2: exit")
__success
__naked void canary_arm64_riscv64(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: r0 = &(void __percpu *)(r0)")
__xlated("3: exit")
__success
__naked void canary_zero_spills(void)
{
	asm volatile (
	"call %[bpf_get_smp_processor_id];"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -16) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r2 = *(u64 *)(r10 -16)")
__success
__naked void wrong_reg_in_pattern1(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r2 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -16) = r6")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r6 = *(u64 *)(r10 -16)")
__success
__naked void wrong_reg_in_pattern2(void)
{
	asm volatile (
	"r6 = 1;"
	"*(u64 *)(r10 - 16) = r6;"
	"call %[bpf_get_smp_processor_id];"
	"r6 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -16) = r0")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r0 = *(u64 *)(r10 -16)")
__success
__naked void wrong_reg_in_pattern3(void)
{
	asm volatile (
	"r0 = 1;"
	"*(u64 *)(r10 - 16) = r0;"
	"call %[bpf_get_smp_processor_id];"
	"r0 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("2: *(u64 *)(r2 -16) = r1")
__xlated("4: r0 = &(void __percpu *)(r0)")
__xlated("6: r1 = *(u64 *)(r10 -16)")
__success
__naked void wrong_base_in_pattern(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = r10;"
	"*(u64 *)(r2 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -16) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r2 = 1")
__success
__naked void wrong_insn_in_pattern(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r2 = 1;"
	"r1 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("2: *(u64 *)(r10 -16) = r1")
__xlated("4: r0 = &(void __percpu *)(r0)")
__xlated("6: r1 = *(u64 *)(r10 -8)")
__success
__naked void wrong_off_in_pattern1(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u32 *)(r10 -4) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r1 = *(u32 *)(r10 -4)")
__success
__naked void wrong_off_in_pattern2(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u32 *)(r10 - 4) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u32 *)(r10 - 4);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u32 *)(r10 -16) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r1 = *(u32 *)(r10 -16)")
__success
__naked void wrong_size_in_pattern(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u32 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u32 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("2: *(u32 *)(r10 -8) = r1")
__xlated("4: r0 = &(void __percpu *)(r0)")
__xlated("6: r1 = *(u32 *)(r10 -8)")
__success
__naked void partial_pattern(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = 2;"
	"*(u32 *)(r10 - 8) = r1;"
	"*(u64 *)(r10 - 16) = r2;"
	"call %[bpf_get_smp_processor_id];"
	"r2 = *(u64 *)(r10 - 16);"
	"r1 = *(u32 *)(r10 - 8);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("0: r1 = 1")
__xlated("1: r2 = 2")
/* not patched, spills for -8, -16 not removed */
__xlated("2: *(u64 *)(r10 -8) = r1")
__xlated("3: *(u64 *)(r10 -16) = r2")
__xlated("5: r0 = &(void __percpu *)(r0)")
__xlated("7: r2 = *(u64 *)(r10 -16)")
__xlated("8: r1 = *(u64 *)(r10 -8)")
/* patched, spills for -16, -24 removed */
__xlated("10: r0 = &(void __percpu *)(r0)")
__xlated("12: exit")
__success
__naked void min_stack_offset(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = 2;"
	/* this call won't be patched */
	"*(u64 *)(r10 - 8) = r1;"
	"*(u64 *)(r10 - 16) = r2;"
	"call %[bpf_get_smp_processor_id];"
	"r2 = *(u64 *)(r10 - 16);"
	"r1 = *(u64 *)(r10 - 8);"
	/* this call would be patched */
	"*(u64 *)(r10 - 16) = r1;"
	"*(u64 *)(r10 - 24) = r2;"
	"call %[bpf_get_smp_processor_id];"
	"r2 = *(u64 *)(r10 - 24);"
	"r1 = *(u64 *)(r10 - 16);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r1 = *(u64 *)(r10 -8)")
__success
__naked void bad_fixed_read(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"r1 = r10;"
	"r1 += -8;"
	"r1 = *(u64 *)(r1 - 0);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r1 = *(u64 *)(r10 -8)")
__success
__naked void bad_fixed_write(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"r1 = r10;"
	"r1 += -8;"
	"*(u64 *)(r1 - 0) = r1;"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("6: *(u64 *)(r10 -16) = r1")
__xlated("8: r0 = &(void __percpu *)(r0)")
__xlated("10: r1 = *(u64 *)(r10 -16)")
__success
__naked void bad_varying_read(void)
{
	asm volatile (
	"r6 = *(u64 *)(r1 + 0);" /* random scalar value */
	"r6 &= 0x7;"		 /* r6 range [0..7] */
	"r6 += 0x2;"		 /* r6 range [2..9] */
	"r7 = 0;"
	"r7 -= r6;"		 /* r7 range [-9..-2] */
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 16);"
	"r1 = r10;"
	"r1 += r7;"
	"r1 = *(u8 *)(r1 - 0);" /* touches slot [-16..-9] where spills are stored */
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("6: *(u64 *)(r10 -16) = r1")
__xlated("8: r0 = &(void __percpu *)(r0)")
__xlated("10: r1 = *(u64 *)(r10 -16)")
__success
__naked void bad_varying_write(void)
{
	asm volatile (
	"r6 = *(u64 *)(r1 + 0);" /* random scalar value */
	"r6 &= 0x7;"		 /* r6 range [0..7] */
	"r6 += 0x2;"		 /* r6 range [2..9] */
	"r7 = 0;"
	"r7 -= r6;"		 /* r7 range [-9..-2] */
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 16);"
	"r1 = r10;"
	"r1 += r7;"
	"*(u8 *)(r1 - 0) = r7;" /* touches slot [-16..-9] where spills are stored */
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r1 = *(u64 *)(r10 -8)")
__success
__naked void bad_write_in_subprog(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"r1 = r10;"
	"r1 += -8;"
	"call bad_write_in_subprog_aux;"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

__used
__naked static void bad_write_in_subprog_aux(void)
{
	asm volatile (
	"r0 = 1;"
	"*(u64 *)(r1 - 0) = r0;"	/* invalidates nocsr contract for caller: */
	"exit;"				/* caller stack at -8 used outside of the pattern */
	::: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
/* main, not patched */
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated("3: r0 = &(void __percpu *)(r0)")
__xlated("5: r1 = *(u64 *)(r10 -8)")
__xlated("9: call pc+1")
__xlated("10: exit")
/* subprogram, patched */
__xlated("11: r1 = 1")
__xlated("13: r0 = &(void __percpu *)(r0)")
__xlated("15: exit")
__success
__naked void invalidate_one_subprog(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"r1 = r10;"
	"r1 += -8;"
	"r1 = *(u64 *)(r1 - 0);"
	"call invalidate_one_subprog_aux;"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

__used
__naked static void invalidate_one_subprog_aux(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 8) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 8);"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("raw_tp")
__arch_x86_64
/* main */
__xlated("0: r1 = 1")
__xlated("2: r0 = &(void __percpu *)(r0)")
__xlated("4: call pc+1")
__xlated("5: exit")
/* subprogram */
__xlated("6: r1 = 1")
__xlated("8: r0 = &(void __percpu *)(r0)")
__xlated("10: *(u64 *)(r10 -16) = r1")
__xlated("11: exit")
__success
__naked void subprogs_use_independent_offsets(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 16) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 16);"
	"call subprogs_use_independent_offsets_aux;"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

__used
__naked static void subprogs_use_independent_offsets_aux(void)
{
	asm volatile (
	"r1 = 1;"
	"*(u64 *)(r10 - 24) = r1;"
	"call %[bpf_get_smp_processor_id];"
	"r1 = *(u64 *)(r10 - 24);"
	"*(u64 *)(r10 - 16) = r1;"
	"exit;"
	:
	: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
