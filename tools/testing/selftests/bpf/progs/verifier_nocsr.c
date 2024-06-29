// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#define __xlated_bpf_get_smp_processor_id		\
	__xlated(": w0 = ")				\
	__xlated(": r0 = &(void __percpu *)(r0)")	\
	__xlated(": r0 = *(u32 *)(r0 +0)")

SEC("raw_tp")
__xlated("4: r5 = 5")
__xlated_bpf_get_smp_processor_id
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

SEC("raw_tp")
__xlated("1: *(u64 *)(r10 -16) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("1: *(u64 *)(r10 -16) = r6")
__xlated_bpf_get_smp_processor_id
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
__xlated("1: *(u64 *)(r10 -16) = r0")
__xlated_bpf_get_smp_processor_id
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
__xlated("2: *(u64 *)(r2 -16) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("1: *(u64 *)(r10 -16) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("2: *(u64 *)(r10 -16) = r1")
__xlated_bpf_get_smp_processor_id
__xlated("6: r1 = *(u64 *)(r10 -8)")
__success
__naked void wrong_off_in_pattern(void)
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
__xlated("1: *(u32 *)(r10 -16) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("2: *(u32 *)(r10 -8) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("0: r1 = 1")
__xlated("1: r2 = 2")
/* not patched, spills for -8, -16 not removed */
__xlated("2: *(u64 *)(r10 -8) = r1")
__xlated("3: *(u64 *)(r10 -16) = r2")
__xlated_bpf_get_smp_processor_id
__xlated("7: r2 = *(u64 *)(r10 -16)")
__xlated("8: r1 = *(u64 *)(r10 -8)")
/* patched, spills for -16, -24 removed */
__xlated_bpf_get_smp_processor_id
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
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("6: *(u64 *)(r10 -16) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("6: *(u64 *)(r10 -16) = r1")
__xlated_bpf_get_smp_processor_id
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
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated_bpf_get_smp_processor_id
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
/* main, not patched */
__xlated("1: *(u64 *)(r10 -8) = r1")
__xlated_bpf_get_smp_processor_id
__xlated("5: r1 = *(u64 *)(r10 -8)")
__xlated("9: call pc+1")
__xlated("10: exit")
/* subprogram, patched */
__xlated("11: r1 = 1")
__xlated_bpf_get_smp_processor_id
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
/* main */
__xlated("0: r1 = 1")
__xlated_bpf_get_smp_processor_id
__xlated("4: call pc+1")
__xlated("5: exit")
/* subprogram */
__xlated("6: r1 = 1")
__xlated_bpf_get_smp_processor_id
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
