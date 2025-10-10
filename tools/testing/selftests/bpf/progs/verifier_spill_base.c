// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../../../include/linux/filter.h"
#include "bpf_misc.h"

SEC("socket")
__log_level(2)
/* Check if compute_live_registers() processes r11 stores and loads*/
__msg("Live regs before insn:")
__msg("2: .12....... 0000000000000000 (7b) *(u64 *)(r10 -8) = r1")
__msg("3: ..2....... 0000000000000000 (7b) *(u64 *)(r11 -8) = r2")
__msg("4: .......... 0000000000000001 (79) r3 = *(u64 *)(r10 -8)")
__msg("5: ...3...... 0000000000000001 (79) r4 = *(u64 *)(r11 -8)")
__msg("6: ...34..... 0000000000000000 (b7) r0 = 0")
/* See if verifier tracks values stored by r11 */
__msg("0: R1=ctx() R10=fp0")
__msg("3: (7b) *(u64 *)(r11 -8) = r2         ; R2=7 sp-8=7")
__msg("5: (79) r4 = *(u64 *)(r11 -8)         ; R4=7")
/* See if r11 loads and stores are converted to r10 */
__xlated("2: *(u64 *)(r10 -8) = r1")
__xlated("3: *(u64 *)(r10 -16) = r2")
__xlated("4: r3 = *(u64 *)(r10 -8)")
__xlated("5: r4 = *(u64 *)(r10 -16)")
/* Finally, check that it executes as expected */
__retval(49)
__naked void convert_spill_base_simple(void)
{
	asm volatile(
	"r1 = 42;"
	"r2 = 7;"
	"*(u64 *)(r10 - 8) = r1;"
	"*(u64 *)(r11 - 8) = r2;"
	"r3 = *(u64 *)(r10 - 8);"
	"r4 = *(u64 *)(r11 - 8);"
	"r0 = 0;"
	"r0 += r3;"
	"r0 += r4;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
/* Check that spill slots in main and subprog are assigned independently */
/* main */
__xlated("3: *(u64 *)(r10 -8) = r0")
__xlated("4: *(u64 *)(r10 -16) = r1")
__xlated("5: *(u64 *)(r10 -24) = r2")
__xlated("6: r3 = *(u64 *)(r10 -8)")
__xlated("7: r4 = *(u64 *)(r10 -16)")
__xlated("8: r5 = *(u64 *)(r10 -24)")
__xlated("...")
__xlated("13: exit")
/* subprog */
__xlated("...")
__xlated("16: *(u64 *)(r10 -8) = r1")
__xlated("17: *(u64 *)(r10 -16) = r2")
__xlated("18: r3 = *(u64 *)(r10 -8)")
__xlated("19: r4 = *(u64 *)(r10 -16)")
__xlated("...")
__xlated("23: exit")
__retval(10)
__naked void convert_spill_base_subprog(void)
{
	asm volatile(
	"call subprog;"
	"r1 = 2;"
	"r2 = 3;"
	"*(u64 *)(r10 - 8)  = r0;"
	"*(u64 *)(r11 - 8)  = r1;"
	"*(u64 *)(r11 - 16) = r2;"
	"r3 = *(u64 *)(r10 - 8);"
	"r4 = *(u64 *)(r11 - 8);"
	"r5 = *(u64 *)(r11 - 16);"
	"r0 = 0;"
	"r0 += r3;"
	"r0 += r4;"
	"r0 += r5;"
	"exit;"
	::: __clobber_all);
}

static __naked __used void subprog(void)
{
	asm volatile(
	"r1 = 2;"
	"r2 = 3;"
	"*(u64 *)(r10 - 8) = r1;"
	"*(u64 *)(r11 - 8) = r2;"
	"r3 = *(u64 *)(r10 - 8);"
	"r4 = *(u64 *)(r11 - 8);"
	"r0 = 0;"
	"r0 += r3;"
	"r0 += r4;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__log_level(2)
/* Check if compute_live_registers() processes r11 stores and loads*/
__msg("Live regs before insn:")
__msg(" 4: 0123...... 0000000000000000 (7b) *(u64 *)(r11 -8) = r1")
__msg(" 5: 0123...... 0000000000000001 (7b) *(u64 *)(r11 -16) = r1")
__msg(" 6: 0123...... 0000000000000003 (7b) *(u64 *)(r11 -24) = r1")
__msg(" 7: 0.23...... 0000000000000003 (25) if r0 > 0x2a goto pc+2")
__msg(" 8: ...3...... 0000000000000001 (79) r2 = *(u64 *)(r11 -8)")
__msg(" 9: ..23...... 0000000000000000 (05) goto pc+1")
__msg("10: ..2....... 0000000000000002 (79) r3 = *(u64 *)(r11 -16)")
__msg("11: ..23...... 0000000000000000 (b7) r0 = 0")
__msg("12: 0.23...... 0000000000000000 (0f) r0 += r2")
__msg("13: 0..3...... 0000000000000000 (0f) r0 += r3")
__msg("14: 0......... 0000000000000000 (95) exit")
__naked void live_regs_join(void)
{
	asm volatile(
	"call %[bpf_get_prandom_u32];"
	"r1 = 42;"
	"r2 = 0;"
	"r3 = 0;"
	"*(u64 *)(r11 - 8)  = r1;"
	"*(u64 *)(r11 - 16) = r1;"
	"*(u64 *)(r11 - 24) = r1;"
	"if r0 > 42 goto 1f;"
	"r2 = *(u64 *)(r11 - 8);"
	"goto 2f;"
"1:"
	"r3 = *(u64 *)(r11 - 16);"
"2:"
	"r0 = 0;"
	"r0 += r2;"
	"r0 += r3;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
__msg("0: (85) call bpf_get_prandom_u32#7")
__msg("1: (b7) r1 = 42")
__msg("2: (7b) *(u64 *)(r11 -8) = r1         ; R1=42 sp-8=42")
__msg("3: (25) if r0 > 0x2a goto pc+1")
__msg("4: (7b) *(u64 *)(r11 -8) = r10        ; R10=fp0 sp-8=fp0")
__msg("5: (b7) r0 = 0")
__msg("6: (95) exit")
__msg("from 3 to 5: safe")
__msg("processed 8 insns {{.*}} total_states 3")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void dead_spill_pruning(void)
{
	asm volatile(
	"call %[bpf_get_prandom_u32];"
	"r1 = 42;"
	"*(u64 *)(r11 - 8) = r1;"
	"if r0 > 42 goto 1f;"
	"*(u64 *)(r11 - 8) = r10;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
__msg("4: (0f) r3 += r2")
__msg("mark_precise: frame0: last_idx 4 first_idx 0 subseq_idx -1 ")
__msg("mark_precise: frame0: regs=r2 stack= before 3: (bf) r3 = r10")
__msg("mark_precise: frame0: regs=r2 stack= before 2: (79) r2 = *(u64 *)(r11 -8)")
__msg("mark_precise: frame0: regs= stack= spill=-8 before 1: (7b) *(u64 *)(r11 -8) = r1")
__msg("mark_precise: frame0: regs=r1 stack= before 0: (b7) r1 = -8")
__naked void precision1(void)
{
	asm volatile(
	"r1 = -8;"
	"*(u64 *)(r11 - 8) = r1;"
	"r2 = *(u64 *)(r11 - 8);"
	"r3 = r10;"
	"r3 += r2;" /* make r2 precise */
	"r0 = *(u64 *)(r3 + 0);"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("from 4 to 6: R0=scalar(umin=43) R1=-8 R2=fp0 R10=fp0")
__msg("6: R0=scalar(umin=43) R1=-8 R2=fp0 R10=fp0")
__msg("6: (79) r3 = *(u64 *)(r11 -8)         ; R3=-8")
__msg("7: (0f) r2 += r3")
__msg("mark_precise: frame0: last_idx 7 first_idx 6 subseq_idx -1")
__msg("mark_precise: frame0: regs=r3 stack= before 6: (79) r3 = *(u64 *)(r11 -8)")
__msg("mark_precise: frame0: parent state regs= stack= spill=-8:  R0=scalar(umin=43) R1=-8 R2=fp0 R10=fp0 sp-8=P-8")
__msg("mark_precise: frame0: last_idx 4 first_idx 4 subseq_idx 6")
__msg("mark_precise: frame0: regs= stack= spill=-8 before 4: (25) if r0 > 0x2a goto pc+1")
/* previous branch already forced spill=-8 precision for parent state, so current iteration stops here */
__msg("mark_precise: frame0: parent state regs= stack=:  R0=scalar() R1=-8 R2=fp0 R10=fp0 sp-8=P-8")
__naked void precision2(void)
{
	asm volatile(
	"call %[bpf_get_prandom_u32];"
	"r1 = -8;"
	"r2 = r10;"
	"*(u64 *)(r11 - 8) = r1;"
	"if r0 > 42 goto 1f;"
	/* check that r11-8 propagation stops at states boundary */
	"r2 += -8;"
"1:"
	"r3 = *(u64 *)(r11 - 8);"
	"r2 += r3;" /* make r3 precise */
	"r1 = -16;"
	"r0 = *(u64 *)(r2 + 0);"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("from 1 to 7: R0=scalar(umin=8) R10=fp0")
/* ... */
__msg("9: (7b) *(u64 *)(r11 -8) = r1         ; R1=0 sp-8=0")
__msg("10: (7b) *(u64 *)(r11 -16) = r2")
__msg("frame 0: propagating sp-8,sp-16")
__msg("mark_precise: frame0: last_idx 11 first_idx 7 subseq_idx -1")
__msg("mark_precise: frame0: regs= stack= spill=-8,-16 before 10: (7b) *(u64 *)(r11 -16) = r2")
__msg("mark_precise: frame0: regs=r2 stack= spill=-8 before 9: (7b) *(u64 *)(r11 -8) = r1")
/* ... */
__msg("11: safe")
__naked void precision3(void)
{
	asm volatile(
	"call %[bpf_get_prandom_u32];"
	/* unpredictable jump */
	"if r0 > 7 goto 1f;"
	/* possibly generate same scalar ids for r3 and r4 */
	"r1 = 0;"
	"r1 = r1;"
	"*(u64 *)(r11 - 8)  = r1;"
	"*(u64 *)(r11 - 16) = r1;"
	"goto 2f;"
"1:"
	/* possibly generate different scalar ids for r3 and r4 */
	"r1 = 0;"
	"r2 = 0;"
	"*(u64 *)(r11 - 8)  = r1;"
	"*(u64 *)(r11 - 16) = r2;"
"2:"
	"r3 = *(u64 *)(r11 - 8);"
	"r4 = *(u64 *)(r11 - 16);"
	/* predictable jump, marks r3 and r4 precise */
	"if r3 == r4 goto +0;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__log_level(2)
/* check that scalar id is allocated for sp-8 */
__msg("1: (7b) *(u64 *)(r11 -8) = r0         ; R0=scalar(id=1) sp-8=scalar(id=1)")
/* ... */
__msg("7: (0f) r2 += r1")
/* check that precision propagation reaches sp-8 */
__msg("mark_precise: frame0: regs= stack= spill=-8 before 3: (15) if r0 == 0x0 goto pc+6")
__msg("mark_precise: frame0: regs= stack= spill=-8 before 2: (25) if r0 > 0x8 goto pc+7")
__msg("mark_precise: frame0: regs= stack= spill=-8 before 1: (7b) *(u64 *)(r11 -8) = r0")
__msg("mark_precise: frame0: regs=r0 stack= before 0: (85) call bpf_get_prandom_u32#7")
__naked void linked_regs1(void)
{
	asm volatile(
	"call %[bpf_get_prandom_u32];"
	"*(u64 *)(r11 - 8) = r0;"
	/* range info for r0 should propagate to sp-8 */
	"if r0 > 8 goto 1f;"
	"if r0 == 0 goto 1f;"
	"r1 = *(u64 *)(r11 - 8);"
	"r1 = -r1;"
	"r2 = r10;"
	/* this makes r1 precise and should propagate to sp-8 */
	"r2 += r1;"
	"r0 = *(u8 *)(r2 + 0);"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__msg("0: (bf) r1 = r11")
__msg("R11 is invalid")
__failure
__naked void spill_base_alias(void)
{
	asm volatile(
	"r1 = r11;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

SEC("socket")
__msg("0: (07) r11 += 1")
__msg("R11 is invalid")
__failure
__naked void spill_base_alu(void)
{
	asm volatile(
	"r11 += 1;"
	"r0 = 0;"
	"exit;"
	::: __clobber_all);
}

#define INVALID_INSN_TEST(name, msg, insn)		\
	SEC("socket")					\
	__msg(msg) __failure __naked void name(void)	\
	{						\
		asm volatile(				\
		".8byte %[i]; exit;"			\
		:: __imm_insn(i, insn)			\
		: __clobber_all);			\
	}

INVALID_INSN_TEST(bad_offset1, "invalid spill base offset",
		  BPF_RAW_INSN(BPF_STX | BPF_MEM | BPF_DW, 11 /* dst */, 0,  -7 /* off */, 0))
INVALID_INSN_TEST(bad_offset2, "invalid spill base offset",
		  BPF_RAW_INSN(BPF_STX | BPF_MEM | BPF_DW, 11 /* dst */, 0, -72 /* off */, 0))
INVALID_INSN_TEST(bad_size, "invalid spill base access operand size",
		  BPF_RAW_INSN(BPF_STX | BPF_MEM | BPF_W,  11 /* dst */, 0,  -8 /* off */, 0))
INVALID_INSN_TEST(bad_mode, "spill base access uses reserved fields",
		  BPF_RAW_INSN(BPF_STX | BPF_MEM | BPF_DW, 11 /* dst */, 0,  -8 /* off */, 1 /* imm */))

char _license[] SEC("license") = "GPL";
