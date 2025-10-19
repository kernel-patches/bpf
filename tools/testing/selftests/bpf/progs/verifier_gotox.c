// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2025 Isovalent */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../../../include/linux/filter.h"

#ifdef __TARGET_ARCH_x86

#define DEFINE_SIMPLE_JUMP_TABLE_PROG(NAME, SRC_REG, OFF, IMM, OUTCOME)	\
									\
	SEC("socket")							\
	OUTCOME								\
	__naked void jump_table_ ## NAME(void)				\
	{								\
		asm volatile ("						\
		.pushsection .jumptables,\"\",@progbits;		\
	jt0_%=:								\
		.quad ret0_%=;						\
		.quad ret1_%=;						\
		.size jt0_%=, 16;					\
		.global jt0_%=;						\
		.popsection;						\
									\
		r0 = jt0_%= ll;						\
		r0 += 8;						\
		r0 = *(u64 *)(r0 + 0);					\
		.8byte %[gotox_r0];					\
		ret0_%=:						\
		r0 = 0;							\
		exit;							\
		ret1_%=:						\
		r0 = 1;							\
		exit;							\
	"	:							\
		: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, (SRC_REG), (OFF) , (IMM))) \
		: __clobber_all);					\
	}

/*
 * The first program which doesn't use reserved fields
 * loads and works properly. The rest fail to load.
 */
DEFINE_SIMPLE_JUMP_TABLE_PROG(ok,                          BPF_REG_0, 0, 0, __success __retval(1))
DEFINE_SIMPLE_JUMP_TABLE_PROG(reserved_field_src_reg,      BPF_REG_1, 0, 0, __failure __msg("BPF_JA|BPF_X uses reserved fields"))
DEFINE_SIMPLE_JUMP_TABLE_PROG(reserved_field_non_zero_off, BPF_REG_0, 1, 0, __failure __msg("BPF_JA|BPF_X uses reserved fields"))
DEFINE_SIMPLE_JUMP_TABLE_PROG(reserved_field_non_zero_imm, BPF_REG_0, 0, 1, __failure __msg("BPF_JA|BPF_X uses reserved fields"))

/*
 * Gotox is forbidden when there is no jump table loaded
 * which points to the sub-function where the gotox is used
 */
SEC("socket")
__failure __msg("no jump tables found for subprog starting at 0")
__naked void jump_table_no_jump_table(void)
{
	asm volatile ("						\
	.8byte %[gotox_r0];					\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0))
	: __clobber_all);
}

/*
 * Incorrect type of the target register, only PTR_TO_INSN allowed
 */
SEC("socket")
__failure __msg("R1 has type 1, expected PTR_TO_INSN")
__naked void jump_table_incorrect_dst_reg_type(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%=;						\
	.quad ret1_%=;						\
	.size jt0_%=, 16;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 += 8;						\
	r0 = *(u64 *)(r0 + 0);					\
	r1 = 42;						\
	.8byte %[gotox_r1];					\
	ret0_%=:						\
	r0 = 0;							\
	exit;							\
	ret1_%=:						\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r1, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_1, 0, 0 , 0))
	: __clobber_all);
}

#define DEFINE_INVALID_SIZE_PROG(READ_SIZE, OUTCOME)			\
									\
	SEC("socket")							\
	OUTCOME								\
	__naked void jump_table_invalid_read_size_ ## READ_SIZE(void)	\
	{								\
		asm volatile ("						\
		.pushsection .jumptables,\"\",@progbits;		\
	jt0_%=:								\
		.quad ret0_%=;						\
		.quad ret1_%=;						\
		.size jt0_%=, 16;					\
		.global jt0_%=;						\
		.popsection;						\
									\
		r0 = jt0_%= ll;						\
		r0 += 8;						\
		r0 = *(" #READ_SIZE " *)(r0 + 0);			\
		.8byte %[gotox_r0];					\
		ret0_%=:						\
		r0 = 0;							\
		exit;							\
		ret1_%=:						\
		r0 = 1;							\
		exit;							\
	"	:							\
		: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0)) \
		: __clobber_all);					\
	}

DEFINE_INVALID_SIZE_PROG(u32, __failure __msg("Invalid read of 4 bytes from insn_array"))
DEFINE_INVALID_SIZE_PROG(u16, __failure __msg("Invalid read of 2 bytes from insn_array"))
DEFINE_INVALID_SIZE_PROG(u8,  __failure __msg("Invalid read of 1 bytes from insn_array"))

SEC("socket")
__failure __msg("misaligned value access off 0+1+0 size 8")
__naked void jump_table_misaligned_access(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%=;						\
	.quad ret1_%=;						\
	.size jt0_%=, 16;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 += 1;						\
	r0 = *(u64 *)(r0 + 0);					\
	.8byte %[gotox_r0];					\
	ret0_%=:						\
	r0 = 0;							\
	exit;							\
	ret1_%=:						\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0))
	: __clobber_all);
}

SEC("socket")
__failure __msg("invalid access to map value, value_size=16 off=24 size=8")
__naked void jump_table_invalid_mem_acceess_pos(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%=;						\
	.quad ret1_%=;						\
	.size jt0_%=, 16;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 += 24;						\
	r0 = *(u64 *)(r0 + 0);					\
	.8byte %[gotox_r0];					\
	ret0_%=:						\
	r0 = 0;							\
	exit;							\
	ret1_%=:						\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0))
	: __clobber_all);
}

SEC("socket")
__failure __msg("invalid access to map value, value_size=16 off=-24 size=8")
__naked void jump_table_invalid_mem_acceess_neg(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%=;						\
	.quad ret1_%=;						\
	.size jt0_%=, 16;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 -= 24;						\
	r0 = *(u64 *)(r0 + 0);					\
	.8byte %[gotox_r0];					\
	ret0_%=:						\
	r0 = 0;							\
	exit;							\
	ret1_%=:						\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0))
	: __clobber_all);
}

SEC("socket")
__success __retval(1)
__naked void jump_table_add_sub_ok(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%=;						\
	.quad ret1_%=;						\
	.size jt0_%=, 16;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 -= 24;						\
	r0 += 32;						\
	r0 = *(u64 *)(r0 + 0);					\
	.8byte %[gotox_r0];					\
	ret0_%=:						\
	r0 = 0;							\
	exit;							\
	ret1_%=:						\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0))
	: __clobber_all);
}

SEC("socket")
__failure __msg("writes into insn_array not allowed")
__naked void jump_table_no_writes(void)
{
	asm volatile ("						\
	.pushsection .jumptables,\"\",@progbits;		\
jt0_%=:								\
	.quad ret0_%=;						\
	.quad ret1_%=;						\
	.size jt0_%=, 16;					\
	.global jt0_%=;						\
	.popsection;						\
								\
	r0 = jt0_%= ll;						\
	r0 += 8;						\
	r1 = 0xbeef;						\
	*(u64 *)(r0 + 0) = r1;					\
	.8byte %[gotox_r0];					\
	ret0_%=:						\
	r0 = 0;							\
	exit;							\
	ret1_%=:						\
	r0 = 1;							\
	exit;							\
"	:							\
	: __imm_insn(gotox_r0, BPF_RAW_INSN(BPF_JMP | BPF_JA | BPF_X, BPF_REG_0, 0, 0 , 0))
	: __clobber_all);
}

#endif /* __TARGET_ARCH_x86 */

char _license[] SEC("license") = "GPL";
