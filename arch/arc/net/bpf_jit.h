/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The interface that a back-end should provide to bpf_jit_core.c.
 *
 * Copyright (c) 2024 Synopsys Inc.
 * Author: Shahab Vahedi <shahab@synopsys.com>
 */

#ifndef _ARC_BPF_JIT_H
#define _ARC_BPF_JIT_H

#include <linux/bpf.h>
#include <linux/filter.h>

/* Print debug info and assert. */
//#define ARC_BPF_JIT_DEBUG

/* Determine the address type of the target. */
#ifdef CONFIG_ISA_ARCV2
#define ARC_ADDR u32
#endif

/*
 * For the translation of some BPF instructions, a temporary register
 * might be needed for some interim data.
 */
#define JIT_REG_TMP MAX_BPF_JIT_REG

/************* Globals that have effects on code generation ***********/
/*
 * If "emit" is true, the instructions are actually generated. Else, the
 * generation part will be skipped and only the length of instruction is
 * returned by the responsible functions.
 */
extern bool emit;

/* An indicator if zero-extend must be done for the 32-bit operations. */
extern bool zext_thyself;

/************** Functions that the back-end must provide **************/
/* Extension for 32-bit operations. */
extern inline u8 zext(u8 *buf, u8 rd);
/***** Moves *****/
extern u8 mov_r32(u8 *buf, u8 rd, u8 rs, u8 sign_ext);
extern u8 mov_r32_i32(u8 *buf, u8 reg, s32 imm);
extern u8 mov_r64(u8 *buf, u8 rd, u8 rs, u8 sign_ext);
extern u8 mov_r64_i32(u8 *buf, u8 reg, s32 imm);
extern u8 mov_r64_i64(u8 *buf, u8 reg, u32 lo, u32 hi);
/***** Loads and stores *****/
extern u8 load_r(u8 *buf, u8 rd, u8 rs, s16 off, u8 size, bool sign_ext);
extern u8 store_r(u8 *buf, u8 rd, u8 rs, s16 off, u8 size);
extern u8 store_i(u8 *buf, s32 imm, u8 rd, s16 off, u8 size);
/***** Addition *****/
extern u8 add_r32(u8 *buf, u8 rd, u8 rs);
extern u8 add_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 add_r64(u8 *buf, u8 rd, u8 rs);
extern u8 add_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Subtraction *****/
extern u8 sub_r32(u8 *buf, u8 rd, u8 rs);
extern u8 sub_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 sub_r64(u8 *buf, u8 rd, u8 rs);
extern u8 sub_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Multiplication *****/
extern u8 mul_r32(u8 *buf, u8 rd, u8 rs);
extern u8 mul_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 mul_r64(u8 *buf, u8 rd, u8 rs);
extern u8 mul_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Division *****/
extern u8 div_r32(u8 *buf, u8 rd, u8 rs, bool sign_ext);
extern u8 div_r32_i32(u8 *buf, u8 rd, s32 imm, bool sign_ext);
/***** Remainder *****/
extern u8 mod_r32(u8 *buf, u8 rd, u8 rs, bool sign_ext);
extern u8 mod_r32_i32(u8 *buf, u8 rd, s32 imm, bool sign_ext);
/***** Bitwise AND *****/
extern u8 and_r32(u8 *buf, u8 rd, u8 rs);
extern u8 and_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 and_r64(u8 *buf, u8 rd, u8 rs);
extern u8 and_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise OR *****/
extern u8 or_r32(u8 *buf, u8 rd, u8 rs);
extern u8 or_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 or_r64(u8 *buf, u8 rd, u8 rs);
extern u8 or_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise XOR *****/
extern u8 xor_r32(u8 *buf, u8 rd, u8 rs);
extern u8 xor_r32_i32(u8 *buf, u8 rd, s32 imm);
extern u8 xor_r64(u8 *buf, u8 rd, u8 rs);
extern u8 xor_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise Negate *****/
extern u8 neg_r32(u8 *buf, u8 r);
extern u8 neg_r64(u8 *buf, u8 r);
/***** Bitwise left shift *****/
extern u8 lsh_r32(u8 *buf, u8 rd, u8 rs);
extern u8 lsh_r32_i32(u8 *buf, u8 rd, u8 imm);
extern u8 lsh_r64(u8 *buf, u8 rd, u8 rs);
extern u8 lsh_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise right shift (logical) *****/
extern u8 rsh_r32(u8 *buf, u8 rd, u8 rs);
extern u8 rsh_r32_i32(u8 *buf, u8 rd, u8 imm);
extern u8 rsh_r64(u8 *buf, u8 rd, u8 rs);
extern u8 rsh_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Bitwise right shift (arithmetic) *****/
extern u8 arsh_r32(u8 *buf, u8 rd, u8 rs);
extern u8 arsh_r32_i32(u8 *buf, u8 rd, u8 imm);
extern u8 arsh_r64(u8 *buf, u8 rd, u8 rs);
extern u8 arsh_r64_i32(u8 *buf, u8 rd, s32 imm);
/***** Frame related *****/
extern u32 mask_for_used_regs(u8 bpf_reg, bool is_call);
extern u8 arc_prologue(u8 *buf, u32 usage, u16 frame_size);
extern u8 arc_epilogue(u8 *buf, u32 usage, u16 frame_size);
/***** Jumps *****/
/*
 * Different sorts of conditions (ARC enum as opposed to BPF_*).
 *
 * Do not change the order of enums here. ARC_CC_SLE+1 is used
 * to determine the number of JCCs.
 */
enum ARC_CC {
	ARC_CC_UGT = 0,		/* unsigned >  */
	ARC_CC_UGE,		/* unsigned >= */
	ARC_CC_ULT,		/* unsigned <  */
	ARC_CC_ULE,		/* unsigned <= */
	ARC_CC_SGT,		/*   signed >  */
	ARC_CC_SGE,		/*   signed >= */
	ARC_CC_SLT,		/*   signed <  */
	ARC_CC_SLE,		/*   signed <= */
	ARC_CC_AL,		/* always      */
	ARC_CC_EQ,		/*          == */
	ARC_CC_NE,		/*          != */
	ARC_CC_SET,		/* test        */
	ARC_CC_LAST
};
/*
 * A few notes:
 *
 * - check_jmp_*() are prerequisites before calling the gen_jmp_*().
 *   They return "true" if the jump is possible and "false" otherwise.
 *
 * - The notion of "*_off" is to emphasize that these parameters are
 *   merely offsets in the JIT stream and not absolute addresses. One
 *   can look at them as addresses if the JIT code would start from
 *   address 0x0000_0000. Nonetheless, since the buffer address for the
 *   JIT is on a word-aligned address, this works and actually makes
 *   things simpler (offsets are in the range of u32 which is more than
 *   enough).
 */
extern bool check_jmp_32(u32 curr_off, u32 targ_off, u8 cond);
extern bool check_jmp_64(u32 curr_off, u32 targ_off, u8 cond);
extern u8 gen_jmp_32(u8 *buf, u8 rd, u8 rs, u8 cond, u32 c_off, u32 t_off);
extern u8 gen_jmp_64(u8 *buf, u8 rd, u8 rs, u8 cond, u32 c_off, u32 t_off);
/***** Miscellaneous *****/
extern u8 gen_func_call(u8 *buf, ARC_ADDR func_addr, bool external_func);
extern u8 arc_to_bpf_return(u8 *buf);
/*
 * Perform byte swaps on "rd" based on the "size". If "force" is
 * set to "true", do it unconditionally. Otherwise, consider the
 * desired "endian"ness and the host endianness.
 */
extern u8 gen_swap(u8 *buf, u8 rd, u8 size, u8 endian, bool force);

#endif /* _ARC_BPF_JIT_H */
