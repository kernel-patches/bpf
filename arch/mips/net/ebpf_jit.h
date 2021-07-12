/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Just-In-Time compiler for eBPF filters on MIPS32/MIPS64
 * Copyright (c) 2021 Tony Ambardar <Tony.Ambardar@gmail.com>
 *
 * Based on code from:
 *
 * Copyright (c) 2017 Cavium, Inc.
 * Author: David Daney <david.daney@cavium.com>
 *
 * Copyright (c) 2014 Imagination Technologies Ltd.
 * Author: Markos Chandras <markos.chandras@imgtec.com>
 */

#ifndef _EBPF_JIT_H
#define _EBPF_JIT_H

#include <linux/filter.h>
#include <linux/bpf.h>
#include <asm/byteorder.h>
#include <asm/uasm.h>

/* Registers used by JIT:	  (MIPS32)	(MIPS64) */
#define MIPS_R_ZERO	0
#define MIPS_R_AT	1
#define MIPS_R_V0	2	/* BPF_R0	BPF_R0 */
#define MIPS_R_V1	3	/* BPF_R0	BPF_TCC */
#define MIPS_R_A0	4	/* BPF_R1	BPF_R1 */
#define MIPS_R_A1	5	/* BPF_R1	BPF_R2 */
#define MIPS_R_A2	6	/* BPF_R2	BPF_R3 */
#define MIPS_R_A3	7	/* BPF_R2	BPF_R4 */
/* MIPS64 swaps T0-T3 regs for extra args A4-A7. */
#ifdef CONFIG_64BIT
#  define MIPS_R_A4	8	/* (n/a)	BPF_R5 */
#else /* CONFIG_32BIT */
#  define MIPS_R_T0	8	/* BPF_R3	(n/a)  */
#  define MIPS_R_T1	9	/* BPF_R3	(n/a)  */
#  define MIPS_R_T2	10	/* BPF_R4	(n/a)  */
#  define MIPS_R_T3	11	/* BPF_R4	(n/a)  */
#endif
#define MIPS_R_T4	12	/* BPF_R5	BPF_AX */
#define MIPS_R_T5	13	/* BPF_R5	(free) */
#define MIPS_R_T6	14	/* BPF_AX	(used) */
#define MIPS_R_T7	15	/* BPF_AX	(free) */
#define MIPS_R_S0	16	/* BPF_R6	BPF_R6 */
#define MIPS_R_S1	17	/* BPF_R6	BPF_R7 */
#define MIPS_R_S2	18	/* BPF_R7	BPF_R8 */
#define MIPS_R_S3	19	/* BPF_R7	BPF_R9 */
#define MIPS_R_S4	20	/* BPF_R8	BPF_TCC */
#define MIPS_R_S5	21	/* BPF_R8	(free) */
#define MIPS_R_S6	22	/* BPF_R9	(free) */
#define MIPS_R_S7	23	/* BPF_R9	(free) */
#define MIPS_R_T8	24	/* (used)	(used) */
#define MIPS_R_T9	25	/* (used)	(used) */
#define MIPS_R_SP	29
#define MIPS_R_S8	30	/* BPF_R10	BPF_R10 */
#define MIPS_R_RA	31

/* eBPF flags */
#define EBPF_SAVE_S0	BIT(0)
#define EBPF_SAVE_S1	BIT(1)
#define EBPF_SAVE_S2	BIT(2)
#define EBPF_SAVE_S3	BIT(3)
#define EBPF_SAVE_S4	BIT(4)
#define EBPF_SAVE_S5	BIT(5)
#define EBPF_SAVE_S6	BIT(6)
#define EBPF_SAVE_S7	BIT(7)
#define EBPF_SAVE_S8	BIT(8)
#define EBPF_SAVE_RA	BIT(9)
#define EBPF_SEEN_FP	BIT(10)
#define EBPF_SEEN_TC	BIT(11)
#define EBPF_TCC_IN_RUN	BIT(12)

/*
 * Word-size and endianness-aware helpers for building MIPS32 vs MIPS64
 * tables and selecting 32-bit subregisters from a register pair base.
 * Simplify use by emulating MIPS_R_SP and MIPS_R_ZERO as register pairs
 * and adding HI/LO word memory offsets.
 */
#ifdef CONFIG_64BIT
#  define HI(reg) (reg)
#  define LO(reg) (reg)
#  define OFFHI(mem) (mem)
#  define OFFLO(mem) (mem)
#else /* CONFIG_32BIT */
#  ifdef __BIG_ENDIAN
#    define HI(reg) ((reg) == MIPS_R_SP ? MIPS_R_ZERO : \
		     (reg) == MIPS_R_S8 ? MIPS_R_ZERO : \
		     (reg))
#    define LO(reg) ((reg) == MIPS_R_ZERO ? (reg) : \
		     (reg) == MIPS_R_SP ? (reg) : \
		     (reg) == MIPS_R_S8 ? (reg) : \
		     (reg) + 1)
#    define OFFHI(mem) (mem)
#    define OFFLO(mem) ((mem) + sizeof(long))
#  else	/* __LITTLE_ENDIAN */
#    define HI(reg) ((reg) == MIPS_R_ZERO ? (reg) : \
		     (reg) == MIPS_R_SP ? MIPS_R_ZERO : \
		     (reg) == MIPS_R_S8 ? MIPS_R_ZERO : \
		     (reg) + 1)
#    define LO(reg) (reg)
#    define OFFHI(mem) ((mem) + sizeof(long))
#    define OFFLO(mem) (mem)
#  endif
#endif

static inline bool is64bit(void)
{
	return IS_ENABLED(CONFIG_64BIT);
}

static inline bool isbigend(void)
{
	return IS_ENABLED(CONFIG_CPU_BIG_ENDIAN);
}

/*
 * For the mips64 ISA, we need to track the value range or type for
 * each JIT register.  The BPF machine requires zero extended 32-bit
 * values, but the mips64 ISA requires sign extended 32-bit values.
 * At each point in the BPF program we track the state of every
 * register so that we can zero extend or sign extend as the BPF
 * semantics require.
 */
enum reg_val_type {
	/* uninitialized */
	REG_UNKNOWN,
	/* not known to be 32-bit compatible. */
	REG_64BIT,
	/* 32-bit compatible, no truncation needed for 64-bit ops. */
	REG_64BIT_32BIT,
	/* 32-bit compatible, need truncation for 64-bit ops. */
	REG_32BIT,
	/* 32-bit no sign/zero extension needed. */
	REG_32BIT_POS
};

/**
 * struct jit_ctx - JIT context
 * @skf:		The sk_filter
 * @stack_size:		eBPF stack size
 * @idx:		Instruction index
 * @flags:		JIT flags
 * @offsets:		Instruction offsets
 * @target:		Memory location for the compiled filter
 * @reg_val_types	Packed enum reg_val_type for each register.
 */
struct jit_ctx {
	const struct bpf_prog *skf;
	int stack_size;
	int bpf_stack_off;
	u32 idx;
	u32 flags;
	u32 *offsets;
	u32 *target;
	u64 *reg_val_types;
	unsigned int long_b_conversion:1;
	unsigned int gen_b_offsets:1;
	unsigned int use_bbit_insns:1;
};

static inline void set_reg_val_type(u64 *rvt, int reg, enum reg_val_type type)
{
	*rvt &= ~(7ull << (reg * 3));
	*rvt |= ((u64)type << (reg * 3));
}

static inline enum reg_val_type get_reg_val_type(const struct jit_ctx *ctx,
					  int index, int reg)
{
	return (ctx->reg_val_types[index] >> (reg * 3)) & 7;
}

/* Simply emit the instruction if the JIT memory space has been allocated */
#define emit_instr_long(ctx, func64, func32, ...)		\
do {								\
	if ((ctx)->target != NULL) {				\
		u32 *p = &(ctx)->target[ctx->idx];		\
		if (IS_ENABLED(CONFIG_64BIT))			\
			uasm_i_##func64(&p, ##__VA_ARGS__);	\
		else						\
			uasm_i_##func32(&p, ##__VA_ARGS__);	\
	}							\
	(ctx)->idx++;						\
} while (0)

#define emit_instr(ctx, func, ...)				\
	emit_instr_long(ctx, func, func, ##__VA_ARGS__)

/*
 * High bit of offsets indicates if long branch conversion done at
 * this insn.
 */
#define OFFSETS_B_CONV	BIT(31)

static inline unsigned int j_target(struct jit_ctx *ctx, int target_idx)
{
	unsigned long target_va, base_va;
	unsigned int r;

	if (!ctx->target)
		return 0;

	base_va = (unsigned long)ctx->target;
	target_va = base_va + (ctx->offsets[target_idx] & ~OFFSETS_B_CONV);

	if ((base_va & ~0x0ffffffful) != (target_va & ~0x0ffffffful))
		return (unsigned int)-1;
	r = target_va & 0x0ffffffful;
	return r;
}

/* Compute the immediate value for PC-relative branches. */
static inline u32 b_imm(unsigned int tgt, struct jit_ctx *ctx)
{
	if (!ctx->gen_b_offsets)
		return 0;

	/*
	 * We want a pc-relative branch.  tgt is the instruction offset
	 * we want to jump to.

	 * Branch on MIPS:
	 * I: target_offset <- sign_extend(offset)
	 * I+1: PC += target_offset (delay slot)
	 *
	 * ctx->idx currently points to the branch instruction
	 * but the offset is added to the delay slot so we need
	 * to subtract 4.
	 */
	return (ctx->offsets[tgt] & ~OFFSETS_B_CONV) -
		(ctx->idx * 4) - 4;
}

static inline bool tail_call_present(struct jit_ctx *ctx)
{
	return ctx->flags & EBPF_SEEN_TC || ctx->skf->aux->tail_call_reachable;
}

static inline bool is_bad_offset(int b_off)
{
	return b_off > 0x1ffff || b_off < -0x20000;
}

/* Sign-extend dst register or HI 32-bit reg of pair. */
static inline void gen_sext_insn(int dst, struct jit_ctx *ctx)
{
	if (is64bit())
		emit_instr(ctx, sll, dst, dst, 0);
	else
		emit_instr(ctx, sra, HI(dst), LO(dst), 31);
}

/*
 * Zero-extend dst register or HI 32-bit reg of pair, if either forced
 * or the BPF verifier does not insert its own zext insns.
 */
static inline void gen_zext_insn(int dst, bool force, struct jit_ctx *ctx)
{
	if (!ctx->skf->aux->verifier_zext || force) {
		if (is64bit())
			emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);
		else
			emit_instr(ctx, and, HI(dst), MIPS_R_ZERO, MIPS_R_ZERO);
	}
}

enum reg_usage {
	REG_SRC_FP_OK,
	REG_SRC_NO_FP,
	REG_DST_FP_OK,
	REG_DST_NO_FP
};

extern int ebpf_to_mips_reg(struct jit_ctx *ctx,
			    const struct bpf_insn *insn,
			    enum reg_usage u);

extern void gen_imm_to_reg(const struct bpf_insn *insn, int reg,
			   struct jit_ctx *ctx);

extern void emit_const_to_reg(struct jit_ctx *ctx, int dst, unsigned long value);

extern void emit_bpf_call(struct jit_ctx *ctx, const struct bpf_insn *insn);

extern int emit_bpf_tail_call(struct jit_ctx *ctx, int this_idx);

extern void emit_caller_save(struct jit_ctx *ctx);

extern void emit_caller_restore(struct jit_ctx *ctx, int bpf_ret);

extern int build_one_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
		   int this_idx, int exit_idx);

#endif /* _EBPF_JIT_H */
