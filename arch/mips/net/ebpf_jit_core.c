// SPDX-License-Identifier: GPL-2.0-only
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

#include <linux/errno.h>
#include <linux/filter.h>
#include <asm/cacheflush.h>
#include <asm/cpu-features.h>
#include <asm/uasm.h>

#include "ebpf_jit.h"

/*
 * Extra JIT registers dedicated to holding TCC during runtime or saving
 * across calls.
 */
enum {
	JIT_RUN_TCC = MAX_BPF_JIT_REG,
	JIT_SAV_TCC
};
/* Temporary register for passing TCC if nothing dedicated. */
#define TEMP_PASS_TCC MIPS_R_T8

#ifdef CONFIG_64BIT
#  define M(expr32, expr64) (expr64)
#else
#  define M(expr32, expr64) (expr32)
#endif
static const struct {
	/* Register or pair base */
	int reg;
	/* Register flags */
	u32 flags;
	/* Usage table:   (MIPS32)			 (MIPS64) */
} bpf2mips[] = {
	/* Return value from in-kernel function, and exit value from eBPF. */
	[BPF_REG_0] =  {M(MIPS_R_V0,			MIPS_R_V0)},
	/* Arguments from eBPF program to in-kernel/BPF functions. */
	[BPF_REG_1] =  {M(MIPS_R_A0,			MIPS_R_A0)},
	[BPF_REG_2] =  {M(MIPS_R_A2,			MIPS_R_A1)},
	[BPF_REG_3] =  {M(MIPS_R_T0,			MIPS_R_A2)},
	[BPF_REG_4] =  {M(MIPS_R_T2,			MIPS_R_A3)},
	[BPF_REG_5] =  {M(MIPS_R_T4,			MIPS_R_A4)},
	/* Callee-saved registers preserved by in-kernel/BPF functions. */
	[BPF_REG_6] =  {M(MIPS_R_S0,			MIPS_R_S0),
			M(EBPF_SAVE_S0|EBPF_SAVE_S1,	EBPF_SAVE_S0)},
	[BPF_REG_7] =  {M(MIPS_R_S2,			MIPS_R_S1),
			M(EBPF_SAVE_S2|EBPF_SAVE_S3,	EBPF_SAVE_S1)},
	[BPF_REG_8] =  {M(MIPS_R_S4,			MIPS_R_S2),
			M(EBPF_SAVE_S4|EBPF_SAVE_S5,	EBPF_SAVE_S2)},
	[BPF_REG_9] =  {M(MIPS_R_S6,			MIPS_R_S3),
			M(EBPF_SAVE_S6|EBPF_SAVE_S7,	EBPF_SAVE_S3)},
	[BPF_REG_10] = {M(MIPS_R_S8,			MIPS_R_S8),
			M(EBPF_SAVE_S8|EBPF_SEEN_FP,	EBPF_SAVE_S8|EBPF_SEEN_FP)},
	/* Internal register for rewriting insns during JIT blinding. */
	[BPF_REG_AX] = {M(MIPS_R_T6,			MIPS_R_T4)},
	/*
	 * Internal registers for TCC runtime holding and saving during
	 * calls. A zero save register indicates using scratch space on
	 * the stack for storage during calls. A zero hold register means
	 * no dedicated register holds TCC during runtime (but a temp reg
	 * still passes TCC to tailcall or bpf2bpf call).
	 */
	[JIT_RUN_TCC] =	{M(0,				MIPS_R_V1)},
	[JIT_SAV_TCC] =	{M(0,				MIPS_R_S4),
			 M(0,				EBPF_SAVE_S4)}
};
#undef M

/*
 * For eBPF, the register mapping naturally falls out of the
 * requirements of eBPF and MIPS N64/O32 ABIs.  We also maintain
 * a separate frame pointer, setting BPF_REG_10 relative to $sp.
 */
int ebpf_to_mips_reg(struct jit_ctx *ctx,
		     const struct bpf_insn *insn,
		     enum reg_usage u)
{
	int ebpf_reg = (u == REG_SRC_FP_OK || u == REG_SRC_NO_FP) ?
		insn->src_reg : insn->dst_reg;

	switch (ebpf_reg) {
	case BPF_REG_0:
	case BPF_REG_1:
	case BPF_REG_2:
	case BPF_REG_3:
	case BPF_REG_4:
	case BPF_REG_5:
	case BPF_REG_6:
	case BPF_REG_7:
	case BPF_REG_8:
	case BPF_REG_9:
	case BPF_REG_AX:
		ctx->flags |= bpf2mips[ebpf_reg].flags;
		return bpf2mips[ebpf_reg].reg;
	case BPF_REG_10:
		if (u == REG_DST_NO_FP || u == REG_SRC_NO_FP)
			goto bad_reg;
		ctx->flags |= bpf2mips[ebpf_reg].flags;
		return bpf2mips[ebpf_reg].reg;
	default:
bad_reg:
		WARN(1, "Illegal bpf reg: %d\n", ebpf_reg);
		return -EINVAL;
	}
}

void gen_imm_to_reg(const struct bpf_insn *insn, int reg,
			   struct jit_ctx *ctx)
{
	if (insn->imm >= S16_MIN && insn->imm <= S16_MAX) {
		emit_instr(ctx, addiu, reg, MIPS_R_ZERO, insn->imm);
	} else {
		int lower = (s16)(insn->imm & 0xffff);
		int upper = insn->imm - lower;

		emit_instr(ctx, lui, reg, upper >> 16);
		/* lui already clears lower halfword */
		if (lower)
			emit_instr(ctx, addiu, reg, reg, lower);
	}
}

void emit_const_to_reg(struct jit_ctx *ctx, int dst, unsigned long value)
{
	if (value >= S16_MIN || value <= S16_MAX) {
		emit_instr_long(ctx, daddiu, addiu, dst, MIPS_R_ZERO, (int)value);
	} else if (value >= S32_MIN ||
		   (value <= S32_MAX && value > U16_MAX)) {
		emit_instr(ctx, lui, dst, (s32)(s16)(value >> 16));
		emit_instr(ctx, ori, dst, dst, (unsigned int)(value & 0xffff));
	} else {
		int i;
		bool seen_part = false;
		int needed_shift = 0;

		for (i = 0; i < 4; i++) {
			u64 part = (value >> (16 * (3 - i))) & 0xffff;

			if (seen_part && needed_shift > 0 && (part || i == 3)) {
				emit_instr(ctx, dsll_safe, dst, dst, needed_shift);
				needed_shift = 0;
			}
			if (part) {
				if (i == 0 || (!seen_part && i < 3 && part < 0x8000)) {
					emit_instr(ctx, lui, dst, (s32)(s16)part);
					needed_shift = -16;
				} else {
					emit_instr(ctx, ori, dst,
						   seen_part ? dst : MIPS_R_ZERO,
						   (unsigned int)part);
				}
				seen_part = true;
			}
			if (seen_part)
				needed_shift += 16;
		}
	}
}

#define RVT_VISITED_MASK 0xc000000000000000ull
#define RVT_FALL_THROUGH 0x4000000000000000ull
#define RVT_BRANCH_TAKEN 0x8000000000000000ull
#define RVT_DONE (RVT_FALL_THROUGH | RVT_BRANCH_TAKEN)

/* return the last idx processed, or negative for error */
static int reg_val_propagate_range(struct jit_ctx *ctx, u64 initial_rvt,
				   int start_idx, bool follow_taken)
{
	const struct bpf_prog *prog = ctx->skf;
	const struct bpf_insn *insn;
	u64 exit_rvt = initial_rvt;
	u64 *rvt = ctx->reg_val_types;
	int idx;
	int reg;

	for (idx = start_idx; idx < prog->len; idx++) {
		rvt[idx] = (rvt[idx] & RVT_VISITED_MASK) | exit_rvt;
		insn = prog->insnsi + idx;
		switch (BPF_CLASS(insn->code)) {
		case BPF_ALU:
			switch (BPF_OP(insn->code)) {
			case BPF_ADD:
			case BPF_SUB:
			case BPF_MUL:
			case BPF_DIV:
			case BPF_OR:
			case BPF_AND:
			case BPF_LSH:
			case BPF_RSH:
			case BPF_ARSH:
			case BPF_NEG:
			case BPF_MOD:
			case BPF_XOR:
				set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT);
				break;
			case BPF_MOV:
				if (BPF_SRC(insn->code)) {
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT);
				} else {
					/* IMM to REG move*/
					if (insn->imm >= 0)
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT_POS);
					else
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT);
				}
				break;
			case BPF_END:
				if (insn->imm == 64)
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT);
				else if (insn->imm == 32)
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT);
				else /* insn->imm == 16 */
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT_POS);
				break;
			}
			rvt[idx] |= RVT_DONE;
			break;
		case BPF_ALU64:
			switch (BPF_OP(insn->code)) {
			case BPF_MOV:
				if (BPF_SRC(insn->code)) {
					/* REG to REG move*/
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT);
				} else {
					/* IMM to REG move*/
					if (insn->imm >= 0)
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT_POS);
					else
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT_32BIT);
				}
				break;
			default:
				set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT);
			}
			rvt[idx] |= RVT_DONE;
			break;
		case BPF_LD:
			switch (BPF_SIZE(insn->code)) {
			case BPF_DW:
				if (BPF_MODE(insn->code) == BPF_IMM) {
					s64 val;

					val = (s64)((u32)insn->imm | ((u64)(insn + 1)->imm << 32));
					if (val > 0 && val <= S32_MAX)
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT_POS);
					else if (val >= S32_MIN && val <= S32_MAX)
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT_32BIT);
					else
						set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT);
					rvt[idx] |= RVT_DONE;
					idx++;
				} else {
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT);
				}
				break;
			case BPF_B:
			case BPF_H:
				set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT_POS);
				break;
			case BPF_W:
				if (BPF_MODE(insn->code) == BPF_IMM)
					set_reg_val_type(&exit_rvt, insn->dst_reg,
							 insn->imm >= 0 ? REG_32BIT_POS : REG_32BIT);
				else
					set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT);
				break;
			}
			rvt[idx] |= RVT_DONE;
			break;
		case BPF_LDX:
			switch (BPF_SIZE(insn->code)) {
			case BPF_DW:
				set_reg_val_type(&exit_rvt, insn->dst_reg, REG_64BIT);
				break;
			case BPF_B:
			case BPF_H:
				set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT_POS);
				break;
			case BPF_W:
				set_reg_val_type(&exit_rvt, insn->dst_reg, REG_32BIT);
				break;
			}
			rvt[idx] |= RVT_DONE;
			break;
		case BPF_JMP:
		case BPF_JMP32:
			switch (BPF_OP(insn->code)) {
			case BPF_EXIT:
				rvt[idx] = RVT_DONE | exit_rvt;
				rvt[prog->len] = exit_rvt;
				return idx;
			case BPF_JA:
			{
				int tgt = idx + 1 + insn->off;
				bool visited = (rvt[tgt] & RVT_FALL_THROUGH);

				rvt[idx] |= RVT_DONE;
				/*
				 * Verifier dead code patching can use
				 * infinite-loop traps, causing hangs and
				 * RCU stalls here. Treat traps as nops
				 * if detected and fall through.
				 */
				if (insn->off == -1)
					break;
				/*
				 * Bounded loops cause the same issues in
				 * fallthrough mode; follow only if jump
				 * target is unvisited to mitigate.
				 */
				if (insn->off < 0 && !follow_taken && visited)
					break;
				idx += insn->off;
				break;
			}
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JLT:
			case BPF_JLE:
			case BPF_JSET:
			case BPF_JNE:
			case BPF_JSGT:
			case BPF_JSGE:
			case BPF_JSLT:
			case BPF_JSLE:
				if (follow_taken) {
					rvt[idx] |= RVT_BRANCH_TAKEN;
					idx += insn->off;
					follow_taken = false;
				} else {
					rvt[idx] |= RVT_FALL_THROUGH;
				}
				break;
			case BPF_CALL:
				set_reg_val_type(&exit_rvt, BPF_REG_0, REG_64BIT);
				/* Upon call return, argument registers are clobbered. */
				for (reg = BPF_REG_0; reg <= BPF_REG_5; reg++)
					set_reg_val_type(&exit_rvt, reg, REG_64BIT);

				rvt[idx] |= RVT_DONE;
				break;
			case BPF_TAIL_CALL:
				rvt[idx] |= RVT_DONE;
				break;
			default:
				WARN(1, "Unhandled BPF_JMP case.\n");
				rvt[idx] |= RVT_DONE;
				break;
			}
			break;
		default:
			rvt[idx] |= RVT_DONE;
			break;
		}
	}
	return idx;
}

/*
 * Track the value range (i.e. 32-bit vs. 64-bit) of each register at
 * each eBPF insn.  This allows unneeded sign and zero extension
 * operations to be omitted.
 *
 * Doesn't handle yet confluence of control paths with conflicting
 * ranges, but it is good enough for most sane code.
 */
static int reg_val_propagate(struct jit_ctx *ctx)
{
	const struct bpf_prog *prog = ctx->skf;
	u64 exit_rvt;
	int reg;
	int i;

	/*
	 * 11 registers * 3 bits/reg leaves top bits free for other
	 * uses.  Bit-62..63 used to see if we have visited an insn.
	 */
	exit_rvt = 0;

	/* Upon entry, argument registers are 64-bit. */
	for (reg = BPF_REG_1; reg <= BPF_REG_5; reg++)
		set_reg_val_type(&exit_rvt, reg, REG_64BIT);

	/*
	 * First follow all conditional branches on the fall-through
	 * edge of control flow..
	 */
	reg_val_propagate_range(ctx, exit_rvt, 0, false);
restart_search:
	/*
	 * Then repeatedly find the first conditional branch where
	 * both edges of control flow have not been taken, and follow
	 * the branch taken edge.  We will end up restarting the
	 * search once per conditional branch insn.
	 */
	for (i = 0; i < prog->len; i++) {
		u64 rvt = ctx->reg_val_types[i];

		if ((rvt & RVT_VISITED_MASK) == RVT_DONE ||
		    (rvt & RVT_VISITED_MASK) == 0)
			continue;
		if ((rvt & RVT_VISITED_MASK) == RVT_FALL_THROUGH) {
			reg_val_propagate_range(ctx, rvt & ~RVT_VISITED_MASK, i, true);
		} else { /* RVT_BRANCH_TAKEN */
			WARN(1, "Unexpected RVT_BRANCH_TAKEN case.\n");
			reg_val_propagate_range(ctx, rvt & ~RVT_VISITED_MASK, i, false);
		}
		goto restart_search;
	}
	/*
	 * Eventually all conditional branches have been followed on
	 * both branches and we are done.  Any insn that has not been
	 * visited at this point is dead.
	 */

	return 0;
}

static void jit_fill_hole(void *area, unsigned int size)
{
	u32 *p;

	/* We are guaranteed to have aligned memory. */
	for (p = area; size >= sizeof(u32); size -= sizeof(u32))
		uasm_i_break(&p, BRK_BUG); /* Increments p */
}

/* Stack region alignment under N64 and O32 ABIs */
#define STACK_ALIGN (2 * sizeof(long))

/*
 * eBPF stack frame will be something like:
 *
 *  Entry $sp ------>   +--------------------------------+
 *                      |   $ra  (optional)              |
 *                      +--------------------------------+
 *                      |   $s8  (optional)              |
 *                      +--------------------------------+
 *                      |   $s7  (optional)              |
 *                      +--------------------------------+
 *                      |   $s6  (optional)              |
 *                      +--------------------------------+
 *                      |   $s5  (optional)              |
 *                      +--------------------------------+
 *                      |   $s4  (optional)              |
 *                      +--------------------------------+
 *                      |   $s3  (optional)              |
 *                      +--------------------------------+
 *                      |   $s2  (optional)              |
 *                      +--------------------------------+
 *                      |   $s1  (optional)              |
 *                      +--------------------------------+
 *                      |   $s0  (optional)              |
 *                      +--------------------------------+
 *                      |   tmp-storage  (optional)      |
 * $sp + bpf_stack_off->+--------------------------------+ <--BPF_REG_10
 *                      |   BPF_REG_10 relative storage  |
 *                      |    MAX_BPF_STACK (optional)    |
 *                      |      .                         |
 *                      |      .                         |
 *                      |      .                         |
 *        $sp ------>   +--------------------------------+
 *
 * If BPF_REG_10 is never referenced, then the MAX_BPF_STACK sized
 * area is not allocated.
 */
static int build_int_prologue(struct jit_ctx *ctx)
{
	int tcc_run = bpf2mips[JIT_RUN_TCC].reg ?
		      bpf2mips[JIT_RUN_TCC].reg :
		      TEMP_PASS_TCC;
	int tcc_sav = bpf2mips[JIT_SAV_TCC].reg;
	const struct bpf_prog *prog = ctx->skf;
	int r10 = bpf2mips[BPF_REG_10].reg;
	int r1 = bpf2mips[BPF_REG_1].reg;
	int stack_adjust = 0;
	int store_offset;
	int locals_size;

	if (ctx->flags & EBPF_SAVE_RA)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S8)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S7)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S6)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S5)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S4)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S3)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S2)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S1)
		stack_adjust += sizeof(long);
	if (ctx->flags & EBPF_SAVE_S0)
		stack_adjust += sizeof(long);
	if (tail_call_present(ctx) &&
	    !(ctx->flags & EBPF_TCC_IN_RUN) && !tcc_sav)
		/* Allocate scratch space for holding TCC if needed. */
		stack_adjust += sizeof(long);

	stack_adjust = ALIGN(stack_adjust, STACK_ALIGN);

	locals_size = (ctx->flags & EBPF_SEEN_FP) ? prog->aux->stack_depth : 0;
	locals_size = ALIGN(locals_size, STACK_ALIGN);

	stack_adjust += locals_size;

	ctx->stack_size = stack_adjust;
	ctx->bpf_stack_off = locals_size;

	/*
	 * First instruction initializes the tail call count (TCC) if
	 * called from kernel or via BPF tail call. A BPF tail-caller
	 * will skip this instruction and pass the TCC via register.
	 * As a BPF2BPF subprog, we are called directly and must avoid
	 * resetting the TCC.
	 */
	if (!ctx->skf->is_func)
		emit_instr(ctx, addiu, tcc_run, MIPS_R_ZERO, MAX_TAIL_CALL_CNT);

	/*
	 * If called from kernel under O32 ABI we must set up BPF R1 context,
	 * since BPF R1 is an endian-order regster pair ($a0:$a1 or $a1:$a0)
	 * but context is always passed in $a0 as 32-bit pointer. Entry from
	 * a tail-call looks just like a kernel call, which means the caller
	 * must set up R1 context according to the kernel call ABI. If we are
	 * a BPF2BPF call then all registers are already correctly set up.
	 */
	if (!is64bit() && !ctx->skf->is_func) {
		if (isbigend())
			emit_instr(ctx, move, LO(r1), MIPS_R_A0);
		/* Sanitize upper 32-bit reg */
		gen_zext_insn(r1, true, ctx);
	}

	if (stack_adjust)
		emit_instr_long(ctx, daddiu, addiu,
					MIPS_R_SP, MIPS_R_SP, -stack_adjust);
	else
		return 0;

	store_offset = stack_adjust - sizeof(long);

	if (ctx->flags & EBPF_SAVE_RA) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_RA, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S8) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S8, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S7) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S7, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S6) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S6, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S5) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S5, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S4) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S4, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S3) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S3, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S2) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S2, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S1) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S1, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S0) {
		emit_instr_long(ctx, sd, sw,
					MIPS_R_S0, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}

	/* Store TCC in backup register or stack scratch space if indicated. */
	if (tail_call_present(ctx) && !(ctx->flags & EBPF_TCC_IN_RUN)) {
		if (tcc_sav)
			emit_instr(ctx, move, tcc_sav, tcc_run);
		else
			emit_instr_long(ctx, sd, sw,
					tcc_run, ctx->bpf_stack_off, MIPS_R_SP);
	}

	/* Prepare BPF FP as single-reg ptr, emulate upper 32-bits as needed.*/
	if (ctx->flags & EBPF_SEEN_FP)
		emit_instr_long(ctx, daddiu, addiu, r10,
						MIPS_R_SP, ctx->bpf_stack_off);

	return 0;
}

static int build_int_body(struct jit_ctx *ctx)
{
	const struct bpf_prog *prog = ctx->skf;
	const struct bpf_insn *insn;
	int i, r;

	for (i = 0; i < prog->len; ) {
		insn = prog->insnsi + i;
		if ((ctx->reg_val_types[i] & RVT_VISITED_MASK) == 0) {
			/* dead instruction, don't emit it. */
			i++;
			continue;
		}

		if (ctx->target == NULL)
			ctx->offsets[i] = (ctx->offsets[i] & OFFSETS_B_CONV) | (ctx->idx * 4);

		r = build_one_insn(insn, ctx, i, prog->len);
		if (r < 0)
			return r;
		i += r;
	}
	/* epilogue offset */
	if (ctx->target == NULL)
		ctx->offsets[i] = ctx->idx * 4;

	/*
	 * All exits have an offset of the epilogue, some offsets may
	 * not have been set due to banch-around threading, so set
	 * them now.
	 */
	if (ctx->target == NULL)
		for (i = 0; i < prog->len; i++) {
			insn = prog->insnsi + i;
			if (insn->code == (BPF_JMP | BPF_EXIT))
				ctx->offsets[i] = ctx->idx * 4;
		}
	return 0;
}

static int build_int_epilogue(struct jit_ctx *ctx, int dest_reg)
{
	const struct bpf_prog *prog = ctx->skf;
	int stack_adjust = ctx->stack_size;
	int store_offset = stack_adjust - sizeof(long);
	int r1 = bpf2mips[BPF_REG_1].reg;
	int r0 = bpf2mips[BPF_REG_0].reg;
	enum reg_val_type td;

	/*
	 * Returns from BPF2BPF calls consistently use the BPF 64-bit ABI
	 * i.e. register usage and mapping between JIT and OS is unchanged.
	 * Returning to the kernel must follow the N64 or O32 ABI, and for
	 * the latter requires fixup of BPF R0 to MIPS V0 register mapping.
	 *
	 * Tails calls must ensure the passed R1 context is consistent with
	 * the kernel ABI, and requires fixup on MIPS32 bigendian systems.
	 */
	if (dest_reg == MIPS_R_RA && !ctx->skf->is_func) { /* kernel return */
		if (is64bit()) {
			/* Don't let zero extended value escape. */
			td = get_reg_val_type(ctx, prog->len, BPF_REG_0);
			if (td == REG_64BIT)
				gen_sext_insn(r0, ctx);
		} else if (isbigend()) { /* and 32-bit */
			/*
			 * O32 ABI specifies 32-bit return value always
			 * placed in MIPS_R_V0 regardless of the native
			 * endianness. This would be in the wrong position
			 * in a BPF R0 reg pair on big-endian systems, so
			 * we must relocate.
			 */
			emit_instr(ctx, move, MIPS_R_V0, LO(r0));
		}
	} else if (dest_reg == MIPS_R_T9) { /* tail call */
		if (!is64bit() && isbigend())
			emit_instr(ctx, move, MIPS_R_A0, LO(r1));
	}


	if (ctx->flags & EBPF_SAVE_RA) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_RA, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S8) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S8, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S7) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S7, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S6) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S6, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S5) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S5, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S4) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S4, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S3) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S3, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S2) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S2, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S1) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S1, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	if (ctx->flags & EBPF_SAVE_S0) {
		emit_instr_long(ctx, ld, lw,
					MIPS_R_S0, store_offset, MIPS_R_SP);
		store_offset -= sizeof(long);
	}
	emit_instr(ctx, jr, dest_reg);

	/* Delay slot */
	if (stack_adjust)
		emit_instr_long(ctx, daddiu, addiu,
					MIPS_R_SP, MIPS_R_SP, stack_adjust);
	else
		emit_instr(ctx, nop);

	return 0;
}

/*
 * Push BPF regs R3-R5 to the stack, skipping BPF regs R1-R2 which are
 * passed via MIPS register pairs in $a0-$a3. Register order within pairs
 * and the memory storage order are identical i.e. endian native.
 */
static void emit_push_args(struct jit_ctx *ctx)
{
	int store_offset = 2 * sizeof(u64); /* Skip R1-R2 in $a0-$a3 */
	int bpf, reg;

	for (bpf = BPF_REG_3; bpf <= BPF_REG_5; bpf++) {
		reg = bpf2mips[bpf].reg;

		emit_instr(ctx, sw, LO(reg), OFFLO(store_offset), MIPS_R_SP);
		emit_instr(ctx, sw, HI(reg), OFFHI(store_offset), MIPS_R_SP);
		store_offset += sizeof(u64);
	}
}

/*
 * Common helper for BPF_CALL insn, handling TCC and ABI variations.
 * Kernel calls under O32 ABI require arguments passed on the stack,
 * while BPF2BPF calls need the TCC passed via register as expected
 * by the subprog's prologue.
 *
 * Under MIPS32 O32 ABI calling convention, u64 BPF regs R1-R2 are passed
 * via reg pairs in $a0-$a3, while BPF regs R3-R5 are passed via the stack.
 * Stack space is still reserved for $a0-$a3, and the whole area aligned.
 */
#define ARGS_SIZE (5 * sizeof(u64))

void emit_bpf_call(struct jit_ctx *ctx, const struct bpf_insn *insn)
{
	int stack_adjust = ALIGN(ARGS_SIZE, STACK_ALIGN);
	int tcc_run = bpf2mips[JIT_RUN_TCC].reg ?
		      bpf2mips[JIT_RUN_TCC].reg :
		      TEMP_PASS_TCC;
	int tcc_sav = bpf2mips[JIT_SAV_TCC].reg;
	long func_addr;

	ctx->flags |= EBPF_SAVE_RA;

	/* Ensure TCC passed into BPF subprog */
	if ((insn->src_reg == BPF_PSEUDO_CALL) &&
	    tail_call_present(ctx) && !(ctx->flags & EBPF_TCC_IN_RUN)) {
		/* Set TCC from reg or stack */
		if (tcc_sav)
			emit_instr(ctx, move, tcc_run, tcc_sav);
		else
			emit_instr_long(ctx, ld, lw, tcc_run,
						ctx->bpf_stack_off, MIPS_R_SP);
	}

	/* Push O32 stack args for kernel call */
	if (!is64bit() && (insn->src_reg != BPF_PSEUDO_CALL)) {
		emit_instr(ctx, addiu, MIPS_R_SP, MIPS_R_SP, -stack_adjust);
		emit_push_args(ctx);
	}

	func_addr = (long)__bpf_call_base + insn->imm;
	emit_const_to_reg(ctx, MIPS_R_T9, func_addr);
	emit_instr(ctx, jalr, MIPS_R_RA, MIPS_R_T9);
	/* Delay slot */
	emit_instr(ctx, nop);

	/* Restore stack */
	if (!is64bit() && (insn->src_reg != BPF_PSEUDO_CALL))
		emit_instr(ctx, addiu, MIPS_R_SP, MIPS_R_SP, stack_adjust);
}

/*
 * Tail call helper arguments passed via BPF ABI as u64 parameters. On
 * MIPS64 N64 ABI systems these are native regs, while on MIPS32 O32 ABI
 * systems these are reg pairs:
 *
 * R1 -> &ctx
 * R2 -> &array
 * R3 -> index
 */
int emit_bpf_tail_call(struct jit_ctx *ctx, int this_idx)
{
	int tcc_run = bpf2mips[JIT_RUN_TCC].reg ?
		      bpf2mips[JIT_RUN_TCC].reg :
		      TEMP_PASS_TCC;
	int tcc_sav = bpf2mips[JIT_SAV_TCC].reg;
	int r2 = bpf2mips[BPF_REG_2].reg;
	int r3 = bpf2mips[BPF_REG_3].reg;
	int off, b_off;
	int tcc;

	ctx->flags |= EBPF_SEEN_TC;
	/*
	 * if (index >= array->map.max_entries)
	 *     goto out;
	 */
	if (is64bit())
		/* Mask index as 32-bit */
		gen_zext_insn(r3, true, ctx);
	off = offsetof(struct bpf_array, map.max_entries);
	emit_instr_long(ctx, lwu, lw, MIPS_R_AT, off, LO(r2));
	emit_instr(ctx, sltu, MIPS_R_AT, MIPS_R_AT, LO(r3));
	b_off = b_imm(this_idx + 1, ctx);
	emit_instr(ctx, bnez, MIPS_R_AT, b_off);
	/*
	 * if (TCC-- < 0)
	 *     goto out;
	 */
	/* Delay slot */
	tcc = (ctx->flags & EBPF_TCC_IN_RUN) ? tcc_run : tcc_sav;
	/* Get TCC from reg or stack */
	if (tcc)
		emit_instr(ctx, move, MIPS_R_T8, tcc);
	else
		emit_instr_long(ctx, ld, lw, MIPS_R_T8,
						ctx->bpf_stack_off, MIPS_R_SP);
	b_off = b_imm(this_idx + 1, ctx);
	emit_instr(ctx, bltz, MIPS_R_T8, b_off);
	/*
	 * prog = array->ptrs[index];
	 * if (prog == NULL)
	 *     goto out;
	 */
	/* Delay slot */
	emit_instr_long(ctx, dsll, sll, MIPS_R_AT, LO(r3), ilog2(sizeof(long)));
	emit_instr_long(ctx, daddu, addu, MIPS_R_AT, MIPS_R_AT, LO(r2));
	off = offsetof(struct bpf_array, ptrs);
	emit_instr_long(ctx, ld, lw, MIPS_R_AT, off, MIPS_R_AT);
	b_off = b_imm(this_idx + 1, ctx);
	emit_instr(ctx, beqz, MIPS_R_AT, b_off);
	/* Delay slot */
	emit_instr(ctx, nop);

	/* goto *(prog->bpf_func + 4); */
	off = offsetof(struct bpf_prog, bpf_func);
	emit_instr_long(ctx, ld, lw, MIPS_R_T9, off, MIPS_R_AT);
	/* All systems are go... decrement and propagate TCC */
	emit_instr_long(ctx, daddiu, addiu, tcc_run, MIPS_R_T8, -1);
	/* Skip first instruction (TCC initialization) */
	emit_instr_long(ctx, daddiu, addiu, MIPS_R_T9, MIPS_R_T9, 4);
	return build_int_epilogue(ctx, MIPS_R_T9);
}

/*
 * Save and restore the BPF VM state across a direct kernel call. This
 * includes the caller-saved registers used for BPF_REG_0 .. BPF_REG_5
 * and BPF_REG_AX used by the verifier for blinding and other dark arts.
 * Restore avoids clobbering bpf_ret, which holds the call return value.
 * BPF_REG_6 .. BPF_REG_10 and TCC are already callee-saved or on stack.
 */
static const int bpf_caller_save[] = {
	BPF_REG_0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_AX,
};

#define CALLER_ENV_SIZE (ARRAY_SIZE(bpf_caller_save) * sizeof(u64))

void emit_caller_save(struct jit_ctx *ctx)
{
	int stack_adj = ALIGN(CALLER_ENV_SIZE, STACK_ALIGN);
	int i, bpf, reg, store_offset;

	emit_instr_long(ctx, daddiu, addiu, MIPS_R_SP, MIPS_R_SP, -stack_adj);

	for (i = 0; i < ARRAY_SIZE(bpf_caller_save); i++) {
		bpf = bpf_caller_save[i];
		reg = bpf2mips[bpf].reg;
		store_offset = i * sizeof(u64);

		if (is64bit()) {
			emit_instr(ctx, sd, reg, store_offset, MIPS_R_SP);
		} else {
			emit_instr(ctx, sw, LO(reg),
						OFFLO(store_offset), MIPS_R_SP);
			emit_instr(ctx, sw, HI(reg),
						OFFHI(store_offset), MIPS_R_SP);
		}
	}
}

void emit_caller_restore(struct jit_ctx *ctx, int bpf_ret)
{
	int stack_adj = ALIGN(CALLER_ENV_SIZE, STACK_ALIGN);
	int i, bpf, reg, store_offset;

	for (i = 0; i < ARRAY_SIZE(bpf_caller_save); i++) {
		bpf = bpf_caller_save[i];
		reg = bpf2mips[bpf].reg;
		store_offset = i * sizeof(u64);
		if (bpf == bpf_ret)
			continue;

		if (is64bit()) {
			emit_instr(ctx, ld, reg, store_offset, MIPS_R_SP);
		} else {
			emit_instr(ctx, lw, LO(reg),
						OFFLO(store_offset), MIPS_R_SP);
			emit_instr(ctx, lw, HI(reg),
						OFFHI(store_offset), MIPS_R_SP);
		}
	}

	emit_instr_long(ctx, daddiu, addiu, MIPS_R_SP, MIPS_R_SP, stack_adj);
}

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	struct bpf_prog *orig_prog = prog;
	bool tmp_blinded = false;
	struct bpf_prog *tmp;
	struct bpf_binary_header *header = NULL;
	struct jit_ctx ctx;
	unsigned int image_size;
	u8 *image_ptr;

	if (!prog->jit_requested)
		return prog;

	tmp = bpf_jit_blind_constants(prog);
	/* If blinding was requested and we failed during blinding,
	 * we must fall back to the interpreter.
	 */
	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	memset(&ctx, 0, sizeof(ctx));

	preempt_disable();
	switch (current_cpu_type()) {
	case CPU_CAVIUM_OCTEON:
	case CPU_CAVIUM_OCTEON_PLUS:
	case CPU_CAVIUM_OCTEON2:
	case CPU_CAVIUM_OCTEON3:
		ctx.use_bbit_insns = 1;
		break;
	default:
		ctx.use_bbit_insns = 0;
	}
	preempt_enable();

	ctx.offsets = kcalloc(prog->len + 1, sizeof(*ctx.offsets), GFP_KERNEL);
	if (ctx.offsets == NULL)
		goto out_err;

	ctx.reg_val_types = kcalloc(prog->len + 1, sizeof(*ctx.reg_val_types), GFP_KERNEL);
	if (ctx.reg_val_types == NULL)
		goto out_err;

	ctx.skf = prog;

	if (reg_val_propagate(&ctx))
		goto out_err;

	/*
	 * First pass discovers used resources and instruction offsets
	 * assuming short branches are used.
	 */
	if (build_int_body(&ctx))
		goto out_err;

	/*
	 * If no calls are made (EBPF_SAVE_RA), then tailcall count located
	 * in runtime reg if defined, else we backup to save reg or stack.
	 */
	if (tail_call_present(&ctx)) {
		if (ctx.flags & EBPF_SAVE_RA)
			ctx.flags |= bpf2mips[JIT_SAV_TCC].flags;
		else if (bpf2mips[JIT_RUN_TCC].reg)
			ctx.flags |= EBPF_TCC_IN_RUN;
	}

	/*
	 * Second pass generates offsets, if any branches are out of
	 * range a jump-around long sequence is generated, and we have
	 * to try again from the beginning to generate the new
	 * offsets.  This is done until no additional conversions are
	 * necessary.
	 */
	do {
		ctx.idx = 0;
		ctx.gen_b_offsets = 1;
		ctx.long_b_conversion = 0;
		if (build_int_prologue(&ctx))
			goto out_err;
		if (build_int_body(&ctx))
			goto out_err;
		if (build_int_epilogue(&ctx, MIPS_R_RA))
			goto out_err;
	} while (ctx.long_b_conversion);

	image_size = 4 * ctx.idx;

	header = bpf_jit_binary_alloc(image_size, &image_ptr,
				      sizeof(u32), jit_fill_hole);
	if (header == NULL)
		goto out_err;

	ctx.target = (u32 *)image_ptr;

	/* Third pass generates the code */
	ctx.idx = 0;
	if (build_int_prologue(&ctx))
		goto out_err;
	if (build_int_body(&ctx))
		goto out_err;
	if (build_int_epilogue(&ctx, MIPS_R_RA))
		goto out_err;

	/* Update the icache */
	flush_icache_range((unsigned long)ctx.target,
			   (unsigned long)&ctx.target[ctx.idx]);

	if (bpf_jit_enable > 1)
		/* Dump JIT code */
		bpf_jit_dump(prog->len, image_size, 2, ctx.target);

	bpf_jit_binary_lock_ro(header);
	prog->bpf_func = (void *)ctx.target;
	prog->jited = 1;
	prog->jited_len = image_size;
out_normal:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	kfree(ctx.offsets);
	kfree(ctx.reg_val_types);

	return prog;

out_err:
	prog = orig_prog;
	if (header)
		bpf_jit_binary_free(header);
	goto out_normal;
}
