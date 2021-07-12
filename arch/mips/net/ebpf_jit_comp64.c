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
#include <asm/uasm.h>

#include "ebpf_jit.h"

static int gen_imm_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
			int idx)
{
	int upper_bound, lower_bound;
	int dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);

	if (dst < 0)
		return dst;

	switch (BPF_OP(insn->code)) {
	case BPF_MOV:
	case BPF_ADD:
		upper_bound = S16_MAX;
		lower_bound = S16_MIN;
		break;
	case BPF_SUB:
		upper_bound = -(int)S16_MIN;
		lower_bound = -(int)S16_MAX;
		break;
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		upper_bound = 0xffff;
		lower_bound = 0;
		break;
	case BPF_RSH:
	case BPF_LSH:
	case BPF_ARSH:
		/* Shift amounts are truncated, no need for bounds */
		upper_bound = S32_MAX;
		lower_bound = S32_MIN;
		break;
	default:
		return -EINVAL;
	}

	/*
	 * Immediate move clobbers the register, so no sign/zero
	 * extension needed.
	 */
	if (BPF_CLASS(insn->code) == BPF_ALU64 &&
	    BPF_OP(insn->code) != BPF_MOV &&
	    get_reg_val_type(ctx, idx, insn->dst_reg) == REG_32BIT)
		emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);
	/* BPF_ALU | BPF_LSH doesn't need separate sign extension */
	if (BPF_CLASS(insn->code) == BPF_ALU &&
	    BPF_OP(insn->code) != BPF_LSH &&
	    BPF_OP(insn->code) != BPF_MOV &&
	    get_reg_val_type(ctx, idx, insn->dst_reg) != REG_32BIT)
		emit_instr(ctx, sll, dst, dst, 0);

	if (insn->imm >= lower_bound && insn->imm <= upper_bound) {
		/* single insn immediate case */
		switch (BPF_OP(insn->code) | BPF_CLASS(insn->code)) {
		case BPF_ALU64 | BPF_MOV:
			emit_instr(ctx, daddiu, dst, MIPS_R_ZERO, insn->imm);
			break;
		case BPF_ALU64 | BPF_AND:
		case BPF_ALU | BPF_AND:
			emit_instr(ctx, andi, dst, dst, insn->imm);
			break;
		case BPF_ALU64 | BPF_OR:
		case BPF_ALU | BPF_OR:
			emit_instr(ctx, ori, dst, dst, insn->imm);
			break;
		case BPF_ALU64 | BPF_XOR:
		case BPF_ALU | BPF_XOR:
			emit_instr(ctx, xori, dst, dst, insn->imm);
			break;
		case BPF_ALU64 | BPF_ADD:
			emit_instr(ctx, daddiu, dst, dst, insn->imm);
			break;
		case BPF_ALU64 | BPF_SUB:
			emit_instr(ctx, daddiu, dst, dst, -insn->imm);
			break;
		case BPF_ALU64 | BPF_RSH:
			emit_instr(ctx, dsrl_safe, dst, dst, insn->imm & 0x3f);
			break;
		case BPF_ALU | BPF_RSH:
			emit_instr(ctx, srl, dst, dst, insn->imm & 0x1f);
			break;
		case BPF_ALU64 | BPF_LSH:
			emit_instr(ctx, dsll_safe, dst, dst, insn->imm & 0x3f);
			break;
		case BPF_ALU | BPF_LSH:
			emit_instr(ctx, sll, dst, dst, insn->imm & 0x1f);
			break;
		case BPF_ALU64 | BPF_ARSH:
			emit_instr(ctx, dsra_safe, dst, dst, insn->imm & 0x3f);
			break;
		case BPF_ALU | BPF_ARSH:
			emit_instr(ctx, sra, dst, dst, insn->imm & 0x1f);
			break;
		case BPF_ALU | BPF_MOV:
			emit_instr(ctx, addiu, dst, MIPS_R_ZERO, insn->imm);
			break;
		case BPF_ALU | BPF_ADD:
			emit_instr(ctx, addiu, dst, dst, insn->imm);
			break;
		case BPF_ALU | BPF_SUB:
			emit_instr(ctx, addiu, dst, dst, -insn->imm);
			break;
		default:
			return -EINVAL;
		}
	} else {
		/* multi insn immediate case */
		if (BPF_OP(insn->code) == BPF_MOV) {
			gen_imm_to_reg(insn, dst, ctx);
		} else {
			gen_imm_to_reg(insn, MIPS_R_AT, ctx);
			switch (BPF_OP(insn->code) | BPF_CLASS(insn->code)) {
			case BPF_ALU64 | BPF_AND:
			case BPF_ALU | BPF_AND:
				emit_instr(ctx, and, dst, dst, MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_OR:
			case BPF_ALU | BPF_OR:
				emit_instr(ctx, or, dst, dst, MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_XOR:
			case BPF_ALU | BPF_XOR:
				emit_instr(ctx, xor, dst, dst, MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_ADD:
				emit_instr(ctx, daddu, dst, dst, MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_SUB:
				emit_instr(ctx, dsubu, dst, dst, MIPS_R_AT);
				break;
			case BPF_ALU | BPF_ADD:
				emit_instr(ctx, addu, dst, dst, MIPS_R_AT);
				break;
			case BPF_ALU | BPF_SUB:
				emit_instr(ctx, subu, dst, dst, MIPS_R_AT);
				break;
			default:
				return -EINVAL;
			}
		}
	}

	return 0;
}

/* Returns the number of insn slots consumed. */
int build_one_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
		   int this_idx, int exit_idx)
{
	int src, dst, r, td, ts, mem_off, b_off;
	bool need_swap, did_move, cmp_eq;
	unsigned int target = 0;
	u64 t64;
	s64 t64s;
	int bpf_op = BPF_OP(insn->code);

	switch (insn->code) {
	case BPF_ALU64 | BPF_ADD | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_SUB | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_OR | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_AND | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_LSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_RSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_XOR | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_ARSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_MOV | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_MOV | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_ADD | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_SUB | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_OR | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_AND | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_LSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_RSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_XOR | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_ARSH | BPF_K: /* ALU64_IMM */
		r = gen_imm_insn(insn, ctx, this_idx);
		if (r < 0)
			return r;
		break;
	case BPF_ALU64 | BPF_MUL | BPF_K: /* ALU64_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		if (get_reg_val_type(ctx, this_idx, insn->dst_reg) == REG_32BIT)
			emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);
		if (insn->imm == 1) /* Mult by 1 is a nop */
			break;
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		if (MIPS_ISA_REV >= 6) {
			emit_instr(ctx, dmulu, dst, dst, MIPS_R_AT);
		} else {
			emit_instr(ctx, dmultu, MIPS_R_AT, dst);
			emit_instr(ctx, mflo, dst);
		}
		break;
	case BPF_ALU64 | BPF_NEG | BPF_K: /* ALU64_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		if (get_reg_val_type(ctx, this_idx, insn->dst_reg) == REG_32BIT)
			emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);
		emit_instr(ctx, dsubu, dst, MIPS_R_ZERO, dst);
		break;
	case BPF_ALU | BPF_MUL | BPF_K: /* ALU_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		td = get_reg_val_type(ctx, this_idx, insn->dst_reg);
		if (td == REG_64BIT) {
			/* sign extend */
			emit_instr(ctx, sll, dst, dst, 0);
		}
		if (insn->imm == 1) /* Mult by 1 is a nop */
			break;
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		if (MIPS_ISA_REV >= 6) {
			emit_instr(ctx, mulu, dst, dst, MIPS_R_AT);
		} else {
			emit_instr(ctx, multu, dst, MIPS_R_AT);
			emit_instr(ctx, mflo, dst);
		}
		break;
	case BPF_ALU | BPF_NEG | BPF_K: /* ALU_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		td = get_reg_val_type(ctx, this_idx, insn->dst_reg);
		if (td == REG_64BIT) {
			/* sign extend */
			emit_instr(ctx, sll, dst, dst, 0);
		}
		emit_instr(ctx, subu, dst, MIPS_R_ZERO, dst);
		break;
	case BPF_ALU | BPF_DIV | BPF_K: /* ALU_IMM */
	case BPF_ALU | BPF_MOD | BPF_K: /* ALU_IMM */
		if (insn->imm == 0)
			return -EINVAL;
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		td = get_reg_val_type(ctx, this_idx, insn->dst_reg);
		if (td == REG_64BIT)
			/* sign extend */
			emit_instr(ctx, sll, dst, dst, 0);
		if (insn->imm == 1) {
			/* div by 1 is a nop, mod by 1 is zero */
			if (bpf_op == BPF_MOD)
				emit_instr(ctx, addu, dst, MIPS_R_ZERO, MIPS_R_ZERO);
			break;
		}
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		if (MIPS_ISA_REV >= 6) {
			if (bpf_op == BPF_DIV)
				emit_instr(ctx, divu_r6, dst, dst, MIPS_R_AT);
			else
				emit_instr(ctx, modu, dst, dst, MIPS_R_AT);
			break;
		}
		emit_instr(ctx, divu, dst, MIPS_R_AT);
		if (bpf_op == BPF_DIV)
			emit_instr(ctx, mflo, dst);
		else
			emit_instr(ctx, mfhi, dst);
		break;
	case BPF_ALU64 | BPF_DIV | BPF_K: /* ALU_IMM */
	case BPF_ALU64 | BPF_MOD | BPF_K: /* ALU_IMM */
		if (insn->imm == 0)
			return -EINVAL;
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		if (get_reg_val_type(ctx, this_idx, insn->dst_reg) == REG_32BIT)
			emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);
		if (insn->imm == 1) {
			/* div by 1 is a nop, mod by 1 is zero */
			if (bpf_op == BPF_MOD)
				emit_instr(ctx, addu, dst, MIPS_R_ZERO, MIPS_R_ZERO);
			break;
		}
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		if (MIPS_ISA_REV >= 6) {
			if (bpf_op == BPF_DIV)
				emit_instr(ctx, ddivu_r6, dst, dst, MIPS_R_AT);
			else
				emit_instr(ctx, dmodu, dst, dst, MIPS_R_AT);
			break;
		}
		emit_instr(ctx, ddivu, dst, MIPS_R_AT);
		if (bpf_op == BPF_DIV)
			emit_instr(ctx, mflo, dst);
		else
			emit_instr(ctx, mfhi, dst);
		break;
	case BPF_ALU64 | BPF_MOV | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_ADD | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_SUB | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_XOR | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_OR | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_AND | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_MUL | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_DIV | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_MOD | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_LSH | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_RSH | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_ARSH | BPF_X: /* ALU64_REG */
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (src < 0 || dst < 0)
			return -EINVAL;
		if (get_reg_val_type(ctx, this_idx, insn->dst_reg) == REG_32BIT)
			emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);
		did_move = false;
		if (get_reg_val_type(ctx, this_idx, insn->src_reg) == REG_32BIT) {
			int tmp_reg = MIPS_R_AT;

			if (bpf_op == BPF_MOV) {
				tmp_reg = dst;
				did_move = true;
			}
			emit_instr(ctx, daddu, tmp_reg, src, MIPS_R_ZERO);
			emit_instr(ctx, dinsu, tmp_reg, MIPS_R_ZERO, 32, 32);
			src = MIPS_R_AT;
		}
		switch (bpf_op) {
		case BPF_MOV:
			if (!did_move)
				emit_instr(ctx, daddu, dst, src, MIPS_R_ZERO);
			break;
		case BPF_ADD:
			emit_instr(ctx, daddu, dst, dst, src);
			break;
		case BPF_SUB:
			emit_instr(ctx, dsubu, dst, dst, src);
			break;
		case BPF_XOR:
			emit_instr(ctx, xor, dst, dst, src);
			break;
		case BPF_OR:
			emit_instr(ctx, or, dst, dst, src);
			break;
		case BPF_AND:
			emit_instr(ctx, and, dst, dst, src);
			break;
		case BPF_MUL:
			if (MIPS_ISA_REV >= 6) {
				emit_instr(ctx, dmulu, dst, dst, src);
			} else {
				emit_instr(ctx, dmultu, dst, src);
				emit_instr(ctx, mflo, dst);
			}
			break;
		case BPF_DIV:
		case BPF_MOD:
			if (MIPS_ISA_REV >= 6) {
				if (bpf_op == BPF_DIV)
					emit_instr(ctx, ddivu_r6,
							dst, dst, src);
				else
					emit_instr(ctx, dmodu, dst, dst, src);
				break;
			}
			emit_instr(ctx, ddivu, dst, src);
			if (bpf_op == BPF_DIV)
				emit_instr(ctx, mflo, dst);
			else
				emit_instr(ctx, mfhi, dst);
			break;
		case BPF_LSH:
			emit_instr(ctx, dsllv, dst, dst, src);
			break;
		case BPF_RSH:
			emit_instr(ctx, dsrlv, dst, dst, src);
			break;
		case BPF_ARSH:
			emit_instr(ctx, dsrav, dst, dst, src);
			break;
		default:
			pr_err("ALU64_REG NOT HANDLED\n");
			return -EINVAL;
		}
		break;
	case BPF_ALU | BPF_MOV | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_ADD | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_SUB | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_XOR | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_OR | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_AND | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_MUL | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_DIV | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_MOD | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_LSH | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_RSH | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_ARSH | BPF_X: /* ALU_REG */
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (src < 0 || dst < 0)
			return -EINVAL;
		td = get_reg_val_type(ctx, this_idx, insn->dst_reg);
		if (td == REG_64BIT) {
			/* sign extend */
			emit_instr(ctx, sll, dst, dst, 0);
		}
		did_move = false;
		ts = get_reg_val_type(ctx, this_idx, insn->src_reg);
		if (ts == REG_64BIT) {
			int tmp_reg = MIPS_R_AT;

			if (bpf_op == BPF_MOV) {
				tmp_reg = dst;
				did_move = true;
			}
			/* sign extend */
			emit_instr(ctx, sll, tmp_reg, src, 0);
			src = MIPS_R_AT;
		}
		switch (bpf_op) {
		case BPF_MOV:
			if (!did_move)
				emit_instr(ctx, addu, dst, src, MIPS_R_ZERO);
			break;
		case BPF_ADD:
			emit_instr(ctx, addu, dst, dst, src);
			break;
		case BPF_SUB:
			emit_instr(ctx, subu, dst, dst, src);
			break;
		case BPF_XOR:
			emit_instr(ctx, xor, dst, dst, src);
			break;
		case BPF_OR:
			emit_instr(ctx, or, dst, dst, src);
			break;
		case BPF_AND:
			emit_instr(ctx, and, dst, dst, src);
			break;
		case BPF_MUL:
			emit_instr(ctx, mul, dst, dst, src);
			break;
		case BPF_DIV:
		case BPF_MOD:
			if (MIPS_ISA_REV >= 6) {
				if (bpf_op == BPF_DIV)
					emit_instr(ctx, divu_r6, dst, dst, src);
				else
					emit_instr(ctx, modu, dst, dst, src);
				break;
			}
			emit_instr(ctx, divu, dst, src);
			if (bpf_op == BPF_DIV)
				emit_instr(ctx, mflo, dst);
			else
				emit_instr(ctx, mfhi, dst);
			break;
		case BPF_LSH:
			emit_instr(ctx, sllv, dst, dst, src);
			break;
		case BPF_RSH:
			emit_instr(ctx, srlv, dst, dst, src);
			break;
		case BPF_ARSH:
			emit_instr(ctx, srav, dst, dst, src);
			break;
		default:
			pr_err("ALU_REG NOT HANDLED\n");
			return -EINVAL;
		}
		break;
	case BPF_JMP | BPF_EXIT:
		if (this_idx + 1 < exit_idx) {
			b_off = b_imm(exit_idx, ctx);
			if (is_bad_offset(b_off)) {
				target = j_target(ctx, exit_idx);
				if (target == (unsigned int)-1)
					return -E2BIG;
				emit_instr(ctx, j, target);
			} else {
				emit_instr(ctx, b, b_off);
			}
			emit_instr(ctx, nop);
		}
		break;
	case BPF_JMP | BPF_JEQ | BPF_K: /* JMP_IMM */
	case BPF_JMP | BPF_JNE | BPF_K: /* JMP_IMM */
		cmp_eq = (bpf_op == BPF_JEQ);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return dst;
		if (insn->imm == 0) {
			src = MIPS_R_ZERO;
		} else {
			gen_imm_to_reg(insn, MIPS_R_AT, ctx);
			src = MIPS_R_AT;
		}
		goto jeq_common;
	case BPF_JMP | BPF_JEQ | BPF_X: /* JMP_REG */
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (src < 0 || dst < 0)
			return -EINVAL;
		td = get_reg_val_type(ctx, this_idx, insn->dst_reg);
		ts = get_reg_val_type(ctx, this_idx, insn->src_reg);
		if (td == REG_32BIT && ts != REG_32BIT) {
			emit_instr(ctx, sll, MIPS_R_AT, src, 0);
			src = MIPS_R_AT;
		} else if (ts == REG_32BIT && td != REG_32BIT) {
			emit_instr(ctx, sll, MIPS_R_AT, dst, 0);
			dst = MIPS_R_AT;
		}
		if (bpf_op == BPF_JSET) {
			emit_instr(ctx, and, MIPS_R_AT, dst, src);
			cmp_eq = false;
			dst = MIPS_R_AT;
			src = MIPS_R_ZERO;
		} else if (bpf_op == BPF_JSGT || bpf_op == BPF_JSLE) {
			emit_instr(ctx, dsubu, MIPS_R_AT, dst, src);
			if ((insn + 1)->code == (BPF_JMP | BPF_EXIT) && insn->off == 1) {
				b_off = b_imm(exit_idx, ctx);
				if (is_bad_offset(b_off))
					return -E2BIG;
				if (bpf_op == BPF_JSGT)
					emit_instr(ctx, blez, MIPS_R_AT, b_off);
				else
					emit_instr(ctx, bgtz, MIPS_R_AT, b_off);
				emit_instr(ctx, nop);
				return 2; /* We consumed the exit. */
			}
			b_off = b_imm(this_idx + insn->off + 1, ctx);
			if (is_bad_offset(b_off))
				return -E2BIG;
			if (bpf_op == BPF_JSGT)
				emit_instr(ctx, bgtz, MIPS_R_AT, b_off);
			else
				emit_instr(ctx, blez, MIPS_R_AT, b_off);
			emit_instr(ctx, nop);
			break;
		} else if (bpf_op == BPF_JSGE || bpf_op == BPF_JSLT) {
			emit_instr(ctx, slt, MIPS_R_AT, dst, src);
			cmp_eq = bpf_op == BPF_JSGE;
			dst = MIPS_R_AT;
			src = MIPS_R_ZERO;
		} else if (bpf_op == BPF_JGT || bpf_op == BPF_JLE) {
			/* dst or src could be AT */
			emit_instr(ctx, dsubu, MIPS_R_T8, dst, src);
			emit_instr(ctx, sltu, MIPS_R_AT, dst, src);
			/* SP known to be non-zero, movz becomes boolean not */
			if (MIPS_ISA_REV >= 6) {
				emit_instr(ctx, seleqz, MIPS_R_T9,
						MIPS_R_SP, MIPS_R_T8);
			} else {
				emit_instr(ctx, movz, MIPS_R_T9,
						MIPS_R_SP, MIPS_R_T8);
				emit_instr(ctx, movn, MIPS_R_T9,
						MIPS_R_ZERO, MIPS_R_T8);
			}
			emit_instr(ctx, or, MIPS_R_AT, MIPS_R_T9, MIPS_R_AT);
			cmp_eq = bpf_op == BPF_JGT;
			dst = MIPS_R_AT;
			src = MIPS_R_ZERO;
		} else if (bpf_op == BPF_JGE || bpf_op == BPF_JLT) {
			emit_instr(ctx, sltu, MIPS_R_AT, dst, src);
			cmp_eq = bpf_op == BPF_JGE;
			dst = MIPS_R_AT;
			src = MIPS_R_ZERO;
		} else { /* JNE/JEQ case */
			cmp_eq = (bpf_op == BPF_JEQ);
		}
jeq_common:
		/*
		 * If the next insn is EXIT and we are jumping arround
		 * only it, invert the sense of the compare and
		 * conditionally jump to the exit.  Poor man's branch
		 * chaining.
		 */
		if ((insn + 1)->code == (BPF_JMP | BPF_EXIT) && insn->off == 1) {
			b_off = b_imm(exit_idx, ctx);
			if (is_bad_offset(b_off)) {
				target = j_target(ctx, exit_idx);
				if (target == (unsigned int)-1)
					return -E2BIG;
				cmp_eq = !cmp_eq;
				b_off = 4 * 3;
				if (!(ctx->offsets[this_idx] & OFFSETS_B_CONV)) {
					ctx->offsets[this_idx] |= OFFSETS_B_CONV;
					ctx->long_b_conversion = 1;
				}
			}

			if (cmp_eq)
				emit_instr(ctx, bne, dst, src, b_off);
			else
				emit_instr(ctx, beq, dst, src, b_off);
			emit_instr(ctx, nop);
			if (ctx->offsets[this_idx] & OFFSETS_B_CONV) {
				emit_instr(ctx, j, target);
				emit_instr(ctx, nop);
			}
			return 2; /* We consumed the exit. */
		}
		b_off = b_imm(this_idx + insn->off + 1, ctx);
		if (is_bad_offset(b_off)) {
			target = j_target(ctx, this_idx + insn->off + 1);
			if (target == (unsigned int)-1)
				return -E2BIG;
			cmp_eq = !cmp_eq;
			b_off = 4 * 3;
			if (!(ctx->offsets[this_idx] & OFFSETS_B_CONV)) {
				ctx->offsets[this_idx] |= OFFSETS_B_CONV;
				ctx->long_b_conversion = 1;
			}
		}

		if (cmp_eq)
			emit_instr(ctx, beq, dst, src, b_off);
		else
			emit_instr(ctx, bne, dst, src, b_off);
		emit_instr(ctx, nop);
		if (ctx->offsets[this_idx] & OFFSETS_B_CONV) {
			emit_instr(ctx, j, target);
			emit_instr(ctx, nop);
		}
		break;
	case BPF_JMP | BPF_JSGT | BPF_K: /* JMP_IMM */
	case BPF_JMP | BPF_JSGE | BPF_K: /* JMP_IMM */
	case BPF_JMP | BPF_JSLT | BPF_K: /* JMP_IMM */
	case BPF_JMP | BPF_JSLE | BPF_K: /* JMP_IMM */
		cmp_eq = (bpf_op == BPF_JSGE);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return dst;

		if (insn->imm == 0) {
			if ((insn + 1)->code == (BPF_JMP | BPF_EXIT) && insn->off == 1) {
				b_off = b_imm(exit_idx, ctx);
				if (is_bad_offset(b_off))
					return -E2BIG;
				switch (bpf_op) {
				case BPF_JSGT:
					emit_instr(ctx, blez, dst, b_off);
					break;
				case BPF_JSGE:
					emit_instr(ctx, bltz, dst, b_off);
					break;
				case BPF_JSLT:
					emit_instr(ctx, bgez, dst, b_off);
					break;
				case BPF_JSLE:
					emit_instr(ctx, bgtz, dst, b_off);
					break;
				}
				emit_instr(ctx, nop);
				return 2; /* We consumed the exit. */
			}
			b_off = b_imm(this_idx + insn->off + 1, ctx);
			if (is_bad_offset(b_off))
				return -E2BIG;
			switch (bpf_op) {
			case BPF_JSGT:
				emit_instr(ctx, bgtz, dst, b_off);
				break;
			case BPF_JSGE:
				emit_instr(ctx, bgez, dst, b_off);
				break;
			case BPF_JSLT:
				emit_instr(ctx, bltz, dst, b_off);
				break;
			case BPF_JSLE:
				emit_instr(ctx, blez, dst, b_off);
				break;
			}
			emit_instr(ctx, nop);
			break;
		}
		/*
		 * only "LT" compare available, so we must use imm + 1
		 * to generate "GT" and imm -1 to generate LE
		 */
		if (bpf_op == BPF_JSGT)
			t64s = insn->imm + 1;
		else if (bpf_op == BPF_JSLE)
			t64s = insn->imm + 1;
		else
			t64s = insn->imm;

		cmp_eq = bpf_op == BPF_JSGT || bpf_op == BPF_JSGE;
		if (t64s >= S16_MIN && t64s <= S16_MAX) {
			emit_instr(ctx, slti, MIPS_R_AT, dst, (int)t64s);
			src = MIPS_R_AT;
			dst = MIPS_R_ZERO;
			goto jeq_common;
		}
		emit_const_to_reg(ctx, MIPS_R_AT, (u64)t64s);
		emit_instr(ctx, slt, MIPS_R_AT, dst, MIPS_R_AT);
		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		goto jeq_common;

	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
		cmp_eq = (bpf_op == BPF_JGE);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return dst;
		/*
		 * only "LT" compare available, so we must use imm + 1
		 * to generate "GT" and imm -1 to generate LE
		 */
		if (bpf_op == BPF_JGT)
			t64s = (u64)(u32)(insn->imm) + 1;
		else if (bpf_op == BPF_JLE)
			t64s = (u64)(u32)(insn->imm) + 1;
		else
			t64s = (u64)(u32)(insn->imm);

		cmp_eq = bpf_op == BPF_JGT || bpf_op == BPF_JGE;

		emit_const_to_reg(ctx, MIPS_R_AT, (u64)t64s);
		emit_instr(ctx, sltu, MIPS_R_AT, dst, MIPS_R_AT);
		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		goto jeq_common;

	case BPF_JMP | BPF_JSET | BPF_K: /* JMP_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return dst;

		if (ctx->use_bbit_insns && hweight32((u32)insn->imm) == 1) {
			if ((insn + 1)->code == (BPF_JMP | BPF_EXIT) && insn->off == 1) {
				b_off = b_imm(exit_idx, ctx);
				if (is_bad_offset(b_off))
					return -E2BIG;
				emit_instr(ctx, bbit0, dst, ffs((u32)insn->imm) - 1, b_off);
				emit_instr(ctx, nop);
				return 2; /* We consumed the exit. */
			}
			b_off = b_imm(this_idx + insn->off + 1, ctx);
			if (is_bad_offset(b_off))
				return -E2BIG;
			emit_instr(ctx, bbit1, dst, ffs((u32)insn->imm) - 1, b_off);
			emit_instr(ctx, nop);
			break;
		}
		t64 = (u32)insn->imm;
		emit_const_to_reg(ctx, MIPS_R_AT, t64);
		emit_instr(ctx, and, MIPS_R_AT, dst, MIPS_R_AT);
		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		cmp_eq = false;
		goto jeq_common;

	case BPF_JMP | BPF_JA:
		/*
		 * Prefer relative branch for easier debugging, but
		 * fall back if needed.
		 */
		b_off = b_imm(this_idx + insn->off + 1, ctx);
		if (is_bad_offset(b_off)) {
			target = j_target(ctx, this_idx + insn->off + 1);
			if (target == (unsigned int)-1)
				return -E2BIG;
			emit_instr(ctx, j, target);
		} else {
			emit_instr(ctx, b, b_off);
		}
		emit_instr(ctx, nop);
		break;
	case BPF_LD | BPF_DW | BPF_IMM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		t64 = ((u64)(u32)insn->imm) | ((u64)(insn + 1)->imm << 32);
		emit_const_to_reg(ctx, dst, t64);
		return 2; /* Double slot insn */

	case BPF_JMP | BPF_CALL:
		emit_bpf_call(ctx, insn);
		break;

	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(ctx, this_idx))
			return -EINVAL;
		break;

	case BPF_ALU | BPF_END | BPF_FROM_BE:
	case BPF_ALU | BPF_END | BPF_FROM_LE:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		td = get_reg_val_type(ctx, this_idx, insn->dst_reg);
		if (insn->imm == 64 && td == REG_32BIT)
			emit_instr(ctx, dinsu, dst, MIPS_R_ZERO, 32, 32);

		if (insn->imm != 64 && td == REG_64BIT) {
			/* sign extend */
			emit_instr(ctx, sll, dst, dst, 0);
		}

#ifdef __BIG_ENDIAN
		need_swap = (BPF_SRC(insn->code) == BPF_FROM_LE);
#else
		need_swap = (BPF_SRC(insn->code) == BPF_FROM_BE);
#endif
		if (insn->imm == 16) {
			if (need_swap)
				emit_instr(ctx, wsbh, dst, dst);
			emit_instr(ctx, andi, dst, dst, 0xffff);
		} else if (insn->imm == 32) {
			if (need_swap) {
				emit_instr(ctx, wsbh, dst, dst);
				emit_instr(ctx, rotr, dst, dst, 16);
			}
		} else { /* 64-bit*/
			if (need_swap) {
				emit_instr(ctx, dsbh, dst, dst);
				emit_instr(ctx, dshd, dst, dst);
			}
		}
		break;

	case BPF_ST | BPF_B | BPF_MEM:
	case BPF_ST | BPF_H | BPF_MEM:
	case BPF_ST | BPF_W | BPF_MEM:
	case BPF_ST | BPF_DW | BPF_MEM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return dst;
		mem_off = insn->off;
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		switch (BPF_SIZE(insn->code)) {
		case BPF_B:
			emit_instr(ctx, sb, MIPS_R_AT, mem_off, dst);
			break;
		case BPF_H:
			emit_instr(ctx, sh, MIPS_R_AT, mem_off, dst);
			break;
		case BPF_W:
			emit_instr(ctx, sw, MIPS_R_AT, mem_off, dst);
			break;
		case BPF_DW:
			emit_instr(ctx, sd, MIPS_R_AT, mem_off, dst);
			break;
		}
		break;

	case BPF_LDX | BPF_B | BPF_MEM:
	case BPF_LDX | BPF_H | BPF_MEM:
	case BPF_LDX | BPF_W | BPF_MEM:
	case BPF_LDX | BPF_DW | BPF_MEM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		if (dst < 0 || src < 0)
			return -EINVAL;
		mem_off = insn->off;
		switch (BPF_SIZE(insn->code)) {
		case BPF_B:
			emit_instr(ctx, lbu, dst, mem_off, src);
			break;
		case BPF_H:
			emit_instr(ctx, lhu, dst, mem_off, src);
			break;
		case BPF_W:
			emit_instr(ctx, lw, dst, mem_off, src);
			break;
		case BPF_DW:
			emit_instr(ctx, ld, dst, mem_off, src);
			break;
		}
		break;

	case BPF_STX | BPF_B | BPF_MEM:
	case BPF_STX | BPF_H | BPF_MEM:
	case BPF_STX | BPF_W | BPF_MEM:
	case BPF_STX | BPF_DW | BPF_MEM:
	case BPF_STX | BPF_W | BPF_ATOMIC:
	case BPF_STX | BPF_DW | BPF_ATOMIC:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		if (src < 0 || dst < 0)
			return -EINVAL;
		mem_off = insn->off;
		if (BPF_MODE(insn->code) == BPF_ATOMIC) {
			if (insn->imm != BPF_ADD) {
				pr_err("ATOMIC OP %02x NOT HANDLED\n", insn->imm);
				return -EINVAL;
			}
			/*
			 * If mem_off does not fit within the 9 bit ll/sc
			 * instruction immediate field, use a temp reg.
			 */
			if (MIPS_ISA_REV >= 6 &&
			    (mem_off >= BIT(8) || mem_off < -BIT(8))) {
				emit_instr(ctx, daddiu, MIPS_R_T6,
						dst, mem_off);
				mem_off = 0;
				dst = MIPS_R_T6;
			}
			switch (BPF_SIZE(insn->code)) {
			case BPF_W:
				if (get_reg_val_type(ctx, this_idx, insn->src_reg) == REG_32BIT) {
					emit_instr(ctx, sll, MIPS_R_AT, src, 0);
					src = MIPS_R_AT;
				}
				emit_instr(ctx, ll, MIPS_R_T8, mem_off, dst);
				emit_instr(ctx, addu, MIPS_R_T8, MIPS_R_T8, src);
				emit_instr(ctx, sc, MIPS_R_T8, mem_off, dst);
				/*
				 * On failure back up to LL (-4
				 * instructions of 4 bytes each
				 */
				emit_instr(ctx, beq, MIPS_R_T8, MIPS_R_ZERO, -4 * 4);
				emit_instr(ctx, nop);
				break;
			case BPF_DW:
				if (get_reg_val_type(ctx, this_idx, insn->src_reg) == REG_32BIT) {
					emit_instr(ctx, daddu, MIPS_R_AT, src, MIPS_R_ZERO);
					emit_instr(ctx, dinsu, MIPS_R_AT, MIPS_R_ZERO, 32, 32);
					src = MIPS_R_AT;
				}
				emit_instr(ctx, lld, MIPS_R_T8, mem_off, dst);
				emit_instr(ctx, daddu, MIPS_R_T8, MIPS_R_T8, src);
				emit_instr(ctx, scd, MIPS_R_T8, mem_off, dst);
				emit_instr(ctx, beq, MIPS_R_T8, MIPS_R_ZERO, -4 * 4);
				emit_instr(ctx, nop);
				break;
			}
		} else { /* BPF_MEM */
			switch (BPF_SIZE(insn->code)) {
			case BPF_B:
				emit_instr(ctx, sb, src, mem_off, dst);
				break;
			case BPF_H:
				emit_instr(ctx, sh, src, mem_off, dst);
				break;
			case BPF_W:
				emit_instr(ctx, sw, src, mem_off, dst);
				break;
			case BPF_DW:
				if (get_reg_val_type(ctx, this_idx, insn->src_reg) == REG_32BIT) {
					emit_instr(ctx, daddu, MIPS_R_AT, src, MIPS_R_ZERO);
					emit_instr(ctx, dinsu, MIPS_R_AT, MIPS_R_ZERO, 32, 32);
					src = MIPS_R_AT;
				}
				emit_instr(ctx, sd, src, mem_off, dst);
				break;
			}
		}
		break;

	default:
		pr_err("NOT HANDLED %d - (%02x)\n",
		       this_idx, (unsigned int)insn->code);
		return -EINVAL;
	}
	return 1;
}
