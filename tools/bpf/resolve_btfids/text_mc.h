/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __TEXT_MC_H
#define __TEXT_MC_H

#include "text_insn.h"

/*
 * What text_mc.cpp has to be told about an arch to describe its instructions
 * in the terms of text_insn.h with LLVM's MC layer.
 *
 * MC gives the length, the MCInst, the flags of MCInstrDesc, the explicit and
 * the implicit defs, the aliases of a register and the target of a branch.
 * It does not say what an instruction computes: the selection patterns are not
 * a part of it. And the headers with the enums of a target are not installed.
 * So opcodes and registers are given by name, as MCInstrInfo::getName() and
 * MCRegisterInfo::getName() return them, and looked up once. A name which this
 * LLVM does not have is an error.
 */

/* A condition on the operands of an MCInst, like an MCInstPredicate of TableGen */
enum mc_predicate_kind {
	MC_TRUE,
	MC_ZERO_REG,	/* operand A is the zero register */
	MC_SAME_REG,	/* operands A and B are the same register */
	MC_IMM,		/* operand A is the immediate B */
};

struct mc_predicate {
	u8 kind;
	u8 a;
	s32 b;
};

#define ZERO_REG(a)	{ MC_ZERO_REG, a, 0 }
#define SAME_REG(a, b)	{ MC_SAME_REG, a, b }
#define IMM(a, b)	{ MC_IMM, a, b }
#define VALUE(v)	.fixed = true, .value = v

/* Instead of the number of an operand: the first implicit def or use */
#define MC_IMPLICIT	0xff

/*
 * What an opcode computes, if it makes or copies a value. The patterns of an
 * opcode are tried in their order. The width of the operation is that of the
 * register DST.
 *
 * A pattern of kind TEXT_OTHER is about the defs. hasUnmodeledSideEffects() is
 * how LLVM says that MCInstrDesc does not tell all about an opcode: it writes
 * TEXT_ALL_REGS, unless such a pattern says that it writes what MCInstrDesc
 * has, and DEFS.
 * With NOP the instruction is a nop if the first predicate holds.
 *
 * A pattern of kind TEXT_RETURN names a return to the caller. isReturn() holds
 * for a return from an exception as well, which does not hand the return value
 * register to a caller. Without such a pattern it is an opcode like any other,
 * and LLVM says hasUnmodeledSideEffects() of it.
 *
 * Without a pattern errors are lost, none is made up. So an opcode has one only
 * if that brings more than a few errors in some kernel.
 */
struct mc_pattern {
	const char *opcode;
	u8 kind;		/* enum text_insn_kind */
	u8 dst, src, src2;	/* the numbers of the operands. DST is 0 unless it is given */
	u8 imm;			/* the operand with the immediate */
	u8 shift;		/* the operand which says how far the immediate is shifted left */
	u8 op;			/* of TEXT_ALU_IMM */
	bool invert;		/* the immediate */
	bool or_zero;		/* TEXT_MOV_IMM: the immediate or 0 */
	bool fixed;		/* the immediate is VALUE, not an operand */
	s64 value;
	u32 defs;		/* of TEXT_OTHER */
	bool nop;		/* of TEXT_OTHER */
	struct mc_predicate predicates[2];
};

/* An instruction, in hex, and what text_arch.decode() has to say about it at MC_TEST_ADDR */
struct mc_test {
	const char *code;
	/* uses and load are compared only if uses is set */
	struct text_insn insn;
};

#define MC_TEST_ADDR	0x1000

struct mc_arch {
	struct text_arch arch;
	unsigned int machine;	/* of the ELF header */
	const char *triple, *features;
	/*
	 * The names of registers 0, 1, ... of text_insn.h, separated by spaces.
	 * A write of a register in REGS32 zero extends. A write of any other
	 * alias is not a copy.
	 */
	const char *regs, *regs32;
	const char *zero_regs;
	const struct mc_pattern *patterns;
	/*
	 * LLVM's tables and names change from release to release, and the ones
	 * above were written for some of them. text_arch_init() fails if one of
	 * these instructions is no longer described as it was.
	 */
	const struct mc_test *tests;
};

/* The arch which the tool is built for, see Build */
extern const struct mc_arch mc_arch;

#endif
