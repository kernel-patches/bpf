// SPDX-License-Identifier: GPL-2.0-only
/* arm64 for text_mc.cpp */

#include <elf.h>
#include <linux/bits.h>

#include "text_mc.h"

/* The W and the X form of an opcode */
#define WX(before, after, ...) \
	{ before "W" after, __VA_ARGS__ }, { before "X" after, __VA_ARGS__ }

static const struct mc_pattern arm64_patterns[] = {
	WX("MOVN", "i",	 TEXT_MOV_IMM, .imm = 1, .shift = 2, .invert = true),
	WX("ORR", "rs",	 TEXT_MOV, .src = 2, .predicates = { ZERO_REG(1), IMM(3, 0) }),		/* mov */
	{ "SBFMXri",	 TEXT_SEXT32, .src = 1, .predicates = { IMM(2, 0), IMM(3, 31) } },	/* sxtw */
	WX("CSEL", "r",	 TEXT_SELECT, .src = 1, .src2 = 2),
	{ "CSINVWr",	 TEXT_MOV_IMM, VALUE(-1), .or_zero = true,
			 .predicates = { ZERO_REG(1), ZERO_REG(2) } },				/* csetm */
	{ "CSINVWr",	 TEXT_SELECT_IMM, .src = 1, VALUE(-1), .predicates = { ZERO_REG(2) } },
	/* rn, or a function of rm */
	{ "CSINCWr",	 TEXT_SELECT, .src = 1, .src2 = 1 },
	/* and rd, rn, rm, asr #31: rn or 0 */
	{ "ANDWrs",	 TEXT_SELECT, .src = 1, .src2 = 1, .predicates = { IMM(3, 2 << 6 | 31) } },
	/* HINT: nop, bti, yield, wfe ... */
	{ "HINT", TEXT_OTHER }, { "AUTIASP", TEXT_OTHER }, { "PRFMui", TEXT_OTHER },
	{ "HINT", TEXT_OTHER, .nop = true, .predicates = { IMM(0, 0) } },	/* nop */
	{ "DMB", TEXT_OTHER }, { "MRS", TEXT_OTHER }, { "MSR", TEXT_OTHER },
	{ "STLRB", TEXT_OTHER }, { "STLRW", TEXT_OTHER },
	WX("LDXR", "", TEXT_OTHER), WX("STXR", "", TEXT_OTHER), WX("STLXR", "", TEXT_OTHER),
	{ "RET", TEXT_RETURN },
	{}
};

#define T(code, insn_kind, ...)	{ code, { .kind = insn_kind, __VA_ARGS__ } }
#define IMMS(a, b)		.imm = a, .imm2 = b
#define SRC(reg)		.src = reg, .src2 = reg

/* Each pattern, and what must not match it */
static const struct mc_test arm64_tests[] = {
	T("a0 02 80 12", TEXT_MOV_IMM, .is32 = true, IMMS(0xffffffea, 0xffffffea)),	/* mov w0, #-22 */
	T("a0 02 80 92", TEXT_MOV_IMM, IMMS(-22, -22)),			/* mov x0, #-22 */
	T("20 00 a0 12", TEXT_MOV_IMM, .is32 = true, IMMS(0xfffeffff, 0xfffeffff)),	/* mov w0, #-0x10001 */
	T("e0 03 13 2a", TEXT_MOV, .is32 = true, SRC(19)),		/* mov w0, w19 */
	T("e0 03 13 aa", TEXT_MOV, SRC(19)),				/* mov x0, x19 */
	T("20 00 02 2a", TEXT_OTHER, .defs = BIT(0)),			/* orr w0, w1, w2 */
	T("20 00 02 aa", TEXT_OTHER, .defs = BIT(0)),			/* orr x0, x1, x2 */
	T("e0 07 13 2a", TEXT_OTHER, .defs = BIT(0)),			/* orr w0, wzr, w19, lsl #1 */
	T("60 7e 40 93", TEXT_SEXT32, SRC(19)),				/* sxtw x0, w19 */
	T("60 3e 40 93", TEXT_OTHER, .defs = BIT(0)),			/* sxth x0, w19 */
	T("00 01 89 1a", TEXT_SELECT, .is32 = true, .src = 8, .src2 = 9),	/* csel w0, w8, w9, eq */
	T("00 01 89 9a", TEXT_SELECT, .src = 8, .src2 = 9),		/* csel x0, x8, x9, eq */
	T("00 01 9f 9a", TEXT_SELECT, SRC(8)),				/* csel x0, x8, xzr, eq */
	T("e0 03 9f 5a", TEXT_MOV_IMM, .is32 = true, IMMS(0xffffffff, 0)),	/* csetm w0, ne */
	T("00 01 9f 5a", TEXT_SELECT_IMM, .is32 = true, SRC(8), IMMS(0xffffffff, 0xffffffff)), /* csinv w0, w8, wzr, eq */
	T("00 01 89 5a", TEXT_OTHER, .defs = BIT(0)),			/* csinv w0, w8, w9, eq */
	T("00 05 89 1a", TEXT_SELECT, .is32 = true, SRC(8)),		/* csinc w0, w8, w9, eq */
	T("00 7d 89 0a", TEXT_SELECT, .is32 = true, SRC(8)),		/* and w0, w8, w9, asr #31 */
	T("00 01 09 0a", TEXT_OTHER, .defs = BIT(0)),			/* and w0, w8, w9 */
	T("1f 20 03 d5", TEXT_OTHER, .nop = true),			/* nop */
	T("5f 24 03 d5", TEXT_OTHER),					/* bti c */
	T("bf 23 03 d5", TEXT_OTHER, .defs = BIT(30)),			/* autiasp */
	T("20 00 80 f9", TEXT_OTHER),					/* prfm pldl1keep, [x1] */
	T("bf 3b 03 d5", TEXT_OTHER),					/* dmb ish */
	/* The brk of BUG() has no next instruction. No return value passes a brk, like ud2 */
	T("00 00 21 d4", TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* brk #0x800 */
	T("80 d0 38 d5", TEXT_OTHER, .defs = BIT(0)),			/* mrs x0, tpidr_el1 */
	T("80 d0 18 d5", TEXT_OTHER),					/* msr tpidr_el1, x0 */
	T("20 fc 9f 08", TEXT_OTHER),					/* stlrb w0, [x1] */
	T("20 fc 9f 88", TEXT_OTHER),					/* stlr w0, [x1] */
	T("20 7c 5f 88", TEXT_OTHER, .defs = BIT(0)),			/* ldxr w0, [x1] */
	T("20 7c 5f c8", TEXT_OTHER, .defs = BIT(0)),			/* ldxr x0, [x1] */
	T("41 7c 00 88", TEXT_OTHER, .defs = BIT(0)),			/* stxr w0, w1, [x2] */
	T("41 7c 00 c8", TEXT_OTHER, .defs = BIT(0)),			/* stxr w0, x1, [x2] */
	T("41 fc 00 88", TEXT_OTHER, .defs = BIT(0)),			/* stlxr w0, w1, [x2] */
	T("41 fc 00 c8", TEXT_OTHER, .defs = BIT(0)),			/* stlxr w0, x1, [x2] */
	/* hasUnmodeledSideEffects() */
	T("02 00 00 d4", TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* hvc #0 */
	/* A write of these which is missed would change the errors of a function in some kernel */
	T("20 00 a0 52", TEXT_OTHER, .defs = BIT(0)),			/* mov w0, #0x10000 */
	T("20 78 1d 12", TEXT_OTHER, .defs = BIT(0)),			/* and w0, w1, #0xfffffffb */
	T("00 01 09 8a", TEXT_OTHER, .defs = BIT(0)),			/* and x0, x8, x9 */
	T("00 01 09 6a", TEXT_OTHER, .defs = BIT(0)),			/* ands w0, w8, w9 */
	T("00 01 29 0a", TEXT_OTHER, .defs = BIT(0)),			/* bic w0, w8, w9 */
	T("20 00 00 32", TEXT_OTHER, .defs = BIT(0)),			/* orr w0, w1, #1 */
	T("20 04 00 11", TEXT_OTHER, .defs = BIT(0)),			/* add w0, w1, #1 */
	T("20 08 01 53", TEXT_OTHER, .defs = BIT(0)),			/* ubfx w0, w1, #1, #2 */
	T("20 00 40 f9", TEXT_OTHER, .defs = BIT(0)),			/* ldr x0, [x1] */
	T("20 00 40 b9", TEXT_OTHER, .defs = BIT(0)),			/* ldr w0, [x1] */
	T("20 c0 5f b8", TEXT_OTHER, .defs = BIT(0)),			/* ldur w0, [x1, #-4] */
	T("20 c0 9f b8", TEXT_OTHER, .defs = BIT(0)),			/* ldursw x0, [x1, #-4] */
	T("08 09 40 b8", TEXT_OTHER, .defs = BIT(8)),			/* ldtr w8, [x8] */
	/* What is read */
	T("20 00 01 91", TEXT_OTHER, .defs = BIT(0), .uses = BIT(1)),	/* add x0, x1, #0x40 */
	T("20 20 40 f9", TEXT_OTHER, .defs = BIT(0), .uses = BIT(1), .load = true),	/* ldr x0, [x1, #0x40] */
	T("20 00 00 b9", TEXT_OTHER, .uses = BIT(0) | BIT(1)),		/* str w0, [x1] */
	/* The control flow */
	T("10 00 00 14", TEXT_BRANCH, .imm = MC_TEST_ADDR + 0x40),	/* b */
	T("00 01 1f d6", TEXT_BRANCH),					/* br x8 */
	T("00 02 00 b4", TEXT_COND_BRANCH, .imm = MC_TEST_ADDR + 0x40),	/* cbz x0 */
	T("10 00 00 94", TEXT_CALL, .defs = BIT(30), .imm = MC_TEST_ADDR + 0x40),	/* bl */
	T("00 01 3f d6", TEXT_CALL, .defs = BIT(30)),			/* blr x8 */
	T("c0 03 5f d6", TEXT_RETURN),					/* ret */
	T("e0 03 9f d6", TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* eret */
	{}
};

const struct mc_arch mc_arch = {
	.arch = {
		.retval = 0,
		.args = { 0, 1, 2, 3, 4, 5, 6, 7 },
		.nr_args = 8,
		.even_reg_align = true,
		/* AAPCS64: x0 to x18 and x30 */
		.caller_saved = 0x4007ffff,
	},
	.machine = EM_AARCH64,
	.triple = "aarch64-unknown-linux-gnu",
	.features = "+all",
	.regs = "X0 X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18 X19 X20 "
		"X21 X22 X23 X24 X25 X26 X27 X28 FP LR",
	.regs32 = "W0 W1 W2 W3 W4 W5 W6 W7 W8 W9 W10 W11 W12 W13 W14 W15 W16 W17 W18 W19 W20 "
		  "W21 W22 W23 W24 W25 W26 W27 W28 W29 W30",
	.zero_regs = "WZR XZR",
	.patterns = arm64_patterns,
	.tests = arm64_tests,
};
