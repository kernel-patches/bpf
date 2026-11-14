// SPDX-License-Identifier: GPL-2.0-only
/* x86-64 for text_mc.cpp */

#include <elf.h>
#include <linux/bits.h>

#include "text_mc.h"

enum { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11 };

#define I	MC_IMPLICIT

static const struct mc_pattern x86_patterns[] = {
	/* A 64-bit immediate, MOV64ri, may be a runtime constant, which the kernel patches */
	{ "MOV32ri",		TEXT_MOV_IMM, .imm = 1 },
	{ "MOV64ri32",		TEXT_MOV_IMM, .imm = 1 },
	{ "OR32ri8",		TEXT_MOV_IMM, .imm = 2, .predicates = { IMM(2, -1) } },
	{ "OR64ri8",		TEXT_MOV_IMM, .imm = 2, .predicates = { IMM(2, -1) } },
	{ "MOV32rr",		TEXT_MOV, .src = 1 },
	{ "MOV64rr",		TEXT_MOV, .src = 1 },
	{ "MOVSX64rr32",	TEXT_SEXT32, .src = 1 },
	{ "CDQE",		TEXT_SEXT32, .dst = I, .src = I },
	{ "CMOV32rr",		TEXT_SELECT, .src = 2, .src2 = 1 },
	{ "CMOV64rr",		TEXT_SELECT, .src = 2, .src2 = 1 },
	/* All bits of the result are equal */
	{ "SBB32rr",		TEXT_MOV_IMM, VALUE(-1), .or_zero = true, .predicates = { SAME_REG(1, 2) } },
	{ "SBB64rr",		TEXT_MOV_IMM, VALUE(-1), .or_zero = true, .predicates = { SAME_REG(1, 2) } },
	{ "SAR32ri",		TEXT_MOV_IMM, VALUE(-1), .or_zero = true, .predicates = { IMM(2, 31) } },
	{ "AND32ri8",		TEXT_ALU_IMM, .src = 1, .imm = 2, .op = TEXT_AND },
	{ "AND64ri8",		TEXT_ALU_IMM, .src = 1, .imm = 2, .op = TEXT_AND },
	{ "SUB32ri8",		TEXT_ALU_IMM, .src = 1, .imm = 2, .op = TEXT_SUB },
	{ "SUB64ri8",		TEXT_ALU_IMM, .src = 1, .imm = 2, .op = TEXT_SUB },
	{ "NOT32r",		TEXT_ALU_IMM, .src = 1, .op = TEXT_XOR, VALUE(-1) },
	{ "LOCK_PREFIX",	TEXT_OTHER },
	{ "NOOPL",		TEXT_OTHER, .nop = true },
	/* A rep prefix is not a part of the MCInst */
	{ "STOSQ",		TEXT_OTHER, .defs = BIT(RCX) },
	{ "RET64",		TEXT_RETURN },
	{}
};

#define T(code, insn_kind, ...)	{ code, { .kind = insn_kind, __VA_ARGS__ } }
#define IMMS(a, b)		.imm = a, .imm2 = b
#define SRC(reg)		.src = reg, .src2 = reg

/* Each pattern, and what must not match it */
static const struct mc_test x86_tests[] = {
	T("b8 ea ff ff ff",	  TEXT_MOV_IMM, .is32 = true, IMMS(0xffffffea, 0xffffffea)), /* mov $-22, %eax */
	T("48 c7 c3 ea ff ff ff", TEXT_MOV_IMM, .dst = RBX, IMMS(-22, -22)),	/* mov $-22, %rbx */
	T("83 c8 ff",		  TEXT_MOV_IMM, .is32 = true, IMMS(0xffffffff, 0xffffffff)), /* or $-1, %eax */
	T("48 83 c8 ff",	  TEXT_MOV_IMM, IMMS(-1, -1)),			/* or $-1, %rax */
	T("83 c8 f0",		  TEXT_OTHER, .defs = BIT(RAX)),		/* or $-16, %eax */
	T("48 83 c8 f0",	  TEXT_OTHER, .defs = BIT(RAX)),		/* or $-16, %rax */
	T("19 c0",		  TEXT_MOV_IMM, .is32 = true, IMMS(0xffffffff, 0)),	/* sbb %eax, %eax */
	T("48 19 c0",		  TEXT_MOV_IMM, IMMS(-1, 0)),			/* sbb %rax, %rax */
	T("19 d8",		  TEXT_OTHER, .defs = BIT(RAX)),		/* sbb %ebx, %eax */
	T("48 19 d8",		  TEXT_OTHER, .defs = BIT(RAX)),		/* sbb %rbx, %rax */
	T("c1 f8 1f",		  TEXT_MOV_IMM, .is32 = true, IMMS(0xffffffff, 0)),	/* sar $31, %eax */
	T("c1 f8 1e",		  TEXT_OTHER, .defs = BIT(RAX)),		/* sar $30, %eax */
	T("89 d8",		  TEXT_MOV, .is32 = true, SRC(RBX)),		/* mov %ebx, %eax */
	T("4c 89 e0",		  TEXT_MOV, SRC(12)),				/* mov %r12, %rax */
	T("48 63 c3",		  TEXT_SEXT32, SRC(RBX)),			/* movslq %ebx, %rax */
	T("48 98",		  TEXT_SEXT32, SRC(RAX)),			/* cltq */
	T("0f 44 c3",		  TEXT_SELECT, .is32 = true, .src = RBX, .src2 = RAX),	/* cmove %ebx, %eax */
	T("48 0f 44 c3",	  TEXT_SELECT, .src = RBX, .src2 = RAX),	/* cmove %rbx, %rax */
	T("83 e3 f2",		  TEXT_ALU_IMM, .is32 = true, .dst = RBX, SRC(RBX), .op = TEXT_AND, IMMS(0xfffffff2, 0xfffffff2)), /* and $-14, %ebx */
	T("48 83 e3 f2",	  TEXT_ALU_IMM, .dst = RBX, SRC(RBX), .op = TEXT_AND, IMMS(-14, -14)),	/* and $-14, %rbx */
	T("83 eb 0e",		  TEXT_ALU_IMM, .is32 = true, .dst = RBX, SRC(RBX), .op = TEXT_SUB, IMMS(14, 14)), /* sub $14, %ebx */
	T("48 83 eb 0e",	  TEXT_ALU_IMM, .dst = RBX, SRC(RBX), .op = TEXT_SUB, IMMS(14, 14)),	/* sub $14, %rbx */
	T("f7 d0",		  TEXT_ALU_IMM, .is32 = true, .op = TEXT_XOR, IMMS(0xffffffff, 0xffffffff)), /* not %eax */
	T("f0",			  TEXT_OTHER),					/* lock */
	T("0f 1f 44 00 00",	  TEXT_OTHER, .nop = true),			/* nopl 0x0(%rax,%rax,1) */
	T("f3 48 ab",		  TEXT_OTHER, .defs = BIT(RCX) | BIT(RDI)),	/* rep stosq */
	/* hasUnmodeledSideEffects() */
	T("f3 48 a5",		  TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* rep movsq */
	T("0f 05",		  TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* syscall */
	T("0f 0b",		  TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* ud2 */
	/* A write of these which is missed would change the errors of a function in some kernel */
	T("31 d8",		  TEXT_OTHER, .defs = BIT(RAX)),		/* xor %ebx, %eax */
	T("8b 03",		  TEXT_OTHER, .defs = BIT(RAX)),		/* mov (%rbx), %eax */
	T("48 8b 03",		  TEXT_OTHER, .defs = BIT(RAX)),		/* mov (%rbx), %rax */
	T("8d 04 1b",		  TEXT_OTHER, .defs = BIT(RAX)),		/* lea (%rbx,%rbx), %eax */
	T("03 03",		  TEXT_OTHER, .defs = BIT(RAX)),		/* add (%rbx), %eax */
	T("83 c0 10",		  TEXT_OTHER, .defs = BIT(RAX)),		/* add $16, %eax */
	T("48 83 c0 10",	  TEXT_OTHER, .defs = BIT(RAX)),		/* add $16, %rax */
	T("05 00 01 00 00",	  TEXT_OTHER, .defs = BIT(RAX)),		/* add $256, %eax */
	T("81 c3 00 01 00 00",	  TEXT_OTHER, .defs = BIT(RBX)),		/* add $256, %ebx */
	T("48 81 c3 00 01 00 00", TEXT_OTHER, .defs = BIT(RBX)),		/* add $256, %rbx */
	T("29 d8",		  TEXT_OTHER, .defs = BIT(RAX)),		/* sub %ebx, %eax */
	T("21 d8",		  TEXT_OTHER, .defs = BIT(RAX)),		/* and %ebx, %eax */
	T("25 00 01 00 00",	  TEXT_OTHER, .defs = BIT(RAX)),		/* and $256, %eax */
	T("81 e3 00 01 00 00",	  TEXT_OTHER, .defs = BIT(RBX)),		/* and $256, %ebx */
	T("48 81 e3 00 01 00 00", TEXT_OTHER, .defs = BIT(RBX)),		/* and $256, %rbx */
	T("09 d8",		  TEXT_OTHER, .defs = BIT(RAX)),		/* or %ebx, %eax */
	T("48 63 03",		  TEXT_OTHER, .defs = BIT(RAX)),		/* movslq (%rbx), %rax */
	T("48 c1 e8 02",	  TEXT_OTHER, .defs = BIT(RAX)),		/* shr $2, %rax */
	T("48 c1 f8 3f",	  TEXT_OTHER, .defs = BIT(RAX)),		/* sar $63, %rax */
	T("0f 44 0b",		  TEXT_OTHER, .defs = BIT(RCX)),		/* cmove (%rbx), %ecx */
	T("48 0f 44 0b",	  TEXT_OTHER, .defs = BIT(RCX)),		/* cmove (%rbx), %rcx */
	T("83 d8 00",		  TEXT_OTHER, .defs = BIT(RAX)),		/* sbb $0, %eax */
	T("83 d0 00",		  TEXT_OTHER, .defs = BIT(RAX)),		/* adc $0, %eax */
	T("0f bd c3",		  TEXT_OTHER, .defs = BIT(RAX)),		/* bsr %ebx, %eax */
	T("48 0f bd c3",	  TEXT_OTHER, .defs = BIT(RAX)),		/* bsr %rbx, %rax */
	T("80 e3 01",		  TEXT_OTHER, .defs = BIT(RBX)),		/* and $1, %bl */
	T("48 0f c1 13",	  TEXT_OTHER, .defs = BIT(RDX)),		/* xadd %rdx, (%rbx) */
	/* The control flow */
	T("eb 10",		  TEXT_BRANCH, .imm = MC_TEST_ADDR + 0x12),	/* jmp */
	T("ff e0",		  TEXT_BRANCH),					/* jmp *%rax */
	T("0f 84 00 01 00 00",	  TEXT_COND_BRANCH, .imm = MC_TEST_ADDR + 0x106), /* je */
	T("e8 00 01 00 00",	  TEXT_CALL, .imm = MC_TEST_ADDR + 0x105),	/* call */
	T("c3",			  TEXT_RETURN),					/* ret */
	T("48 cf",		  TEXT_OTHER, .defs = TEXT_ALL_REGS),		/* iretq */
	{}
};

const struct mc_arch mc_arch = {
	.arch = {
		.retval = RAX,
		.caller_saved = BIT(RAX) | BIT(RCX) | BIT(RDX) | BIT(RSI) | BIT(RDI) |
				BIT(R8) | BIT(R9) | BIT(R10) | BIT(R11),
		.return_thunk = "__x86_return_thunk",
		.entry_hook = "__fentry__",
	},
	.machine = EM_X86_64,
	.triple = "x86_64-unknown-linux-gnu",
	.features = "",
	.regs = "RAX RCX RDX RBX RSP RBP RSI RDI R8 R9 R10 R11 R12 R13 R14 R15",
	.regs32 = "EAX ECX EDX EBX ESP EBP ESI EDI R8D R9D R10D R11D R12D R13D R14D R15D",
	.patterns = x86_patterns,
	.tests = x86_tests,
};
