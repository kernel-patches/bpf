// SPDX-License-Identifier: GPL-2.0-only
/*
 * Just-In-Time compiler for eBPF bytecode on MIPS I-V and MIPS32.
 *
 * Copyright (c) 2021 Anyfi Networks AB.
 * Author: Johan Almbladh <johan.almbladh@gmail.com>
 *
 * Based on code and ideas from
 * Copyright (c) 2017 Cavium, Inc.
 * Copyright (c) 2017 Shubham Bansal <illusionist.neo@gmail.com>
 * Copyright (c) 2011 Mircea Gherzan <mgherzan@gmail.com>
 */

#include <linux/bitops.h>
#include <linux/math64.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/slab.h>
#include <asm/bitops.h>
#include <asm/cacheflush.h>
#include <asm/cpu-features.h>
#include <asm/isa-rev.h>
#include <asm/uasm.h>

/* MIPS 32-bit registers */
#define MIPS_R_ZERO	0   /* Const zero */
#define MIPS_R_AT	1   /* Asm temp   */
#define MIPS_R_V0	2   /* Result     */
#define MIPS_R_V1	3   /* Result     */
#define MIPS_R_A0	4   /* Argument   */
#define MIPS_R_A1	5   /* Argument   */
#define MIPS_R_A2	6   /* Argument   */
#define MIPS_R_A3	7   /* Argument   */
#define MIPS_R_T0	8   /* Temporary  */
#define MIPS_R_T1	9   /* Temporary  */
#define MIPS_R_T2	10  /* Temporary  */
#define MIPS_R_T3	11  /* Temporary  */
#define MIPS_R_T4	12  /* Temporary  */
#define MIPS_R_T5	13  /* Temporary  */
#define MIPS_R_T6	14  /* Temporary  */
#define MIPS_R_T7	15  /* Temporary  */
#define MIPS_R_S0	16  /* Saved      */
#define MIPS_R_S1	17  /* Saved      */
#define MIPS_R_S2	18  /* Saved      */
#define MIPS_R_S3	19  /* Saved      */
#define MIPS_R_S4	20  /* Saved      */
#define MIPS_R_S5	21  /* Saved      */
#define MIPS_R_S6	22  /* Saved      */
#define MIPS_R_S7	23  /* Saved      */
#define MIPS_R_T8	24  /* Temporary  */
#define MIPS_R_T9	25  /* Temporary  */
/*      MIPS_R_K0	26     Reserved   */
/*      MIPS_R_K1	27     Reserved   */
#define MIPS_R_GP	28  /* Global ptr */
#define MIPS_R_SP	29  /* Stack ptr  */
#define MIPS_R_FP	30  /* Frame ptr  */
#define MIPS_R_RA	31  /* Return     */

/* Stack is 8-byte aligned in O32 ABI */
#define MIPS_STACK_ALIGNMENT 8

/*
 * Jump address mask for immediate jumps. The four most significant bits
 * must be equal to PC.
 */
#define MIPS_JMP_MASK 0x0fffffff

/* Maximum number of iterations in offset table computation */
#define JIT_MAX_ITERATIONS 64

/* Jump pseudo-instruction used internally */
#define JIT_JNSET 0xf0

/* Temporary 64-bit registers used by JIT */
#define JIT_REG_T0 (MAX_BPF_JIT_REG + 0)
#define JIT_REG_T1 (MAX_BPF_JIT_REG + 1)

/*
 * Number of prologue bytes to skip when doing a tail call.
 * Tail call count (TCC) initialization (8 bytes) always, plus
 * R0-to-v0 assignment (4 bytes) if big endian.
 */
#ifdef __BIG_ENDIAN
#define JIT_TCALL_SKIP 12
#else
#define JIT_TCALL_SKIP 8
#endif

/*
 * The top 16 bytes of a stack frame is reserved for the callee.
 * This corresponds to stack space for register arguments a0-a3.
 */
#define JIT_RESERVED_STACK 16

/* CPU registers holding the callee return value */
#define JIT_RETURN_REGS	  \
	(BIT(MIPS_R_V0) | \
	 BIT(MIPS_R_V1))

/* CPU registers arguments passed to callee directly */
#define JIT_ARG_REGS      \
	(BIT(MIPS_R_A0) | \
	 BIT(MIPS_R_A1) | \
	 BIT(MIPS_R_A2) | \
	 BIT(MIPS_R_A3))

/* CPU register arguments passed to callee on stack */
#define JIT_STACK_REGS    \
	(BIT(MIPS_R_T0) | \
	 BIT(MIPS_R_T1) | \
	 BIT(MIPS_R_T2) | \
	 BIT(MIPS_R_T3) | \
	 BIT(MIPS_R_T4) | \
	 BIT(MIPS_R_T5))

/* Caller-saved CPU registers */
#define JIT_CALLER_REGS    \
	(JIT_RETURN_REGS | \
	 JIT_ARG_REGS    | \
	 JIT_STACK_REGS)

/* Callee-saved CPU registers */
#define JIT_CALLEE_REGS   \
	(BIT(MIPS_R_S0) | \
	 BIT(MIPS_R_S1) | \
	 BIT(MIPS_R_S2) | \
	 BIT(MIPS_R_S3) | \
	 BIT(MIPS_R_S4) | \
	 BIT(MIPS_R_S5) | \
	 BIT(MIPS_R_S6) | \
	 BIT(MIPS_R_S7) | \
	 BIT(MIPS_R_GP) | \
	 BIT(MIPS_R_FP) | \
	 BIT(MIPS_R_RA))

/*
 * Mapping of 64-bit eBPF registers to 32-bit native MIPS registers.
 *
 * 1) Native register pairs are ordered according to CPU endiannes, following
 *    the MIPS convention for passing 64-bit arguments and return values.
 * 2) The eBPF return value, arguments and callee-saved registers are mapped
 *    to their native MIPS equivalents.
 * 3) Since the 32 highest bits in the eBPF FP register are always zero,
 *    only one general-purpose register is actually needed for the mapping.
 *    We use the fp register for this purpose, and map the highest bits to
 *    the MIPS register r0 (zero).
 * 4) We use the MIPS gp and at registers as internal temporary registers
 *    for constant blinding. The gp register is callee-saved.
 * 5) Two 64-bit temporary registers are available for use when performing
 *    more complex operations.
 *
 * With this scheme all eBPF registers are being mapped to native MIPS
 * registers without having to use any stack scratch space. The direct
 * register mapping (2) simplifies the handling of function calls.
 */
static const u8 bpf2mips32[][2] = {
	/* Return value from in-kernel function, and exit value from eBPF */
	[BPF_REG_0] = {MIPS_R_V1, MIPS_R_V0},
	/* Arguments from eBPF program to in-kernel function */
	[BPF_REG_1] = {MIPS_R_A1, MIPS_R_A0},
	[BPF_REG_2] = {MIPS_R_A3, MIPS_R_A2},
	/* Remaining arguments, to be passed on the stack per O32 ABI */
	[BPF_REG_3] = {MIPS_R_T1, MIPS_R_T0},
	[BPF_REG_4] = {MIPS_R_T3, MIPS_R_T2},
	[BPF_REG_5] = {MIPS_R_T5, MIPS_R_T4},
	/* Callee-saved registers that in-kernel function will preserve */
	[BPF_REG_6] = {MIPS_R_S1, MIPS_R_S0},
	[BPF_REG_7] = {MIPS_R_S3, MIPS_R_S2},
	[BPF_REG_8] = {MIPS_R_S5, MIPS_R_S4},
	[BPF_REG_9] = {MIPS_R_S7, MIPS_R_S6},
	/* Read-only frame pointer to access the eBPF stack */
#ifdef __BIG_ENDIAN
	[BPF_REG_FP] = {MIPS_R_FP, MIPS_R_ZERO},
#else
	[BPF_REG_FP] = {MIPS_R_ZERO, MIPS_R_FP},
#endif
	/* Temporary register for blinding constants */
	[BPF_REG_AX] = {MIPS_R_GP, MIPS_R_AT},
	/* Temporary registers for internal JIT use */
	[JIT_REG_T0] = {MIPS_R_T7, MIPS_R_T6},
	[JIT_REG_T1] = {MIPS_R_T9, MIPS_R_T8},
};

/* JIT descriptor for an eBPF instruction */
struct jit_desc {
	u32 convert : 1;   /* PC-relative branch converted to absolute jump */
	u32 offset : 31;   /* Index of (first) native instruction generated */
};

/* JIT context for an eBPF program */
struct jit_context {
	struct bpf_prog *program;       /* The eBPF program being JITed     */
	struct jit_desc *descriptors;   /* Per-eBPF insn offset descriptors */
	u32 *target;           /* JITed code buffer                         */
	u32 bpf_index;         /* Index of current BPF program instruction  */
	u32 jit_index;         /* Index of current JIT target instruction   */
	u32 changes;           /* Number of PC-relative branch conversions  */
	u32 clobbered;         /* Bit mask of clobbered callee-saved regs   */
	u32 stack_size;        /* Total allocated stack size in bytes       */
	u32 saved_size;        /* Total size of callee-saved registers      */
	u32 stack_used;        /* Total stack size used for function calls  */
};

/* Simply emit the instruction if the JIT memory space has been allocated */
#define emit(ctx, func, ...)					\
do {								\
	if ((ctx)->target != NULL) {				\
		u32 *p = &(ctx)->target[ctx->jit_index];	\
		uasm_i_##func(&p, ##__VA_ARGS__);		\
	}							\
	(ctx)->jit_index++;					\
} while (0)

/* Get low CPU register for a 64-bit eBPF register mapping */
static inline u8 lo(const u8 reg[])
{
#ifdef __BIG_ENDIAN
	return reg[0];
#else
	return reg[1];
#endif
}

/* Get high CPU register for a 64-bit eBPF register mapping */
static inline u8 hi(const u8 reg[])
{
#ifdef __BIG_ENDIAN
	return reg[1];
#else
	return reg[0];
#endif
}

/* Test if a value is within the signed 16-bit range */
static inline bool is_16bit(int value)
{
	return value >= -0x8000 && value <= 0x7fff;
}

/* Test if a value is within the signed 18-bit range */
static inline bool is_18bit(int value)
{
	return value >= -0x20000 && value <= 0x1ffff;
}

/*
 * Mark a 32-bit CPU register as clobbered, it needs to be
 * saved/restored by the program if callee-saved.
 */
static void clobber_reg(struct jit_context *ctx, u8 reg)
{
	ctx->clobbered |= BIT(reg);
}

/*
 * Mark a 64-bit CPU register pair as clobbered, it needs to be
 * saved/restored by the program if callee-saved.
 */
static void clobber_reg64(struct jit_context *ctx, const u8 reg[])
{
	clobber_reg(ctx, reg[0]);
	clobber_reg(ctx, reg[1]);
}

/*
 * Push registers on the stack, starting at a given depth from the stack
 * pointer and increasing. The next depth to be written is returned.
 */
static int push_regs(struct jit_context *ctx, u32 mask, u32 excl, int depth)
{
	int reg;

	for (reg = 0; reg < BITS_PER_BYTE * sizeof(u32); reg++)
		if (mask & BIT(reg)) {
			if ((excl & BIT(reg)) == 0)
				emit(ctx, sw, reg, depth, MIPS_R_SP);
			depth += sizeof(u32);
		}

	ctx->stack_used = max((int)ctx->stack_used, depth);
	return depth;
}

/*
 * Pop registers from the stack, starting at a given depth from the stack
 * pointer and increasing. The next depth to be read is returned.
 */
static int pop_regs(struct jit_context *ctx, u32 mask, u32 excl, int depth)
{
	int reg;

	for (reg = 0; reg < BITS_PER_BYTE * sizeof(u32); reg++)
		if (mask & BIT(reg)) {
			if ((excl & BIT(reg)) == 0)
				emit(ctx, lw, reg, depth, MIPS_R_SP);
			depth += sizeof(u32);
		}

	return depth;
}

/* Compute the 28-bit jump target address from a BPF program location */
static int get_target(struct jit_context *ctx, u32 loc)
{
	u32 offset = ctx->descriptors[loc].offset;
	u32 addr = (u32)&ctx->target[offset];
	u32 pc = (u32)&ctx->target[ctx->jit_index];

	if (!ctx->target)
		return 0;

	if ((addr ^ pc) & ~MIPS_JMP_MASK)
		return -1;

	return addr & MIPS_JMP_MASK;
}

/* Compute the PC-relative offset to relative BPF program offset */
static inline int get_offset(const struct jit_context *ctx, int off)
{
	return (ctx->descriptors[ctx->bpf_index + 1].offset -
		ctx->jit_index - 1) * sizeof(u32);
}

/* Build program prologue to set up the stack and registers */
static void build_prologue(struct jit_context *ctx)
{
	const u8 *r1 = bpf2mips32[BPF_REG_1];
	int stack, saved, locals, reserved;

	/*
	 * The first two instructions initialize TCC in the reserved (for us)
	 * 16-byte area in the parent's stack frame. On a tail call, the
	 * calling function jumps into the prologue after these instructions.
	 */
	emit(ctx, ori, MIPS_R_T9, MIPS_R_ZERO, min(MAX_TAIL_CALL_CNT, 0xffff));
	emit(ctx, sw, MIPS_R_T9, 0, MIPS_R_SP);

	/*
	 * Register eBPF R1 contains the 32-bit context pointer argument.
	 * A 32-bit argument is always passed in MIPS register a0, regardless
	 * of CPU endianness. Initalize R1 accordingly and zero-extend.
	 */
#ifdef __BIG_ENDIAN
	emit(ctx, addiu, lo(r1), MIPS_R_A0, 0);
#endif

	/* === Entry-point for tail calls === */

	/* Zero-extend the 32-bit argument */
	emit(ctx, addiu, hi(r1), MIPS_R_ZERO, 0);

	/* Compute the stack space needed for callee-saved registers */
	saved = hweight32(ctx->clobbered & JIT_CALLEE_REGS) * sizeof(u32);
	saved = ALIGN(saved, MIPS_STACK_ALIGNMENT);

	/* Stack space used by eBPF program local data */
	locals = ALIGN(ctx->program->aux->stack_depth, MIPS_STACK_ALIGNMENT);

	/*
	 * If we are emitting function calls, reserve extra stack space for
	 * caller-saved registers and function arguments passed on the stack.
	 * The required space is computed automatically during resource
	 * usage discovery (pass 1).
	 */
	reserved = ctx->stack_used;

	/* Allocate the stack frame */
	stack = ALIGN(saved + locals + reserved, MIPS_STACK_ALIGNMENT);
	emit(ctx, addiu, MIPS_R_SP, MIPS_R_SP, -stack);

	/* Store callee-saved registers on stack */
	push_regs(ctx, ctx->clobbered & JIT_CALLEE_REGS, 0, stack - saved);

	/* Set up the eBPF stack pointer */
	emit(ctx, addiu, MIPS_R_FP, MIPS_R_SP, stack - saved);
	ctx->saved_size = saved;
	ctx->stack_size = stack;
}

/* Build the program epilogue to restore the stack and registers */
static void build_epilogue(struct jit_context *ctx, int dest_reg)
{
	/* Restore callee-saved registers from stack */
	pop_regs(ctx, ctx->clobbered & JIT_CALLEE_REGS, 0,
		 ctx->stack_size - ctx->saved_size);
	/*
	 * A 32-bit return value is always passed in MIPS register v0,
	 * but on big-endian targets the low part of R0 is mapped to v1.
	 */
#ifdef __BIG_ENDIAN
	emit(ctx, addiu, MIPS_R_V0, MIPS_R_V1, 0);
#endif

	/* Jump to the return address and adjust the stack pointer */
	emit(ctx, jr, dest_reg);
	emit(ctx, addiu, MIPS_R_SP, MIPS_R_SP, ctx->stack_size);
}

/* dst = imm (4 bytes) */
static inline void emit_mov_i(struct jit_context *ctx, u8 dst, s32 imm)
{
	if (is_16bit(imm)) {
		emit(ctx, addiu, dst, MIPS_R_ZERO, imm);
	} else {
		emit(ctx, lui, dst, (s16)((u32)imm >> 16));
		emit(ctx, ori, dst, dst, (u16)(imm & 0xffff));
	}
	clobber_reg(ctx, dst);
}

/* dst = src (4 bytes) */
static inline void emit_mov_r(struct jit_context *ctx, u8 dst, u8 src)
{
	emit(ctx, addiu, dst, src, 0);
	clobber_reg(ctx, dst);
}

/* dst = imm (sign-extended) */
static inline void emit_mov_se_i64(struct jit_context *ctx,
				   const u8 dst[], s32 imm)
{
	emit_mov_i(ctx, lo(dst), imm);
	if (imm < 0)
		emit(ctx, addiu, hi(dst), MIPS_R_ZERO, -1);
	else
		emit(ctx, addiu, hi(dst), MIPS_R_ZERO, 0);
	clobber_reg64(ctx, dst);
}

/* dst = 0 */
static inline void emit_zext(struct jit_context *ctx, u8 dst)
{
	if (!ctx->program->aux->verifier_zext)
		emit_mov_i(ctx, dst, 0);
}

/* ALU register operation (32 bit) */
static inline void emit_alu_r(struct jit_context *ctx, u8 dst, u8 src, u8 op)
{
	switch (BPF_OP(op)) {
	/* dst = dst + src */
	case BPF_ADD:
		emit(ctx, addu, dst, dst, src);
		break;
	/* dst = dst - src */
	case BPF_SUB:
		emit(ctx, subu, dst, dst, src);
		break;
	/* dst = dst | src */
	case BPF_OR:
		emit(ctx, or, dst, dst, src);
		break;
	/* dst = dst & src */
	case BPF_AND:
		emit(ctx, and, dst, dst, src);
		break;
	/* dst = dst ^ src */
	case BPF_XOR:
		emit(ctx, xor, dst, dst, src);
		break;
	/* dst = dst * src */
	case BPF_MUL:
		if (cpu_has_mips32r1) {
			emit(ctx, mul, dst, dst, src);
		} else {
			emit(ctx, multu, dst, src);
			emit(ctx, mflo, dst);
		}
		break;
	/* dst = dst << src */
	case BPF_LSH:
		emit(ctx, sllv, dst, dst, src);
		break;
	/* dst = dst >> src */
	case BPF_RSH:
		emit(ctx, srlv, dst, dst, src);
		break;
	/* dst = dst >> src (arithmetic) */
	case BPF_ARSH:
		emit(ctx, srav, dst, dst, src);
		break;
	}
	clobber_reg(ctx, dst);
}

/* ALU immediate operation (32 bit) */
static inline void emit_alu_i(struct jit_context *ctx, u8 dst, s16 imm, u8 op)
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	switch (BPF_OP(op)) {
	/* dst = -dst */
	case BPF_NEG:
		emit(ctx, subu, dst, MIPS_R_ZERO, dst);
		break;
	/* dst = dst + imm */
	case BPF_ADD:
		emit(ctx, addiu, dst, dst, imm);
		break;
	/* dst = dst - imm */
	case BPF_SUB:
		emit(ctx, addiu, dst, dst, -imm);
		break;
	/* dst = dst | imm */
	case BPF_OR:
		emit(ctx, ori, dst, dst, (u16)imm);
		break;
	/* dst = dst & imm */
	case BPF_AND:
		emit(ctx, andi, dst, dst, (u16)imm);
		break;
	/* dst = dst ^ imm */
	case BPF_XOR:
		emit(ctx, xori, dst, dst, (u16)imm);
		break;
	/* dst = dst * imm */
	case BPF_MUL:
		emit_mov_i(ctx, tmp, imm);
		if (cpu_has_mips32r1) {
			emit(ctx, mul, dst, dst, tmp);
		} else {
			emit(ctx, multu, dst, tmp);
			emit(ctx, mflo, dst);
		}
		break;
	/* dst = dst << imm */
	case BPF_LSH:
		emit(ctx, sll, dst, dst, imm);
		break;
	/* dst = dst >> imm */
	case BPF_RSH:
		emit(ctx, srl, dst, dst, imm);
		break;
	/* dst = dst >> imm (arithmetic) */
	case BPF_ARSH:
		emit(ctx, sra, dst, dst, imm);
		break;
	}
	clobber_reg(ctx, dst);
}

/* ALU register operation (64 bit) */
static inline void emit_alu_r64(struct jit_context *ctx,
				const u8 dst[], const u8 src[], u8 op)
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	switch (BPF_OP(op)) {
	/* dst = dst + src */
	case BPF_ADD:
		emit(ctx, addu, lo(dst), lo(dst), lo(src));
		emit(ctx, sltu, tmp, lo(dst), lo(src));
		emit(ctx, addu, hi(dst), hi(dst), hi(src));
		emit(ctx, addu, hi(dst), hi(dst), tmp);
		break;
	/* dst = dst - src */
	case BPF_SUB:
		emit(ctx, sltu, tmp, lo(dst), lo(src));
		emit(ctx, subu, lo(dst), lo(dst), lo(src));
		emit(ctx, subu, hi(dst), hi(dst), hi(src));
		emit(ctx, subu, hi(dst), hi(dst), tmp);
		break;
	/* dst = dst | src */
	case BPF_OR:
		emit(ctx, or, lo(dst), lo(dst), lo(src));
		emit(ctx, or, hi(dst), hi(dst), hi(src));
		break;
	/* dst = dst & src */
	case BPF_AND:
		emit(ctx, and, lo(dst), lo(dst), lo(src));
		emit(ctx, and, hi(dst), hi(dst), hi(src));
		break;
	/* dst = dst ^ src */
	case BPF_XOR:
		emit(ctx, xor, lo(dst), lo(dst), lo(src));
		emit(ctx, xor, hi(dst), hi(dst), hi(src));
		break;
	}
	clobber_reg64(ctx, dst);
}

/* ALU invert (64 bit) */
static inline void emit_neg_i64(struct jit_context *ctx, const u8 dst[])
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	emit(ctx, sltu, tmp, MIPS_R_ZERO, lo(dst));
	emit(ctx, subu, lo(dst), MIPS_R_ZERO, lo(dst));
	emit(ctx, subu, hi(dst), MIPS_R_ZERO, hi(dst));
	emit(ctx, subu, hi(dst), hi(dst), tmp);

	clobber_reg64(ctx, dst);
}

/* ALU shift immediate (64 bit) */
static inline void emit_shift_i64(struct jit_context *ctx,
				  const u8 dst[], u32 imm, u8 op)
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	switch (BPF_OP(op)) {
	/* dst = dst << imm */
	case BPF_LSH:
		if (imm < 32) {
			emit(ctx, srl, tmp, lo(dst), 32 - imm);
			emit(ctx, sll, lo(dst), lo(dst), imm);
			emit(ctx, sll, hi(dst), hi(dst), imm);
			emit(ctx, or, hi(dst), hi(dst), tmp);
		} else {
			emit(ctx, sll, hi(dst), lo(dst), imm - 32);
			emit(ctx, addiu, lo(dst), MIPS_R_ZERO, 0);
		}
		break;
	/* dst = dst >> imm */
	case BPF_RSH:
		if (imm < 32) {
			emit(ctx, sll, tmp, hi(dst), 32 - imm);
			emit(ctx, srl, lo(dst), lo(dst), imm);
			emit(ctx, srl, hi(dst), hi(dst), imm);
			emit(ctx, or, lo(dst), lo(dst), tmp);
		} else {
			emit(ctx, srl, lo(dst), hi(dst), imm - 32);
			emit(ctx, addiu, hi(dst), MIPS_R_ZERO, 0);
		}
		break;
	/* dst = dst >> imm (arithmetic) */
	case BPF_ARSH:
		if (imm < 32) {
			emit(ctx, sll, tmp, hi(dst), 32 - imm);
			emit(ctx, srl, lo(dst), lo(dst), imm);
			emit(ctx, sra, hi(dst), hi(dst), imm);
			emit(ctx, or, lo(dst), lo(dst), tmp);
		} else {
			emit(ctx, sra, lo(dst), hi(dst), imm - 32);
			emit(ctx, sra, hi(dst), hi(dst), 31);
		}
		break;
	}
	clobber_reg64(ctx, dst);
}

/* ALU shift register (64 bit) */
static inline void emit_shift_r64(struct jit_context *ctx,
				  const u8 dst[], u8 src, u8 op)
{
	u8 t1 = bpf2mips32[JIT_REG_T1][0];
	u8 t2 = bpf2mips32[JIT_REG_T1][1];

	emit(ctx, andi, t1, src, 32);              /* t1 = src & 32          */
	emit(ctx, beqz, t1, 16);                   /* PC += 16 if t1 == 0    */
	emit(ctx, nor, t2, src, MIPS_R_ZERO);      /* t2 = ~src (delay slot) */

	switch (BPF_OP(op)) {
	/* dst = dst << src */
	case BPF_LSH:
		/* Next: shift >= 32 */
		emit(ctx, sllv, hi(dst), lo(dst), src);    /* dh = dl << src */
		emit(ctx, addiu, lo(dst), MIPS_R_ZERO, 0); /* dl = 0         */
		emit(ctx, b, 20);                          /* PC += 20       */
		/* +16: shift < 32 */
		emit(ctx, srl, t1, lo(dst), 1);            /* t1 = dl >> 1   */
		emit(ctx, srlv, t1, t1, t2);               /* t1 = t1 >> t2  */
		emit(ctx, sllv, lo(dst), lo(dst), src);    /* dl = dl << src */
		emit(ctx, sllv, hi(dst), hi(dst), src);    /* dh = dh << src */
		emit(ctx, or, hi(dst), hi(dst), t1);       /* dh = dh | t1   */
		break;
	/* dst = dst >> src */
	case BPF_RSH:
		/* Next: shift >= 32 */
		emit(ctx, srlv, lo(dst), hi(dst), src);    /* dl = dh >> src */
		emit(ctx, addiu, hi(dst), MIPS_R_ZERO, 0); /* dh = 0         */
		emit(ctx, b, 20);                          /* PC += 20       */
		/* +16: shift < 32 */
		emit(ctx, sll, t1, hi(dst), 1);            /* t1 = dl << 1   */
		emit(ctx, sllv, t1, t1, t2);               /* t1 = t1 << t2  */
		emit(ctx, srlv, lo(dst), lo(dst), src);    /* dl = dl >> src */
		emit(ctx, srlv, hi(dst), hi(dst), src);    /* dh = dh >> src */
		emit(ctx, or, lo(dst), lo(dst), t1);       /* dl = dl | t1   */
		break;
	/* dst = dst >> src (arithmetic) */
	case BPF_ARSH:
		/* Next: shift >= 32 */
		emit(ctx, srav, lo(dst), hi(dst), src);   /* dl = dh >>a src */
		emit(ctx, sra, hi(dst), hi(dst), 31);     /* dh = dh >>a 31  */
		emit(ctx, b, 20);                         /* PC += 20        */
		/* +16: shift < 32 */
		emit(ctx, sll, t1, hi(dst), 1);           /* t1 = dl << 1    */
		emit(ctx, sllv, t1, t1, t2);              /* t1 = t1 << t2   */
		emit(ctx, srlv, lo(dst), lo(dst), src);   /* dl = dl >>a src */
		emit(ctx, srav, hi(dst), hi(dst), src);   /* dh = dh >> src  */
		emit(ctx, or, lo(dst), lo(dst), t1);      /* dl = dl | t1    */
		break;
	}

	/* +20: Done */
	clobber_reg64(ctx, dst);
}

/* ALU mul register (64 bit) */
static inline void emit_mul_r64(struct jit_context *ctx,
				const u8 dst[], const u8 src[])
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	emit(ctx, multu, hi(dst), lo(src));       /* hi,lo = dh * sl  */
	emit(ctx, mflo, hi(dst));                 /* dh    = lo       */
	emit(ctx, multu, lo(dst), hi(src));       /* hi,lo = dl * sh  */
	emit(ctx, mflo, tmp);                     /* tmp   = lo       */
	emit(ctx, addu, hi(dst), hi(dst), tmp);   /* dh    = dh + tmp */
	emit(ctx, multu, lo(dst), lo(src));       /* hi,lo = dl * sl  */
	emit(ctx, mflo, lo(dst));                 /* dl    = lo       */
	emit(ctx, mfhi, tmp);                     /* tmp   = hi       */
	emit(ctx, addu, hi(dst), hi(dst), tmp);   /* dh    = dh + tmp */

	clobber_reg64(ctx, dst);
}

/* ALU div/mod register */
static inline void emit_divmod_r(struct jit_context *ctx,
				 u8 dst, u8 src, u8 op)
{
	emit(ctx, divu, dst, src);
	switch (BPF_OP(op)) {
	/* dst = dst / src */
	case BPF_DIV:
		emit(ctx, mflo, dst);
		break;
	/* dst = dst % src */
	case BPF_MOD:
		emit(ctx, mfhi, dst);
		break;
	}
	clobber_reg(ctx, dst);
}

/* Helper function for 64-bit modulo */
static u64 jit_mod64(u64 a, u64 b)
{
	u64 rem;
	div64_u64_rem(a, b, &rem);
	return rem;
}

/* Helper function for 64-bit atomic exchange */
static s64 jit_xchg64(s64 a, atomic64_t *v)
{
	return atomic64_xchg(v, a);
}

/* ALU div/mod register (64-bit) */
static void emit_divmod_r64(struct jit_context *ctx,
			    const u8 dst[], const u8 src[], u8 op)
{
	const u8 *r0 = bpf2mips32[BPF_REG_0]; /* Mapped to v0-v1 */
	const u8 *r1 = bpf2mips32[BPF_REG_1]; /* Mapped to a0-a1 */
	const u8 *r2 = bpf2mips32[BPF_REG_2]; /* Mapped to a2-a3 */
	u8 tmp = bpf2mips32[JIT_REG_T1][0];
	u32 addr = 0;
	int exclude, k;

	/* Push caller-saved registers on stack */
	push_regs(ctx, ctx->clobbered & JIT_CALLER_REGS,
		  0, JIT_RESERVED_STACK);

	/* Put 64-bit arguments 1 and 2 in registers a0-a3 */
	for (k = 0; k < 2; k++) {
		emit(ctx, addiu, tmp, src[k], 0);
		emit(ctx, addiu, r1[k], dst[k], 0);
		emit(ctx, addiu, r2[k], tmp, 0);
	}

	/* Emit function call */
	switch (BPF_OP(op)) {
	/* dst = dst / src */
	case BPF_DIV:
		addr = (u32)&div64_u64;
		break;
	/* dst = dst % src */
	case BPF_MOD:
		addr = (u32)&jit_mod64;
		break;
	}
	emit_mov_i(ctx, tmp, addr);
	emit(ctx, jalr, MIPS_R_RA, tmp);
	emit(ctx, nop); /* Delay slot */

	/* Store the 64-bit result in dst */
	emit(ctx, addiu, dst[0], r0[0], 0);
	emit(ctx, addiu, dst[1], r0[1], 0);

	/* Restore caller-saved registers, excluding the computed result */
	exclude = BIT(lo(dst)) | BIT(hi(dst));
	pop_regs(ctx, ctx->clobbered & JIT_CALLER_REGS,
		 exclude, JIT_RESERVED_STACK);

	clobber_reg64(ctx, dst);
	clobber_reg(ctx, MIPS_R_V0);
	clobber_reg(ctx, MIPS_R_V1);
	clobber_reg(ctx, MIPS_R_RA);
}

/* Byteswap (64-bit) */
static inline void emit_bswap_i64(struct jit_context *ctx,
				  const u8 dst[], u32 imm)
{
/* Load constant 0x00ff00ff in a register */
#define MASK8(ctx, mask)		\
	emit(ctx, lui, mask, 0xff);	\
	emit(ctx, ori, mask, mask, 0xff)

/* Swap bytes in a register word */
#define SWAP8(ctx, dst, src, mask, tmp)					\
	emit(ctx, and, tmp, src, mask); /* tmp = src & 0x00ff00ff */	\
	emit(ctx, sll, tmp, tmp, 8);    /* tmp = tmp << 8         */	\
	emit(ctx, srl, dst, src, 8);    /* dst = src >> 8         */	\
	emit(ctx, and, dst, dst, mask); /* dst = dst & 0x00ff00ff */	\
	emit(ctx, or,  dst, dst, tmp)   /* dst = dst | tmp        */

/* Swap half words in a register word */
#define SWAP16(ctx, dst, src, tmp)				\
	emit(ctx, sll, tmp, src, 16); /* tmp = src << 16 */	\
	emit(ctx, srl, dst, src, 16); /* dst = src >> 16 */	\
	emit(ctx, or,  dst, dst, tmp) /* dst = dst | tmp */

	u8 t1 = bpf2mips32[JIT_REG_T1][0];
	u8 t2 = bpf2mips32[JIT_REG_T1][1];

	switch (imm) {
	case 64:
		if (cpu_has_mips32r2) {
			emit(ctx, rotr, t1, hi(dst), 16);
			emit(ctx, rotr, hi(dst), lo(dst), 16);
			emit(ctx, wsbh, lo(dst), t1);
			emit(ctx, wsbh, hi(dst), hi(dst));
		} else {
			SWAP16(ctx, t1, lo(dst), t2);
			SWAP16(ctx, lo(dst), hi(dst), t2);
			emit(ctx, addiu, hi(dst), t1, 0);

			MASK8(ctx, t1);
			SWAP8(ctx, lo(dst), lo(dst), t1, t2);
			SWAP8(ctx, hi(dst), hi(dst), t1, t2);
		}
		clobber_reg64(ctx, dst);
		break;

	case 32:
		if (cpu_has_mips32r2) {
			emit(ctx, rotr, lo(dst), lo(dst), 16);
			emit(ctx, wsbh, lo(dst), lo(dst));
		} else {
			SWAP16(ctx, lo(dst), lo(dst), t2);
			MASK8(ctx, t1);
			SWAP8(ctx, lo(dst), lo(dst), t1, t2);
		}
		clobber_reg(ctx, lo(dst));
		break;

	case 16:
		if (cpu_has_mips32r2) {
			emit(ctx, wsbh, lo(dst), lo(dst));
		} else {
			emit(ctx, andi, t1, lo(dst), 0xff00);
			emit(ctx, srl, t1, t1, 8);
			emit(ctx, andi, lo(dst), lo(dst), 0x00ff);
			emit(ctx, sll, lo(dst), lo(dst), 8);
			emit(ctx, or, lo(dst), lo(dst), t1);
		}
		clobber_reg(ctx, lo(dst));
		break;
	}
}

/* Zero-extend imm bits of dst */
static inline void emit_zext_i64(struct jit_context *ctx,
				 const u8 dst[], u32 imm)
{
	switch (imm) {
	case 64:
		break;

	case 32:
		emit_zext(ctx, hi(dst));
		break;

	case 16:
		emit_zext(ctx, hi(dst));
		emit(ctx, andi, lo(dst), lo(dst), 0xffff);
		clobber_reg(ctx, lo(dst));
		break;
	}
}

/* Load operation: dst = *(size*)(src + off) */
static inline void emit_ldx_r(struct jit_context *ctx,
			      const u8 dst[], u8 src, s16 off, u8 size)
{
	switch (size) {
	/* Load a byte */
	case BPF_B:
		emit(ctx, lbu, lo(dst), off, src);
		clobber_reg(ctx, lo(dst));
		break;
	/* Load a half word */
	case BPF_H:
		emit(ctx, lhu, lo(dst), off, src);
		clobber_reg(ctx, lo(dst));
		break;
	/* Load a word */
	case BPF_W:
		emit(ctx, lw, lo(dst), off, src);
		clobber_reg(ctx, lo(dst));
		break;
	/* Load a double word */
	case BPF_DW:
		emit(ctx, lw, dst[1], off, src);
		emit(ctx, lw, dst[0], off + 4, src);
		clobber_reg64(ctx, dst);
		break;
	}
}

/* Store operation: *(size *)(dst + off) = src */
static inline void emit_stx_r(struct jit_context *ctx,
			      const u8 dst, const u8 src[], s16 off, u8 size)
{
	switch (size) {
	/* Store a byte */
	case BPF_B:
		emit(ctx, sb, lo(src), off, dst);
		break;
	/* Store a half word */
	case BPF_H:
		emit(ctx, sh, lo(src), off, dst);
		break;
	/* Store a word */
	case BPF_W:
		emit(ctx, sw, lo(src), off, dst);
		break;
	/* Store a double word */
	case BPF_DW:
		emit(ctx, sw, src[1], off, dst);
		emit(ctx, sw, src[0], off + 4, dst);
		break;
	}
}

/* Atomic read-modify-write */
static inline void emit_atomic_r(struct jit_context *ctx,
				 u8 dst, u8 src, s16 off, u8 code)
{
	u8 t1 = bpf2mips32[JIT_REG_T1][0];
	u8 t2 = bpf2mips32[JIT_REG_T1][1];

	emit(ctx, ll, t1, off, dst);
	switch (code) {
	case BPF_ADD:
	case BPF_ADD | BPF_FETCH:
		emit(ctx, addu, t2, t1, src);
		break;
	case BPF_SUB:
	case BPF_SUB | BPF_FETCH:
		emit(ctx, subu, t2, t1, src);
		break;
	case BPF_OR:
	case BPF_OR | BPF_FETCH:
		emit(ctx, or, t2, t1, src);
		break;
	case BPF_AND:
	case BPF_AND | BPF_FETCH:
		emit(ctx, and, t2, t1, src);
		break;
	case BPF_XOR:
	case BPF_XOR | BPF_FETCH:
		emit(ctx, xor, t2, t1, src);
		break;
	case BPF_XCHG:
		emit(ctx, addiu, t2, src, 0);
		break;
	}
	emit(ctx, sc, t2, off, dst);
	emit(ctx, beqz, t2, -16);
	if (code & BPF_FETCH) {
		emit(ctx, addiu, src, t1, 0);
		clobber_reg(ctx, src);
	} else {
		emit(ctx, nop); /* Delay slot */
	}
}

/* Atomic read-modify-write (64-bit) */
static inline void emit_atomic_r64(struct jit_context *ctx,
				   u8 dst, const u8 src[], s16 off, u8 code)
{
	const u8 *r0 = bpf2mips32[BPF_REG_0]; /* Mapped to v0-v1 */
	const u8 *r1 = bpf2mips32[BPF_REG_1]; /* Mapped to a0-a1 */
	int tmp = bpf2mips32[JIT_REG_T1][0];
	u32 exclude = 0;
	u32 addr = 0;

	/* Push caller-saved registers on stack */
	push_regs(ctx, ctx->clobbered & JIT_CALLER_REGS,
		  0, JIT_RESERVED_STACK);
	/*
	 * Argument 1: 64-bit src, passed in registers a0-a1
	 * Argument 2: 32-bit dst+off, passed in register a2
	 */
	emit(ctx, addiu, tmp, dst, 0);
	emit(ctx, addiu, r1[0], src[0], 0);
	emit(ctx, addiu, r1[1], src[1], 0);
	emit(ctx, addiu, MIPS_R_A2, tmp, off);

	/* Emit function call */
	switch (code) {
	case BPF_ADD:
		addr = (u32)&atomic64_add;
		break;
	case BPF_ADD | BPF_FETCH:
		addr = (u32)&atomic64_fetch_add;
		break;
	case BPF_SUB:
		addr = (u32)&atomic64_sub;
		break;
	case BPF_SUB | BPF_FETCH:
		addr = (u32)&atomic64_fetch_sub;
		break;
	case BPF_OR:
		addr = (u32)&atomic64_or;
		break;
	case BPF_OR | BPF_FETCH:
		addr = (u32)&atomic64_fetch_or;
		break;
	case BPF_AND:
		addr = (u32)&atomic64_and;
		break;
	case BPF_AND | BPF_FETCH:
		addr = (u32)&atomic64_fetch_and;
		break;
	case BPF_XOR:
		addr = (u32)&atomic64_xor;
		break;
	case BPF_XOR | BPF_FETCH:
		addr = (u32)&atomic64_fetch_xor;
		break;
	case BPF_XCHG:
		addr = (u32)&jit_xchg64;
		break;
	}
	emit_mov_i(ctx, tmp, addr);
	emit(ctx, jalr, MIPS_R_RA, tmp);
	emit(ctx, nop); /* Delay slot */

	/* Update src register with old value, if specified */
	if (code & BPF_FETCH) {
		emit(ctx, addiu, lo(src), lo(r0), 0);
		emit(ctx, addiu, hi(src), hi(r0), 0);
		exclude = BIT(src[0]) | BIT(src[1]);
		clobber_reg64(ctx, src);
	}

	/* Restore caller-saved registers, except any fetched value */
	pop_regs(ctx, ctx->clobbered & JIT_CALLER_REGS,
		 exclude, JIT_RESERVED_STACK);
	clobber_reg(ctx, MIPS_R_RA);
}

/* Atomic compare-and-exchange */
static inline void emit_cmpxchg_r(struct jit_context *ctx,
				  u8 dst, u8 src, s16 off)
{
	const u8 *r0 = bpf2mips32[BPF_REG_0];
	u8 t1 = bpf2mips32[JIT_REG_T1][0];
	u8 t2 = bpf2mips32[JIT_REG_T1][1];

	emit(ctx, ll, t1, off, dst);
	emit(ctx, bne, t1, lo(r0), 12);
	emit(ctx, addiu, t2, src, 0); /* Delay slot */
	emit(ctx, sc, t2, off, dst);
	emit(ctx, beqz, t2, -20);
	emit(ctx, addiu, lo(r0), t1, 0);
	emit(ctx, addiu, hi(r0), MIPS_R_ZERO, 0);

	clobber_reg64(ctx, r0);
}

/* Atomic compare-and-exchange (64-bit) */
static inline void emit_cmpxchg_r64(struct jit_context *ctx,
				    u8 dst, const u8 src[], s16 off)
{
	const u8 *r0 = bpf2mips32[BPF_REG_0];
	const u8 *r2 = bpf2mips32[BPF_REG_2];
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	/* Push caller-saved registers on stack */
	push_regs(ctx, ctx->clobbered & JIT_CALLER_REGS,
		  JIT_RETURN_REGS, JIT_RESERVED_STACK + 2 * sizeof(u32));
	/*
	 * Argument 1: 32-bit dst+off, passed in register a0 (a1 unused)
	 * Argument 2: 64-bit r0, passed in registers a2-a3
	 * Argument 3: 64-bit src, passed on stack
	 */
	push_regs(ctx, BIT(src[0]) | BIT(src[1]), 0, JIT_RESERVED_STACK);
	emit(ctx, addiu, tmp, dst, off);
	emit(ctx, addiu, r2[0], r0[0], 0);
	emit(ctx, addiu, r2[1], r0[1], 0);
	emit(ctx, addiu, MIPS_R_A0, tmp, 0);

	/* Emit function call */
	emit_mov_i(ctx, tmp, (u32)&atomic64_cmpxchg);
	emit(ctx, jalr, MIPS_R_RA, tmp);
	emit(ctx, nop); /* Delay slot */

	/* Restore caller-saved registers, except the return value */
	pop_regs(ctx, ctx->clobbered & JIT_CALLER_REGS,
		 JIT_RETURN_REGS, JIT_RESERVED_STACK + 2 * sizeof(u32));
	clobber_reg(ctx, MIPS_R_V0);
	clobber_reg(ctx, MIPS_R_V1);
	clobber_reg(ctx, MIPS_R_RA);
}

/* Invert a conditional jump operation */
static inline u8 invert_jmp(u8 op)
{
	switch (op) {
	case BPF_JEQ: return BPF_JNE;
	case BPF_JNE: return BPF_JEQ;
	case BPF_JSET: return JIT_JNSET;
	case BPF_JGT: return BPF_JLE;
	case BPF_JGE: return BPF_JLT;
	case BPF_JLT: return BPF_JGE;
	case BPF_JLE: return BPF_JGT;
	case BPF_JSGT: return BPF_JSLE;
	case BPF_JSGE: return BPF_JSLT;
	case BPF_JSLT: return BPF_JSGE;
	case BPF_JSLE: return BPF_JSGT;
	}
	return 0;
}

/* Prepare a PC-relative jump operation */
static inline void setup_jmp(struct jit_context *ctx,
			     u8 bpf_op, s16 bpf_off,
			     u8 *jit_op, s16 *jit_off)
{
	struct jit_desc *desc = &ctx->descriptors[ctx->bpf_index];
	int offset = 0;
	int op = bpf_op;

	/* Do not compute offsets on the first pass */
	if (desc->offset == 0)
		goto done;
	/*
	 * Current ctx->jit_index points to the start of the branch preamble.
	 * Since the preamble differs among different branch conditionals,
	 * the current index cannot be used to compute the branch offset.
	 * Instead, we use the offset table value for the next instruction,
	 * which gives the index immediately after the branch delay slot.
	 */
	if (!desc->convert) {
		int origin = ctx->bpf_index + 1;
		int target = ctx->bpf_index + bpf_off + 1;
		offset = (ctx->descriptors[target].offset -
			  ctx->descriptors[origin].offset) * sizeof(u32);
	}

	/*
	 * The PC-relative branch offset field on MIPS is 18 bits signed,
	 * so if the computed offset is larger than this we generate a an
	 * absolute jump that we skip with an inverted conditional branch.
	 */
	if (desc->convert || is_18bit(offset)) {
		offset = 2 * sizeof(u32);
		op = invert_jmp(bpf_op);
		ctx->changes += !desc->convert;
		desc->convert = true;
	}

done:
	*jit_off = offset;
	*jit_op = op;
}

/* Finish a PC-relative jump operation */
static inline int finish_jmp(struct jit_context *ctx, s16 bpf_off)
{
	struct jit_desc *desc = &ctx->descriptors[ctx->bpf_index];

	/*
	 * Add an absolute long jump with delay slot,
	 * if the PC-relative branch was converted.
	 */
	if (desc->convert) {
		int target = get_target(ctx, ctx->bpf_index + bpf_off + 1);
		if (target < 0)
			return -1;
		emit(ctx, j, target);
		emit(ctx, nop);
	}
	return 0;
}

/* Jump immediate */
static inline void emit_jmp_i(struct jit_context *ctx,
			      u8 dst, s16 imm, s16 off, u8 op)
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	switch (op) {
	/* PC += off if dst == imm */
	case BPF_JEQ:
		emit(ctx, addiu, tmp, dst, -imm);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst != imm */
	case BPF_JNE:
		emit(ctx, addiu, tmp, dst, -imm);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if dst & imm */
	case BPF_JSET:
		emit(ctx, andi, tmp, dst, (u16)imm);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if (dst & imm) == 0 (not in BPF, used for long jumps) */
	case JIT_JNSET:
		emit(ctx, andi, tmp, dst, (u16)imm);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst > imm */
	case BPF_JGT:
		emit(ctx, addiu, tmp, MIPS_R_ZERO, imm);
		emit(ctx, sltu, tmp, tmp, dst);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if dst >= imm */
	case BPF_JGE:
		emit(ctx, addiu, tmp, MIPS_R_ZERO, imm);
		emit(ctx, sltu, tmp, dst, tmp);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst < imm */
	case BPF_JLT:
		emit(ctx, addiu, tmp, MIPS_R_ZERO, imm);
		emit(ctx, sltu, tmp, dst, tmp);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if dst <= imm */
	case BPF_JLE:
		emit(ctx, addiu, tmp, MIPS_R_ZERO, imm);
		emit(ctx, sltu, tmp, tmp, dst);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst > imm (signed) */
	case BPF_JSGT:
		emit(ctx, addiu, tmp, dst, -imm);
		emit(ctx, bgtz, tmp, off);
		break;
	/* PC += off if dst >= imm (signed) */
	case BPF_JSGE:
		emit(ctx, addiu, tmp, dst, -imm);
		emit(ctx, bgez, tmp, off);
		break;
	/* PC += off if dst < imm (signed) */
	case BPF_JSLT:
		emit(ctx, addiu, tmp, dst, -imm);
		emit(ctx, bltz, tmp, off);
		break;
	/* PC += off if dst <= imm (signed) */
	case BPF_JSLE:
		emit(ctx, addiu, tmp, dst, -imm);
		emit(ctx, blez, tmp, off);
		break;
	}

	emit(ctx, nop); /* Delay slot */
}

/* Jump register */
static inline void emit_jmp_r(struct jit_context *ctx,
			      u8 dst, u8 src, s16 off, u8 op)
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];

	switch (op) {
	/* PC += off if dst == src */
	case BPF_JEQ:
		emit(ctx, subu, tmp, dst, src);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst != src */
	case BPF_JNE:
		emit(ctx, subu, tmp, dst, src);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if dst & src */
	case BPF_JSET:
		emit(ctx, and, tmp, dst, src);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if (dst & imm) == 0 (not in BPF, used for long jumps) */
	case JIT_JNSET:
		emit(ctx, and, tmp, dst, src);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst > src */
	case BPF_JGT:
		emit(ctx, sltu, tmp, src, dst);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if dst >= src */
	case BPF_JGE:
		emit(ctx, sltu, tmp, dst, src);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst < src */
	case BPF_JLT:
		emit(ctx, sltu, tmp, dst, src);
		emit(ctx, bnez, tmp, off);
		break;
	/* PC += off if dst <= src */
	case BPF_JLE:
		emit(ctx, sltu, tmp, src, dst);
		emit(ctx, beqz, tmp, off);
		break;
	/* PC += off if dst > src (signed) */
	case BPF_JSGT:
		emit(ctx, subu, tmp, dst, src);
		emit(ctx, bgtz, tmp, off);
		break;
	/* PC += off if dst >= src (signed) */
	case BPF_JSGE:
		emit(ctx, subu, tmp, dst, src);
		emit(ctx, bgez, tmp, off);
		break;
	/* PC += off if dst < src (signed) */
	case BPF_JSLT:
		emit(ctx, subu, tmp, dst, src);
		emit(ctx, bltz, tmp, off);
		break;
	/* PC += off if dst <= src (signed) */
	case BPF_JSLE:
		emit(ctx, subu, tmp, dst, src);
		emit(ctx, blez, tmp, off);
		break;
	}

	emit(ctx, nop); /* Delay slot */
}

/* Jump register (64-bit) */
static inline void emit_jmp_r64(struct jit_context *ctx,
				const u8 dst[], const u8 src[], s16 off, u8 op)
{
	u8 t1 = bpf2mips32[JIT_REG_T1][0];
	u8 t2 = bpf2mips32[JIT_REG_T1][1];

	switch (op) {
	/* PC += off if dst == src */
	/* PC += off if dst != src */
	case BPF_JEQ:
	case BPF_JNE:
		emit(ctx, subu, t1, lo(dst), lo(src));
		emit(ctx, subu, t2, hi(dst), hi(src));
		emit(ctx, or, t1, t1, t2);
		if (op == BPF_JEQ)
			emit(ctx, beqz, t1, off);
		else
			emit(ctx, bnez, t1, off);
		break;
	/* PC += off if dst & src */
	/* PC += off if (dst & imm) == 0 (not in BPF, used for long jumps) */
	case BPF_JSET:
	case JIT_JNSET:
		emit(ctx, and, t1, lo(dst), lo(src));
		emit(ctx, and, t2, hi(dst), hi(src));
		emit(ctx, or, t1, t1, t2);
		if (op == BPF_JSET)
			emit(ctx, bnez, t1, off);
		else
			emit(ctx, beqz, t1, off);
		break;
	/* PC += off if dst > src */
	/* PC += off if dst <= src */
	case BPF_JGT:
	case BPF_JLE:
		emit(ctx, sltu, t1, lo(src), lo(dst));  /* t1 = sl < dl      */
		emit(ctx, subu, t2, hi(src), hi(dst));  /* t2 = sh - dh      */
		emit(ctx, movn, t1, MIPS_R_ZERO, t2);   /* t1 = 0 if t2 != 0 */
		emit(ctx, sltu, t2, hi(src), hi(dst));  /* t2 = sh < dh      */
		emit(ctx, or, t1, t1, t2);              /* t1 = t1 | t2      */
		if (op == BPF_JGT)
			emit(ctx, bnez, t1, off);
		else
			emit(ctx, beqz, t1, off);
		break;
	/* PC += off if dst >= src */
	/* PC += off if dst < src */
	case BPF_JLT:
	case BPF_JGE:
		emit(ctx, sltu, t1, lo(dst), lo(src));  /* t1 = dl < sl      */
		emit(ctx, subu, t2, hi(dst), hi(src));  /* t2 = dh - sh      */
		emit(ctx, movn, t1, MIPS_R_ZERO, t2);   /* t1 = 0 if t2 != 0 */
		emit(ctx, sltu, t2, hi(dst), hi(src));  /* t2 = dh < sh      */
		emit(ctx, or, t1, t1, t2);              /* t1 = t1 | t2      */
		if (op == BPF_JLT)
			emit(ctx, bnez, t1, off);
		else
			emit(ctx, beqz, t1, off);
		break;
	/* PC += off if dst > src (signed) */
	/* PC += off if dst <= src (signed) */
	case BPF_JSGT:
	case BPF_JSLE:
		emit(ctx, sltu, t1, lo(src), lo(dst));  /* t1 = sl < dl  */
		emit(ctx, subu, t2, hi(src), hi(dst));  /* t2 = sh - dh  */
		emit(ctx, subu, t2, t2, t1);            /* t2 = t2 - t1  */
		emit(ctx, srl, t2, t2, 31);             /* t2 = t2 >> 31 */
		if (op == BPF_JSGT)
			emit(ctx, bnez, t2, off);
		else
			emit(ctx, beqz, t2, off);
		break;
	/* PC += off if dst < src (signed) */
	/* PC += off if dst >= src (signed) */
	case BPF_JSLT:
	case BPF_JSGE:
		emit(ctx, sltu, t1, lo(dst), lo(src));  /* t1 = sl < sl  */
		emit(ctx, subu, t2, hi(dst), hi(src));  /* t2 = sh - sh  */
		emit(ctx, subu, t2, t2, t1);            /* t2 = t2 - t1  */
		emit(ctx, srl, t2, t2, 31);             /* t2 = t2 >> 31 */
		if (op == BPF_JSLT)
			emit(ctx, bnez, t2, off);
		else
			emit(ctx, beqz, t2, off);
		break;
	}

	emit(ctx, nop); /* Delay slot */
}

/* Jump always */
static inline int emit_ja(struct jit_context *ctx, s16 off)
{
	int target = get_target(ctx, ctx->bpf_index + off + 1);

	if (target < 0)
		return -1;
	emit(ctx, j, target);
	emit(ctx, nop);
	return 0;
}

/* Jump to epilogue */
static inline int emit_exit(struct jit_context *ctx)
{
	int target = get_target(ctx, ctx->program->len);

	if (target < 0)
		return -1;
	emit(ctx, j, target);
	emit(ctx, nop);
	return 0;
}

/* Function call */
static inline int emit_call(struct jit_context *ctx,
			    const struct bpf_insn *insn)
{
	u8 tmp = bpf2mips32[JIT_REG_T1][0];
	u64 addr;
	bool unused;

	/* Decode the call address */
	if (bpf_jit_get_func_addr(ctx->program, insn, ctx->target == NULL,
				  &addr, &unused) < 0)
		return -1;

	/* Push stack arguments */
	push_regs(ctx, JIT_STACK_REGS, 0, JIT_RESERVED_STACK);

	/* Emit function call */
	emit_mov_i(ctx, tmp, addr);
	emit(ctx, jalr, MIPS_R_RA, tmp);
	emit(ctx, nop); /* Delay slot */

	clobber_reg(ctx, MIPS_R_RA);
	clobber_reg(ctx, MIPS_R_V0);
	clobber_reg(ctx, MIPS_R_V1);
	return 0;
}

/* Function tail call */
static inline int emit_tail_call(struct jit_context *ctx)
{
	u8 ary = lo(bpf2mips32[BPF_REG_2]);
	u8 ind = lo(bpf2mips32[BPF_REG_3]);
	u8 t1 = bpf2mips32[JIT_REG_T1][0];
	u8 t2 = bpf2mips32[JIT_REG_T1][1];
	int off;

	/*
	 * Tail call:
	 * eBPF R1   - function argument (context ptr), passed in a0-a1
	 * eBPF R2   - ptr to object with array of function entry points
	 * eBPF R3   - array index of function to be called
	 * stack[sz] - remaining tail call count, initialized in prologue
	 */

	/* if (ind >= ary->map.max_entries) goto out */
	off = offsetof(struct bpf_array, map.max_entries);
	if (off > 0x7fff)
		return -1;
	emit(ctx, lw, t1, off, ary);             /* t1 = ary->map.max_entries*/
	emit(ctx, sltu, t1, ind, t1);            /* t1 = ind < t1            */
	emit(ctx, beqz, t1, get_offset(ctx, 1)); /* PC += off(1) if t1 == 0  */
	                                         /* (next insn delay slot)   */
	/* if (TCC-- < 0) goto out */
	emit(ctx, lw, t2, ctx->stack_size, MIPS_R_SP);  /* t2 = *(SP + size) */
	emit(ctx, bltz, t2, get_offset(ctx, 1));  /* PC += off(1) if t2 < 0  */
	emit(ctx, subu, t2, t2, 1);               /* t2-- (delay slot)       */
	emit(ctx, sw, t2, ctx->stack_size, MIPS_R_SP);  /* *(SP + size) = t2 */

	/* prog = ary->ptrs[ind] */
	off = offsetof(struct bpf_array, ptrs);
	if (off > 0x7fff)
		return -1;
	emit(ctx, sll, t1, ind, 2);               /* t1 = ind << 2           */
	emit(ctx, addu, t1, t1, ary);             /* t1 += ary               */
	emit(ctx, lw, t2, off, t1);               /* t2 = *(t1 + off)        */

	/* if (prog == 0) goto out */
	emit(ctx, beqz, t2, get_offset(ctx, 1));  /* PC += off(1) if t2 == 0 */
	emit(ctx, nop);                           /* Delay slot              */

	/* func = prog->bpf_func + 8 (prologue skip offset) */
	off = offsetof(struct bpf_prog, bpf_func);
	if (off > 0x7fff)
		return -1;
	emit(ctx, lw, t1, off, t2);                /* t1 = *(t2 + off)       */
	emit(ctx, addiu, t1, t1, JIT_TCALL_SKIP);  /* t1 += skip (8 or 12)   */

	/* goto func */
	build_epilogue(ctx, t1);
	return 0;
}

/*
 * Convert an eBPF instruction to native instruction, i.e
 * JITs an eBPF instruction.
 * Returns :
 *	0  - Successfully JITed an 8-byte eBPF instruction
 *	>0 - Successfully JITed a 16-byte eBPF instruction
 *	<0 - Failed to JIT.
 */
static int build_insn(const struct bpf_insn *insn, struct jit_context *ctx)
{
	u8 code = insn->code;
	const u8 *dst = bpf2mips32[insn->dst_reg];
	const u8 *src = bpf2mips32[insn->src_reg];
	const u8 *tmp = bpf2mips32[JIT_REG_T0];
	s16 off = insn->off;
	s32 imm = insn->imm;
	s16 rel;
	u8 jmp;

	switch (code) {
	/* ALU operations */
	/* dst = imm */
	case BPF_ALU | BPF_MOV | BPF_K:
		emit_mov_i(ctx, lo(dst), imm);
		emit_zext(ctx, hi(dst));
		break;
	/* dst = src */
	case BPF_ALU | BPF_MOV | BPF_X:
		if (imm == 1) {
			/* Special mov32 for zext */
			emit_mov_i(ctx, hi(dst), 0);
		} else {
			emit_mov_r(ctx, lo(dst), lo(src));
			emit_zext(ctx, hi(dst));
		}
		break;
	/* dst = imm */
	case BPF_ALU64 | BPF_MOV | BPF_K:
		emit_mov_se_i64(ctx, dst, imm);
		break;
	/* dst = src */
	case BPF_ALU64 | BPF_MOV | BPF_X:
		emit_mov_r(ctx, lo(dst), lo(src));
		emit_mov_r(ctx, hi(dst), hi(src));
		break;
	/* dst = dst + imm */
	/* dst = dst - imm */
	/* dst = dst * imm */
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_MUL | BPF_K:
		if (is_16bit(imm)) {
			emit_alu_i(ctx, lo(dst), imm, BPF_OP(code));
		} else {
			emit_mov_i(ctx, tmp[0], imm);
			emit_alu_r(ctx, lo(dst), tmp[0], BPF_OP(code));
		}
		emit_zext(ctx, hi(dst));
		break;
	/* dst = dst | imm */
	/* dst = dst & imm */
	/* dst = dst ^ imm */
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_K:
		if ((u32)imm <= 0xffff) {
			emit_alu_i(ctx, lo(dst), imm, BPF_OP(code));
		} else {
			emit_mov_i(ctx, tmp[0], imm);
			emit_alu_r(ctx, lo(dst), tmp[0], BPF_OP(code));
		}
		emit_zext(ctx, hi(dst));
		break;
	/* dst = dst << imm */
	/* dst = dst >> imm */
	/* dst = dst >> imm (signed) */
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_ARSH | BPF_K:
		if (unlikely(imm > 31))
			return -EINVAL;
		if (imm)
			emit_alu_i(ctx, lo(dst), imm, BPF_OP(code));
		emit_zext(ctx, hi(dst));
		break;
	/* dst = dst + src */
	/* dst = dst - src */
	/* dst = dst | src */
	/* dst = dst & src */
	/* dst = dst ^ src */
	/* dst = dst * src */
	/* dst = dst << src */
	/* dst = dst >> src */
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_X:
		emit_alu_r(ctx, lo(dst), lo(src), BPF_OP(code));
		emit_zext(ctx, hi(dst));
		break;
	/* dst = dst + imm */
	/* dst = dst - imm */
	/* dst = dst | imm */
	/* dst = dst & imm */
	/* dst = dst ^ imm */
	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
		/*
		 * Sign-extend the immediate value into a temporary register,
		 * and then do the operation on this register.
		 */
		emit_mov_se_i64(ctx, tmp, imm);
		emit_alu_r64(ctx, dst, tmp, BPF_OP(code));
		break;
	/* dst = dst + src */
	/* dst = dst - src */
	/* dst = dst | src */
	/* dst = dst & src */
	/* dst = dst ^ src */
	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit_alu_r64(ctx, dst, src, BPF_OP(code));
		break;
	/* dst = dst << imm */
	/* dst = dst >> imm */
	/* dst = dst >> imm (arithmetic) */
	case BPF_ALU64 | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		if (unlikely(imm > 63))
			return -EINVAL;
		if (imm)
			emit_shift_i64(ctx, dst, imm, BPF_OP(code));
		break;
	/* dst = dst << src */
	/* dst = dst >> src */
	/* dst = dst >> src (arithmetic) */
	case BPF_ALU64 | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit_shift_r64(ctx, dst, lo(src), BPF_OP(code));
		break;
	/* dst = -dst */
	case BPF_ALU | BPF_NEG:
		emit_alu_i(ctx, lo(dst), 0, BPF_NEG);
		emit_zext(ctx, hi(dst));
		break;
	/* dst = -dst (64 bit) */
	case BPF_ALU64 | BPF_NEG:
		emit_neg_i64(ctx, dst);
		break;
	/* dst = dst * src */
	case BPF_ALU64 | BPF_MUL | BPF_X:
		emit_mul_r64(ctx, dst, src);
		break;
	/* dst = dst * imm */
	case BPF_ALU64 | BPF_MUL | BPF_K:
		/*
		 * Sign-extend the immediate value into a temporary register,
		 * and then do the operation on this register.
		 */
		emit_mov_se_i64(ctx, tmp, imm);
		emit_mul_r64(ctx, dst, tmp);
		break;
	/* dst = dst / src */
	/* dst = dst % src */
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_X:
		emit_divmod_r(ctx, lo(dst), lo(src), BPF_OP(code));
		emit_zext(ctx, hi(dst));
		break;
	/* dst = dst / src */
	/* dst = dst % src */
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_K:
		emit_mov_i(ctx, tmp[0], imm);
		emit_divmod_r(ctx, lo(dst), tmp[0], BPF_OP(code));
		emit_zext(ctx, hi(dst));
		break;
	/* dst = dst / src (64 bit) */
	/* dst = dst % src (64 bit) */
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
		emit_divmod_r64(ctx, dst, src, BPF_OP(code));
		break;
	/* dst = dst / imm (64 bit) */
	/* dst = dst % imm (64 bit) */
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		/*
		 * Sign-extend the immediate value into a temporary register,
		 * and then do the operation on this register.
		 */
		emit_mov_se_i64(ctx, tmp, imm);
		emit_divmod_r64(ctx, dst, tmp, BPF_OP(code));
		break;
	/* dst = htole(dst) */
	/* dst = htobe(dst) */
	case BPF_ALU | BPF_END | BPF_FROM_LE:
	case BPF_ALU | BPF_END | BPF_FROM_BE:
		if (BPF_SRC(code) ==
#ifdef __BIG_ENDIAN
		    BPF_FROM_LE
#else
		    BPF_FROM_BE
#endif
		    )
			emit_bswap_i64(ctx, dst, imm);
		emit_zext_i64(ctx, dst, imm);
		break;
	/* dst = imm64 */
	case BPF_LD | BPF_IMM | BPF_DW:
		emit_mov_i(ctx, lo(dst), imm);
		emit_mov_i(ctx, hi(dst), insn[1].imm);
		return 1;
	/* LDX: dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_DW:
		emit_ldx_r(ctx, dst, lo(src), off, BPF_SIZE(code));
		break;
	/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		switch (BPF_SIZE(code)) {
		case BPF_DW:
			/* Sign-extend immediate value into temporary reg */
			emit_mov_se_i64(ctx, tmp, imm);
			break;
		case BPF_W:
		case BPF_H:
		case BPF_B:
			emit_mov_i(ctx, lo(tmp), imm);
			break;
		}
		emit_stx_r(ctx, lo(dst), tmp, off, BPF_SIZE(code));
		break;
	/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_DW:
		emit_stx_r(ctx, lo(dst), src, off, BPF_SIZE(code));
		break;
	/* Atomics */
	case BPF_STX | BPF_XADD | BPF_W:
	case BPF_STX | BPF_XADD | BPF_DW:
		switch (imm) {
		case BPF_ADD:
		case BPF_ADD | BPF_FETCH:
		case BPF_SUB:
		case BPF_SUB | BPF_FETCH:
		case BPF_OR:
		case BPF_OR | BPF_FETCH:
		case BPF_AND:
		case BPF_AND | BPF_FETCH:
		case BPF_XOR:
		case BPF_XOR | BPF_FETCH:
		case BPF_XCHG:
			if (BPF_SIZE(code) == BPF_W)
				emit_atomic_r(ctx, lo(dst), lo(src), off, imm);
			else
				emit_atomic_r64(ctx, lo(dst), src, off, imm);
			break;
		case BPF_CMPXCHG:
			if (BPF_SIZE(code) == BPF_W)
				emit_cmpxchg_r(ctx, lo(dst), lo(src), off);
			else
				emit_cmpxchg_r64(ctx, lo(dst), src, off);
			break;
		default:
			goto notyet;
		}
		break;
	/* PC += off if dst == src */
	/* PC += off if dst != src */
	/* PC += off if dst & src */
	/* PC += off if dst > src */
	/* PC += off if dst >= src */
	/* PC += off if dst > src (signed) */
	/* PC += off if dst >= src (signed) */
	/* PC += off if dst < src */
	/* PC += off if dst <= src */
	/* PC += off if dst < src (signed) */
	/* PC += off if dst <= src (signed) */
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
		if (off == 0)
			break;
		setup_jmp(ctx, BPF_OP(code), off, &jmp, &rel);
		emit_jmp_r(ctx, lo(dst), lo(src), rel, jmp);
		if (finish_jmp(ctx, off) < 0)
			goto toofar;
		break;
	/* PC += off if dst == imm */
	/* PC += off if dst != imm */
	/* PC += off if dst & imm */
	/* PC += off if dst > imm */
	/* PC += off if dst >= imm */
	/* PC += off if dst > imm (signed) */
	/* PC += off if dst >= imm (signed) */
	/* PC += off if dst < imm */
	/* PC += off if dst <= imm */
	/* PC += off if dst < imm (signed) */
	/* PC += off if dst <= imm (signed) */
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		if (off == 0)
			break;
		setup_jmp(ctx, BPF_OP(code), off, &jmp, &rel);
		if (is_16bit(imm)) {
			emit_jmp_i(ctx, lo(dst), imm, rel, jmp);
		} else {
			/* Move large immediate to register */
			emit_mov_i(ctx, tmp[0], imm);
			emit_jmp_r(ctx, lo(dst), tmp[0], rel, jmp);
		}
		if (finish_jmp(ctx, off) < 0)
			goto toofar;
		break;
	/* PC += off if dst == src */
	/* PC += off if dst != src */
	/* PC += off if dst & src */
	/* PC += off if dst > src */
	/* PC += off if dst >= src */
	/* PC += off if dst > src (signed) */
	/* PC += off if dst >= src (signed) */
	/* PC += off if dst < src */
	/* PC += off if dst <= src */
	/* PC += off if dst < src (signed) */
	/* PC += off if dst <= src (signed) */
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
		if (off == 0)
			break;
		setup_jmp(ctx, BPF_OP(code), off, &jmp, &rel);
		emit_jmp_r64(ctx, dst, src, rel, jmp);
		if (finish_jmp(ctx, off) < 0)
			goto toofar;
		break;
	/* PC += off if dst == imm */
	/* PC += off if dst != imm */
	/* PC += off if dst & imm */
	/* PC += off if dst > imm */
	/* PC += off if dst >= imm */
	/* PC += off if dst > imm (signed) */
	/* PC += off if dst >= imm (signed) */
	/* PC += off if dst < imm */
	/* PC += off if dst <= imm */
	/* PC += off if dst < imm (signed) */
	/* PC += off if dst <= imm (signed) */
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
		if (off == 0)
			break;
		emit_mov_se_i64(ctx, tmp, imm);
		setup_jmp(ctx, BPF_OP(code), off, &jmp, &rel);
		emit_jmp_r64(ctx, dst, tmp, rel, jmp);
		if (finish_jmp(ctx, off) < 0)
			goto toofar;
		break;
	/* PC += off */
	case BPF_JMP | BPF_JA:
		if (off == 0)
			break;
		if (emit_ja(ctx, off) < 0)
			goto toofar;
		break;
	/* Tail call */
	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_tail_call(ctx) < 0)
			goto invalid;
		break;
	/* Function call */
	case BPF_JMP | BPF_CALL:
		if (emit_call(ctx, insn) < 0)
			goto invalid;
		break;
	/* Function return */
	case BPF_JMP | BPF_EXIT:
		/*
		 * Optimization: when last instruction is EXIT
		 * simply fallthrough to epilogue.
		 */
		if (ctx->bpf_index == ctx->program->len - 1)
			break;
		if (emit_exit(ctx) < 0)
			goto toofar;
		break;

	default:
invalid:
		pr_err_once("unknown opcode %02x\n", code);
		return -EINVAL;
notyet:
		pr_info_once("*** NOT YET: opcode %02x ***\n", code);
		return -EFAULT;
toofar:
		pr_info_once("*** TOO FAR: jump at %u opcode %02x ***\n",
			     ctx->bpf_index, code);
		return -E2BIG;
	}
	return 0;
}

/*
 * Stack frame layout for a JITed program (stack grows down).
 *
 * Higher address  : Previous stack frame      :
 *                 : 64-bit eBPF args r3-r5    :
 *                 +===========================+  <--- MIPS sp before call
 *                 | Callee-saved registers,   |
 *                 | including RA and FP       |
 *                 +---------------------------+  <--- eBPF FP (MIPS zero,fp)
 *                 | Local eBPF variables      |
 *                 | allocated by program      |
 *                 +---------------------------+
 *                 | Reserved for caller-saved |
 *                 | registers                 |
 *                 +---------------------------+
 *                 | Reserved for 64-bit eBPF  |
 *                 | args r3-r5 & args passed  |
 *                 | on stack in kernel calls  |
 * Lower address   +===========================+  <--- MIPS sp
 */

/* Build the program body from eBPF bytecode */
static int build_body(struct jit_context *ctx)
{
	const struct bpf_prog *prog = ctx->program;
	unsigned int i;

	/* MIPS fp and eBPF R1 (context) are always used */
	clobber_reg(ctx, MIPS_R_FP);
	clobber_reg64(ctx, bpf2mips32[BPF_REG_1]);

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		struct jit_desc *desc = &ctx->descriptors[i];
		int ret;

		ctx->bpf_index = i;
		if (ctx->target == NULL) {
			ctx->changes += desc->offset != ctx->jit_index;
			desc->offset = ctx->jit_index;
		}

		ret = build_insn(insn, ctx);
		if (ret < 0)
			return ret;

		if (ret > 0) {
			i++;
			if (ctx->target == NULL)
				desc[1].offset = ctx->jit_index;
		}
	}

	/* Store the end offset, where the epilogue begins */
	ctx->descriptors[prog->len].offset = ctx->jit_index;
	return 0;
}

/* Set the branch conversion flag on all instructions */
static void set_convert_flag(struct jit_context *ctx, bool convert)
{
	const struct bpf_prog *prog = ctx->program;
	unsigned int i;

	for (i = 0; i <= prog->len; i++) {
		ctx->descriptors[i].convert = convert;
	}
}

static void jit_fill_hole(void *area, unsigned int size)
{
	u32 *p;

	/* We are guaranteed to have aligned memory. */
	for (p = area; size >= sizeof(u32); size -= sizeof(u32))
		uasm_i_break(&p, BRK_BUG); /* Increments p */
}

bool bpf_jit_needs_zext(void)
{
	return true;
}

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	struct bpf_prog *tmp, *orig_prog = prog;
	struct bpf_binary_header *header = NULL;
	struct jit_context ctx;
	bool tmp_blinded = false;
	unsigned int tmp_idx;
	unsigned int image_size;
	u8 *image_ptr;
	int tries;

	/*
	 * If BPF JIT was not enabled then we must fall back to
	 * the interpreter.
	 */
	if (!bpf_jit_enable)
		return orig_prog;
	/*
	 * If constant blinding was enabled and we failed during blinding
	 * then we must fall back to the interpreter. Otherwise, we save
	 * the new JITed code.
	 */
	tmp = bpf_jit_blind_constants(prog);
	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.program = prog;

	/*
	 * Not able to allocate memory for descriptors[], then
	 * we must fall back to the interpreter
	 */
	ctx.descriptors = kcalloc(prog->len + 1, sizeof *ctx.descriptors,
				  GFP_KERNEL);
	if (ctx.descriptors == NULL)
		goto out_err;

	/* First pass discovers used resources */
	if (build_body(&ctx) < 0)
		goto out_err;
	/*
	 * Second pass computes instruction offsets.
	 * If any PC-relative branches are out of range, a sequence of
	 * a PC-relative branch + a jump is is generated, and we have
	 * to try again from the beginning to generate the new offsets.
	 * This is done until no additional conversions are necessary.
	 * The last two iterations are done with all branches being
	 * converted, to guarantee offset table convergence within a
	 * fixed number of iterations.
	 */
	ctx.jit_index = 0;
	build_prologue(&ctx);
	tmp_idx = ctx.jit_index;

	tries = JIT_MAX_ITERATIONS;
	do {
		ctx.jit_index = tmp_idx;
		ctx.changes = 0;
		if (tries == 2)
			set_convert_flag(&ctx, true);
		if (build_body(&ctx) < 0)
			goto out_err;
	} while (ctx.changes > 0 && --tries > 0);

	if (WARN_ONCE(ctx.changes > 0, "JIT offsets failed to converge"))
		goto out_err;

	build_epilogue(&ctx, MIPS_R_RA);

	/* Now we know the size of the structure to make */
	image_size = sizeof(u32) * ctx.jit_index;
	header = bpf_jit_binary_alloc(image_size, &image_ptr,
				      sizeof(u32), jit_fill_hole);
	/*
	 * Not able to allocate memory for the structure then
	 * we must fall back to the interpretation
	 */
	if (header == NULL)
		goto out_err;

	/* Actual pass to generate final JIT code */
	ctx.target = (u32*)image_ptr;
	ctx.jit_index = 0;

	/*
	 * If building the JITed code fails somehow,
	 * we fall back to the interpretation.
	 */
	build_prologue(&ctx);
	if (build_body(&ctx) < 0)
		goto out_err;
	build_epilogue(&ctx, MIPS_R_RA);

	flush_icache_range((u32)header, (u32)(ctx.target + ctx.jit_index));

	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, image_size, 2, ctx.target);

	set_memory_ro((unsigned long)header, header->pages);
	prog->bpf_func = (void *)ctx.target;
	prog->jited = 1;
	prog->jited_len = image_size;

out:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	kfree(ctx.descriptors);
	return prog;

out_err:
	prog = orig_prog;
	if (header)
		bpf_jit_binary_free(header);
	goto out;
}
