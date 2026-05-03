// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF JIT compiler for m68k
 *
 * Copyright (C) 2026 Kuan-Wei Chiu <visitorckw@gmail.com>
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/irqflags.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
#include <linux/math64.h>

#define STACK_OFFSET(k) (-4 - (4 * (k)))

enum {
	BPF_R1_HI, BPF_R1_LO,
	BPF_R2_HI, BPF_R2_LO,
	BPF_R3_HI, BPF_R3_LO,
	BPF_R4_HI, BPF_R4_LO,
	BPF_R5_HI, BPF_R5_LO,
	BPF_R6_HI, BPF_R6_LO,
	BPF_R7_HI, BPF_R7_LO,
	BPF_R8_HI, BPF_R8_LO,
	BPF_R9_HI, BPF_R9_LO,
	BPF_R10_HI, BPF_R10_LO,
	BPF_AX_HI, BPF_AX_LO,
	BPF_TC_HI, BPF_TC_LO,
	BPF_JIT_SCRATCH_REGS,
};

#define SCRATCH_SIZE (BPF_JIT_SCRATCH_REGS * 4)

#define TMP_REG_1 14
#define TMP_REG_2 15

#define M68K_D0 0
#define M68K_D1 1
#define M68K_D2 2
#define M68K_D3 3
#define M68K_D4 4
#define M68K_D5 5

static const s8 bpf2m68k[16][2] = {
	[BPF_REG_0]  = {M68K_D1, M68K_D0},
	[BPF_REG_1]  = {STACK_OFFSET(BPF_R1_HI),  STACK_OFFSET(BPF_R1_LO)},
	[BPF_REG_2]  = {STACK_OFFSET(BPF_R2_HI),  STACK_OFFSET(BPF_R2_LO)},
	[BPF_REG_3]  = {STACK_OFFSET(BPF_R3_HI),  STACK_OFFSET(BPF_R3_LO)},
	[BPF_REG_4]  = {STACK_OFFSET(BPF_R4_HI),  STACK_OFFSET(BPF_R4_LO)},
	[BPF_REG_5]  = {STACK_OFFSET(BPF_R5_HI),  STACK_OFFSET(BPF_R5_LO)},
	[BPF_REG_6]  = {STACK_OFFSET(BPF_R6_HI),  STACK_OFFSET(BPF_R6_LO)},
	[BPF_REG_7]  = {STACK_OFFSET(BPF_R7_HI),  STACK_OFFSET(BPF_R7_LO)},
	[BPF_REG_8]  = {STACK_OFFSET(BPF_R8_HI),  STACK_OFFSET(BPF_R8_LO)},
	[BPF_REG_9]  = {STACK_OFFSET(BPF_R9_HI),  STACK_OFFSET(BPF_R9_LO)},
	[BPF_REG_10] = {STACK_OFFSET(BPF_R10_HI), STACK_OFFSET(BPF_R10_LO)},
	[BPF_REG_AX] = {STACK_OFFSET(BPF_AX_HI),  STACK_OFFSET(BPF_AX_LO)},
	[TMP_REG_1]  = {M68K_D3, M68K_D2},
	[TMP_REG_2]  = {M68K_D5, M68K_D4},
};

struct jit_ctx {
	const struct bpf_prog *prog;
	u16 *target;
	unsigned int idx;
	int *offsets;
};

static noinline u32 jit_mul32(u32 a, u32 b) { return a * b; }
static noinline u32 jit_div32(u32 a, u32 b) { return b ? a / b : 0; }
static noinline u32 jit_mod32(u32 a, u32 b) { return b ? a % b : a; }
static noinline s32 jit_sdiv32(s32 a, s32 b) { return b ? a / b : 0; }
static noinline s32 jit_smod32(s32 a, s32 b) { return b ? a % b : a; }

static noinline u64 jit_mul64(u64 a, u64 b) { return a * b; }
static noinline u64 jit_div64(u64 a, u64 b) { return b ? div64_u64(a, b) : 0; }
static noinline s64 jit_sdiv64(s64 a, s64 b) { return b ? div64_s64(a, b) : 0; }

static noinline u64 jit_mod64(u64 a, u64 b)
{
	u64 rem = a;

	if (b)
		div64_u64_rem(a, b, &rem);
	return rem;
}

static noinline s64 jit_smod64(s64 a, s64 b)
{
	if (!b)
		return a;
	return a - div64_s64(a, b) * b;
}

static u32 jit_atomic32(u32 *ptr, u32 val, u32 op, u32 cmp)
{
	unsigned long flags;
	u32 old;

	local_irq_save(flags);
	old = *ptr;
	switch (op) {
	case BPF_ADD:
	case BPF_ADD | BPF_FETCH:
		*ptr += val;
		break;
	case BPF_AND:
	case BPF_AND | BPF_FETCH:
		*ptr &= val;
		break;
	case BPF_OR:
	case BPF_OR | BPF_FETCH:
		*ptr |= val;
		break;
	case BPF_XOR:
	case BPF_XOR | BPF_FETCH:
		*ptr ^= val;
		break;
	case BPF_XCHG:
		*ptr = val;
		break;
	case BPF_CMPXCHG:
		if (old == cmp)
			*ptr = val;
		break;
	}
	local_irq_restore(flags);

	return old;
}

static u64 jit_atomic64(u32 *ptr, u32 val_hi, u32 val_lo, u32 op, u32 cmp_hi, u32 cmp_lo)
{
	unsigned long flags;
	u64 old, val, cmp;
	u64 *ptr64 = (u64 *)ptr;

	val = ((u64)val_hi << 32) | val_lo;
	cmp = ((u64)cmp_hi << 32) | cmp_lo;

	local_irq_save(flags);
	old = *ptr64;
	switch (op) {
	case BPF_ADD:
	case BPF_ADD | BPF_FETCH:
		*ptr64 += val;
		break;
	case BPF_AND:
	case BPF_AND | BPF_FETCH:
		*ptr64 &= val;
		break;
	case BPF_OR:
	case BPF_OR | BPF_FETCH:
		*ptr64 |= val;
		break;
	case BPF_XOR:
	case BPF_XOR | BPF_FETCH:
		*ptr64 ^= val;
		break;
	case BPF_XCHG:
		*ptr64 = val;
		break;
	case BPF_CMPXCHG:
		if (old == cmp)
			*ptr64 = val;
		break;
	}
	local_irq_restore(flags);

	return old;
}

static inline void emit_16(struct jit_ctx *ctx, u16 inst)
{
	if (ctx->target)
		ctx->target[ctx->idx] = inst;
	ctx->idx++;
}

static inline void emit_32(struct jit_ctx *ctx, u32 val)
{
	emit_16(ctx, val >> 16);
	emit_16(ctx, val & 0xffff);
}

static inline bool is_stacked(s8 reg)
{
	return reg < 0;
}

static s8 bpf_get_reg32(s8 bpf_reg, s8 tmp_reg, struct jit_ctx *ctx)
{
	if (is_stacked(bpf_reg)) {
		emit_16(ctx, 0x202e | (tmp_reg << 9));		/* move.l d16(%fp), reg */
		emit_16(ctx, (u16)bpf_reg);
		return tmp_reg;
	}
	return bpf_reg;
}

static void bpf_put_reg32(s8 bpf_reg, s8 src_reg, struct jit_ctx *ctx)
{
	if (is_stacked(bpf_reg)) {
		emit_16(ctx, 0x2d40 | src_reg);			/* move.l reg, d16(%fp) */
		emit_16(ctx, (u16)bpf_reg);
	} else if (bpf_reg != src_reg) {
		emit_16(ctx, 0x2000 | (bpf_reg << 9) | src_reg); /* move.l src, dst */
	}
}

static void emit_alu32_neg(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	s8 d_reg = bpf_get_reg32(dst[1], tmp1[1], ctx);

	emit_16(ctx, 0x4480 | d_reg);				/* neg.l d_reg */

	bpf_put_reg32(dst[1], d_reg, ctx);
	emit_16(ctx, 0x7000 | (tmp1[0] << 9));			/* moveq #0, tmp1 */
	bpf_put_reg32(dst[0], tmp1[0], ctx);
}

static void emit_alu64_neg(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	s8 d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	s8 d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);

	emit_16(ctx, 0x4480 | d_lo);				/* neg.l d_lo */
	emit_16(ctx, 0x4080 | d_hi);				/* negx.l d_hi */

	bpf_put_reg32(dst[1], d_lo, ctx);
	bpf_put_reg32(dst[0], d_hi, ctx);
}

static void emit_alu32_x(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_reg, s_reg;

	d_reg = bpf_get_reg32(dst[1], tmp1[1], ctx);
	s_reg = bpf_get_reg32(src[1], tmp2[1], ctx);

	switch (BPF_OP(insn->code)) {
	case BPF_MOV:
		if (insn->off == 8 || insn->off == 16) {
			if (d_reg != s_reg)
				emit_16(ctx, 0x2000 | (d_reg << 9) | s_reg); /* move.l src, dst */
			if (insn->off == 8)
				emit_16(ctx, 0x49c0 | d_reg);	/* extb.l d_reg */
			else
				emit_16(ctx, 0x48c0 | d_reg);	/* ext.l d_reg */
		} else {
			if (d_reg != s_reg)
				emit_16(ctx, 0x2000 | (d_reg << 9) | s_reg); /* move.l src, dst */
		}
		break;
	case BPF_ADD:
		emit_16(ctx, 0xd080 | (d_reg << 9) | s_reg);	/* add.l src, dst */
		break;
	case BPF_SUB:
		emit_16(ctx, 0x9080 | (d_reg << 9) | s_reg);	/* sub.l src, dst */
		break;
	case BPF_AND:
		emit_16(ctx, 0xc080 | (d_reg << 9) | s_reg);	/* and.l src, dst */
		break;
	case BPF_OR:
		emit_16(ctx, 0x8080 | (d_reg << 9) | s_reg);	/* or.l src, dst */
		break;
	case BPF_XOR:
		emit_16(ctx, 0xb180 | (s_reg << 9) | d_reg);	/* eor.l src, dst */
		break;
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH: {
		s8 count_reg = tmp2[1];

		if (s_reg != count_reg)
			emit_16(ctx, 0x2000 | (count_reg << 9) | s_reg); /* move.l src, count */

		emit_16(ctx, 0x0280 | count_reg);		/* andi.l #imm, count */
		emit_32(ctx, 0x1f);

		if (BPF_OP(insn->code) == BPF_LSH)
			emit_16(ctx, 0xe1a8 | (count_reg << 9) | d_reg); /* lsl.l count, dst */
		else if (BPF_OP(insn->code) == BPF_RSH)
			emit_16(ctx, 0xe0a8 | (count_reg << 9) | d_reg); /* lsr.l count, dst */
		else
			emit_16(ctx, 0xe0a0 | (count_reg << 9) | d_reg); /* asr.l count, dst */
		break;
	}
	}

	bpf_put_reg32(dst[1], d_reg, ctx);
	emit_16(ctx, 0x7000 | (tmp1[0] << 9));			/* moveq #0, tmp1 */
	bpf_put_reg32(dst[0], tmp1[0], ctx);
}

static void emit_alu32_k(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_reg;

	d_reg = bpf_get_reg32(dst[1], tmp1[1], ctx);

	switch (BPF_OP(insn->code)) {
	case BPF_MOV:
		emit_16(ctx, 0x203c | (d_reg << 9));		/* move.l #imm, dst */
		emit_32(ctx, insn->imm);
		break;
	case BPF_ADD:
		emit_16(ctx, 0x0680 | d_reg);			/* addi.l #imm, dst */
		emit_32(ctx, insn->imm);
		break;
	case BPF_SUB:
		emit_16(ctx, 0x0480 | d_reg);			/* subi.l #imm, dst */
		emit_32(ctx, insn->imm);
		break;
	case BPF_AND:
		emit_16(ctx, 0x0280 | d_reg);			/* andi.l #imm, dst */
		emit_32(ctx, insn->imm);
		break;
	case BPF_OR:
		emit_16(ctx, 0x0080 | d_reg);			/* ori.l #imm, dst */
		emit_32(ctx, insn->imm);
		break;
	case BPF_XOR:
		emit_16(ctx, 0x0a80 | d_reg);			/* eori.l #imm, dst */
		emit_32(ctx, insn->imm);
		break;
	case BPF_LSH:
	case BPF_RSH:
	case BPF_ARSH:
		emit_16(ctx, 0x203c | (tmp2[1] << 9));		/* move.l #imm, count */
		emit_32(ctx, insn->imm & 0x1f);

		if (BPF_OP(insn->code) == BPF_LSH)
			emit_16(ctx, 0xe1a8 | (tmp2[1] << 9) | d_reg);	/* lsl.l count, dst */
		else if (BPF_OP(insn->code) == BPF_RSH)
			emit_16(ctx, 0xe0a8 | (tmp2[1] << 9) | d_reg);	/* lsr.l count, dst */
		else
			emit_16(ctx, 0xe0a0 | (tmp2[1] << 9) | d_reg);	/* asr.l count, dst */
		break;
	}

	bpf_put_reg32(dst[1], d_reg, ctx);
	emit_16(ctx, 0x7000 | (tmp1[0] << 9));			/* moveq #0, tmp1 */
	bpf_put_reg32(dst[0], tmp1[0], ctx);
}

static void emit_alu64_x(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_lo, d_hi, s_lo, s_hi;

	d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);
	s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);
	s_hi = bpf_get_reg32(src[0], tmp2[0], ctx);

	switch (BPF_OP(insn->code)) {
	case BPF_MOV:
		if (insn->off == 8 || insn->off == 16 || insn->off == 32) {
			if (d_lo != s_lo)
				emit_16(ctx, 0x2000 | (d_lo << 9) | s_lo); /* move.l src, dst */

			if (insn->off == 8)
				emit_16(ctx, 0x49c0 | d_lo);		/* extb.l d_lo */
			else if (insn->off == 16)
				emit_16(ctx, 0x48c0 | d_lo);		/* ext.l d_lo */

			emit_16(ctx, 0x4a80 | d_lo);			/* tst.l d_lo */
			emit_16(ctx, 0x6b04);				/* bmi.s .+6 */
			emit_16(ctx, 0x7000 | (d_hi << 9));		/* moveq #0, d_hi */
			emit_16(ctx, 0x6002);				/* bra.s .+4 */
			emit_16(ctx, 0x70ff | (d_hi << 9));		/* moveq #-1, d_hi */
		} else {
			if (d_lo != s_lo)
				emit_16(ctx, 0x2000 | (d_lo << 9) | s_lo); /* move.l s_lo, d_lo */
			if (d_hi != s_hi)
				emit_16(ctx, 0x2000 | (d_hi << 9) | s_hi); /* move.l s_hi, d_hi */
		}
		break;
	case BPF_ADD:
		emit_16(ctx, 0xd080 | (d_lo << 9) | s_lo);		/* add.l s_lo, d_lo */
		emit_16(ctx, 0xd180 | (d_hi << 9) | s_hi);		/* addx.l s_hi, d_hi */
		break;
	case BPF_SUB:
		emit_16(ctx, 0x9080 | (d_lo << 9) | s_lo);		/* sub.l s_lo, d_lo */
		emit_16(ctx, 0x9180 | (d_hi << 9) | s_hi);		/* subx.l s_hi, d_hi */
		break;
	case BPF_AND:
		emit_16(ctx, 0xc080 | (d_lo << 9) | s_lo);		/* and.l s_lo, d_lo */
		emit_16(ctx, 0xc080 | (d_hi << 9) | s_hi);		/* and.l s_hi, d_hi */
		break;
	case BPF_OR:
		emit_16(ctx, 0x8080 | (d_lo << 9) | s_lo);		/* or.l s_lo, d_lo */
		emit_16(ctx, 0x8080 | (d_hi << 9) | s_hi);		/* or.l s_hi, d_hi */
		break;
	case BPF_XOR:
		emit_16(ctx, 0xb180 | (s_lo << 9) | d_lo);		/* eor.l s_lo, d_lo */
		emit_16(ctx, 0xb180 | (s_hi << 9) | d_hi);		/* eor.l s_hi, d_hi */
		break;
	}

	bpf_put_reg32(dst[1], d_lo, ctx);
	bpf_put_reg32(dst[0], d_hi, ctx);
}

static void emit_alu64_k(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_lo, d_hi, s_lo, s_hi;
	u32 imm_lo = insn->imm;
	u32 imm_hi = insn->imm < 0 ? 0xffffffff : 0;

	d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);

	if (BPF_OP(insn->code) == BPF_MOV) {
		emit_16(ctx, 0x203c | (d_lo << 9));			/* move.l #imm, d_lo */
		emit_32(ctx, imm_lo);
		emit_16(ctx, 0x203c | (d_hi << 9));			/* move.l #imm, d_hi */
		emit_32(ctx, imm_hi);
		bpf_put_reg32(dst[1], d_lo, ctx);
		bpf_put_reg32(dst[0], d_hi, ctx);
		return;
	}

	s_lo = tmp2[1];
	s_hi = tmp2[0];

	emit_16(ctx, 0x203c | (s_lo << 9));				/* move.l #imm, s_lo */
	emit_32(ctx, imm_lo);
	emit_16(ctx, 0x203c | (s_hi << 9));				/* move.l #imm, s_hi */
	emit_32(ctx, imm_hi);

	switch (BPF_OP(insn->code)) {
	case BPF_ADD:
		emit_16(ctx, 0xd080 | (d_lo << 9) | s_lo);		/* add.l s_lo, d_lo */
		emit_16(ctx, 0xd180 | (d_hi << 9) | s_hi);		/* addx.l s_hi, d_hi */
		break;
	case BPF_SUB:
		emit_16(ctx, 0x9080 | (d_lo << 9) | s_lo);		/* sub.l s_lo, d_lo */
		emit_16(ctx, 0x9180 | (d_hi << 9) | s_hi);		/* subx.l s_hi, d_hi */
		break;
	case BPF_AND:
		emit_16(ctx, 0xc080 | (d_lo << 9) | s_lo);		/* and.l s_lo, d_lo */
		emit_16(ctx, 0xc080 | (d_hi << 9) | s_hi);		/* and.l s_hi, d_hi */
		break;
	case BPF_OR:
		emit_16(ctx, 0x8080 | (d_lo << 9) | s_lo);		/* or.l s_lo, d_lo */
		emit_16(ctx, 0x8080 | (d_hi << 9) | s_hi);		/* or.l s_hi, d_hi */
		break;
	case BPF_XOR:
		emit_16(ctx, 0xb180 | (s_lo << 9) | d_lo);		/* eor.l d_lo, s_lo */
		emit_16(ctx, 0xb180 | (s_hi << 9) | d_hi);		/* eor.l d_hi, s_hi */
		break;
	}

	bpf_put_reg32(dst[1], d_lo, ctx);
	bpf_put_reg32(dst[0], d_hi, ctx);
}

static void emit_alu64_shift(const struct bpf_insn *insn, struct jit_ctx *ctx, bool is_imm)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_lo, d_hi, count_reg;
	int loop_start, done_idx;

	d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);
	count_reg = tmp2[1];

	if (is_imm) {
		emit_16(ctx, 0x203c | (count_reg << 9));		/* move.l #imm, count_reg */
		emit_32(ctx, insn->imm);
	} else {
		const s8 *src = bpf2m68k[insn->src_reg];
		s8 s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);

		if (count_reg != s_lo)
			emit_16(ctx, 0x2000 | (count_reg << 9) | s_lo);	/* move.l s_lo, count_reg */
	}

	emit_16(ctx, 0x0280 | count_reg);			/* andi.l #0x3f, count_reg */
	emit_32(ctx, 0x3f);

	emit_16(ctx, 0x4a80 | count_reg);				/* tst.l count_reg */
	emit_16(ctx, 0x6700);						/* beq.w done_idx */
	done_idx = ctx->idx;
	emit_16(ctx, 0);

	loop_start = ctx->idx;

	if (BPF_OP(insn->code) == BPF_LSH) {
		emit_16(ctx, 0xe388 | d_lo);				/* lsll #1, d_lo */
		emit_16(ctx, 0xe390 | d_hi);				/* roxl.l #1, d_hi */
	} else if (BPF_OP(insn->code) == BPF_RSH) {
		emit_16(ctx, 0xe288 | d_hi);				/* lsrl #1, d_hi */
		emit_16(ctx, 0xe290 | d_lo);				/* roxr.l #1, d_lo */
	} else if (BPF_OP(insn->code) == BPF_ARSH) {
		emit_16(ctx, 0xe280 | d_hi);				/* asrl #1, d_hi */
		emit_16(ctx, 0xe290 | d_lo);				/* roxr.l #1, d_lo */
	}

	emit_16(ctx, 0x5380 | count_reg);				/* subq.l #1, count_reg */
	emit_16(ctx, 0x6600);						/* bne.w loop_start */
	emit_16(ctx, (loop_start - (int)ctx->idx) * 2);

	if (ctx->target)
		ctx->target[done_idx] = (ctx->idx - done_idx) * 2;

	bpf_put_reg32(dst[1], d_lo, ctx);
	bpf_put_reg32(dst[0], d_hi, ctx);
}

static void emit_bpf_end(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	s8 d_lo, d_hi;
	bool to_le = BPF_SRC(insn->code) == BPF_TO_LE;
	int imm = insn->imm;

	d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);

	if (to_le) {
		switch (imm) {
		case 16:
			emit_16(ctx, 0x0280 | d_lo);			/* andi.l #0xffff, d_lo */
			emit_32(ctx, 0xffff);
			emit_16(ctx, 0xe058 | d_lo);			/* ror.w #8, d_lo */
			emit_16(ctx, 0x7000 | (d_hi << 9));		/* moveq #0, d_hi */
			break;
		case 32:
			emit_16(ctx, 0xe058 | d_lo);			/* ror.w #8, d_lo */
			emit_16(ctx, 0x4840 | d_lo);			/* swap d_lo */
			emit_16(ctx, 0xe058 | d_lo);			/* ror.w #8, d_lo */
			emit_16(ctx, 0x7000 | (d_hi << 9));		/* moveq #0, d_hi */
			break;
		case 64:
			emit_16(ctx, 0xe058 | d_lo);			/* ror.w #8, d_lo */
			emit_16(ctx, 0x4840 | d_lo);			/* swap d_lo */
			emit_16(ctx, 0xe058 | d_lo);			/* ror.w #8, d_lo */

			emit_16(ctx, 0xe058 | d_hi);			/* ror.w #8, d_hi */
			emit_16(ctx, 0x4840 | d_hi);			/* swap d_hi */
			emit_16(ctx, 0xe058 | d_hi);			/* ror.w #8, d_hi */

			emit_16(ctx, 0xc140 | (d_hi << 9) | d_lo);	/* exg d_lo, d_hi */
			break;
		}
	} else {
		switch (imm) {
		case 16:
			emit_16(ctx, 0x0280 | d_lo);			/* andi.l #0xffff, d_lo */
			emit_32(ctx, 0xffff);
			emit_16(ctx, 0x7000 | (d_hi << 9));		/* moveq #0, d_hi */
			break;
		case 32:
			emit_16(ctx, 0x7000 | (d_hi << 9));		/* moveq #0, d_hi */
			break;
		case 64:
			break;
		}
	}

	bpf_put_reg32(dst[1], d_lo, ctx);
	bpf_put_reg32(dst[0], d_hi, ctx);
}

static void emit_math_call(const struct bpf_insn *insn, struct jit_ctx *ctx, bool is_64)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_lo, d_hi, s_lo, s_hi = 0;
	void *func = NULL;
	u8 op = BPF_OP(insn->code);

	d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);

	if (BPF_SRC(insn->code) == BPF_X) {
		s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);
		if (is_64)
			s_hi = bpf_get_reg32(src[0], tmp2[0], ctx);
	} else {
		s_lo = tmp2[1];
		emit_16(ctx, 0x203c | (s_lo << 9));			/* move.l #imm, s_lo */
		emit_32(ctx, insn->imm);
		if (is_64) {
			s_hi = tmp2[0];
			emit_16(ctx, 0x203c | (s_hi << 9));		/* move.l #imm, s_hi */
			emit_32(ctx, insn->imm < 0 ? 0xffffffff : 0);
		}
	}

	if (is_64) {
		switch (op) {
		case BPF_MUL:
			func = (void *)jit_mul64;
			break;
		case BPF_DIV:
			func = (void *)jit_div64;
			break;
		case BPF_MOD:
			func = (void *)jit_mod64;
			break;
		}
		if (BPF_CLASS(insn->code) == BPF_ALU64 && op == BPF_DIV && insn->off == 1)
			func = (void *)jit_sdiv64;
		if (BPF_CLASS(insn->code) == BPF_ALU64 && op == BPF_MOD && insn->off == 1)
			func = (void *)jit_smod64;
	} else {
		switch (op) {
		case BPF_MUL:
			func = (void *)jit_mul32;
			break;
		case BPF_DIV:
			func = (void *)jit_div32;
			break;
		case BPF_MOD:
			func = (void *)jit_mod32;
			break;
		}
		if (BPF_CLASS(insn->code) == BPF_ALU && op == BPF_DIV && insn->off == 1)
			func = (void *)jit_sdiv32;
		if (BPF_CLASS(insn->code) == BPF_ALU && op == BPF_MOD && insn->off == 1)
			func = (void *)jit_smod32;
	}

	if (is_64) {
		emit_16(ctx, 0x48e7);					/* movem.l d0-d1, -(%sp) */
		emit_16(ctx, 0xc000);

		emit_16(ctx, 0x2f00 | s_lo);				/* move.l s_lo, -(%sp) */
		emit_16(ctx, 0x2f00 | s_hi);				/* move.l s_hi, -(%sp) */
		emit_16(ctx, 0x2f00 | d_lo);				/* move.l d_lo, -(%sp) */
		emit_16(ctx, 0x2f00 | d_hi);				/* move.l d_hi, -(%sp) */

		emit_16(ctx, 0x207c);					/* movea.l #func, %a0 */
		emit_32(ctx, (u32)func);
		emit_16(ctx, 0x4e90);					/* jsr (%a0) */

		emit_16(ctx, 0x4fef);					/* lea 16(%sp), %sp */
		emit_16(ctx, 16);

		emit_16(ctx, 0x2601);					/* move.l %d1, %d3 */
		emit_16(ctx, 0x2400);					/* move.l %d0, %d2 */

		emit_16(ctx, 0x4cdf);					/* movem.l (%sp)+, d0-d1 */
		emit_16(ctx, 0x0003);
	} else {
		emit_16(ctx, 0x48e7);					/* movem.l d0-d1, -(%sp) */
		emit_16(ctx, 0xc000);

		emit_16(ctx, 0x2f00 | s_lo);				/* move.l s_lo, -(%sp) */
		emit_16(ctx, 0x2f00 | d_lo);				/* move.l d_lo, -(%sp) */

		emit_16(ctx, 0x207c);					/* movea.l #func, %a0 */
		emit_32(ctx, (u32)func);
		emit_16(ctx, 0x4e90);					/* jsr (%a0) */

		emit_16(ctx, 0x4fef);					/* lea 8(%sp), %sp */
		emit_16(ctx, 8);

		emit_16(ctx, 0x2600);					/* move.l %d0, %d3 */
		emit_16(ctx, 0x7400);					/* moveq #0, %d2 */

		emit_16(ctx, 0x4cdf);					/* movem.l (%sp)+, d0-d1 */
		emit_16(ctx, 0x0003);
	}

	bpf_put_reg32(dst[1], M68K_D3, ctx);
	bpf_put_reg32(dst[0], M68K_D2, ctx);
}

static void emit_ldx(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	s8 d_lo, d_hi;
	bool is_mem_sx = BPF_MODE(insn->code) == BPF_MEMSX;

	if (is_stacked(src[1])) {
		emit_16(ctx, 0x206e);				/* movea.l d16(%fp), %a0 */
		emit_16(ctx, (u16)src[1]);
	} else {
		emit_16(ctx, 0x2040 | src[1]);			/* movea.l src, %a0 */
	}

	d_lo = is_stacked(dst[1]) ? tmp1[1] : dst[1];
	d_hi = is_stacked(dst[0]) ? tmp1[0] : dst[0];

	switch (BPF_SIZE(insn->code)) {
	case BPF_B:
		if (!is_mem_sx)
			emit_16(ctx, 0x7000 | (d_lo << 9));	/* moveq #0, d_lo */
		emit_16(ctx, 0x1028 | (d_lo << 9));		/* move.b d16(%a0), d_lo */
		emit_16(ctx, insn->off);
		if (is_mem_sx)
			emit_16(ctx, 0x49c0 | d_lo);	/* extb.l d_lo */
		break;
	case BPF_H:
		if (!is_mem_sx)
			emit_16(ctx, 0x7000 | (d_lo << 9));	/* moveq #0, d_lo */
		emit_16(ctx, 0x3028 | (d_lo << 9));		/* move.w d16(%a0), d_lo */
		emit_16(ctx, insn->off);
		if (is_mem_sx)
			emit_16(ctx, 0x48c0 | d_lo);	/* ext.l d_lo */
		break;
	case BPF_W:
		emit_16(ctx, 0x2028 | (d_lo << 9));		/* move.l d16(%a0), d_lo */
		emit_16(ctx, insn->off);
		break;
	case BPF_DW:
		emit_16(ctx, 0x2028 | (d_hi << 9));		/* move.l d16(%a0), d_hi */
		emit_16(ctx, insn->off);
		emit_16(ctx, 0x41e8);				/* lea 4(%a0), %a0 */
		emit_16(ctx, 4);
		emit_16(ctx, 0x2028 | (d_lo << 9));		/* move.l d16(%a0), d_lo */
		emit_16(ctx, insn->off);
		break;
	}

	if (BPF_SIZE(insn->code) != BPF_DW) {
		if (is_mem_sx) {
			emit_16(ctx, 0x4a80 | d_lo);		/* tst.l d_lo */
			emit_16(ctx, 0x6b04);			/* bmi.s .+6 */
			emit_16(ctx, 0x7000 | (d_hi << 9));	/* moveq #0, d_hi */
			emit_16(ctx, 0x6002);			/* bra.s .+4 */
			emit_16(ctx, 0x70ff | (d_hi << 9));	/* moveq #-1, d_hi */
		} else {
			emit_16(ctx, 0x7000 | (d_hi << 9));	/* moveq #0, d_hi */
		}
	}

	bpf_put_reg32(dst[1], d_lo, ctx);
	bpf_put_reg32(dst[0], d_hi, ctx);
}

static void emit_stx(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 s_lo, s_hi;

	if (is_stacked(dst[1])) {
		emit_16(ctx, 0x206e);				/* movea.l d16(%fp), %a0 */
		emit_16(ctx, (u16)dst[1]);
	} else {
		emit_16(ctx, 0x2040 | dst[1]);			/* movea.l dst, %a0 */
	}

	s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);

	switch (BPF_SIZE(insn->code)) {
	case BPF_B:
		emit_16(ctx, 0x1140 | s_lo);			/* move.b s_lo, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	case BPF_H:
		emit_16(ctx, 0x3140 | s_lo);			/* move.w s_lo, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	case BPF_W:
		emit_16(ctx, 0x2140 | s_lo);			/* move.l s_lo, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	case BPF_DW:
		s_hi = bpf_get_reg32(src[0], tmp2[0], ctx);
		emit_16(ctx, 0x2140 | s_hi);			/* move.l s_hi, d16(%a0) */
		emit_16(ctx, insn->off);
		emit_16(ctx, 0x41e8);				/* lea 4(%a0), %a0 */
		emit_16(ctx, 4);
		emit_16(ctx, 0x2140 | s_lo);			/* move.l s_lo, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	}
}

static void emit_st(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *tmp = bpf2m68k[TMP_REG_1];

	if (is_stacked(dst[1])) {
		emit_16(ctx, 0x206e);				/* movea.l d16(%fp), %a0 */
		emit_16(ctx, (u16)dst[1]);
	} else {
		emit_16(ctx, 0x2040 | dst[1]);			/* movea.l dst, %a0 */
	}

	emit_16(ctx, 0x203c | (tmp[1] << 9));			/* move.l #imm, tmp */
	emit_32(ctx, insn->imm);

	switch (BPF_SIZE(insn->code)) {
	case BPF_B:
		emit_16(ctx, 0x1140 | tmp[1]);			/* move.b tmp, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	case BPF_H:
		emit_16(ctx, 0x3140 | tmp[1]);			/* move.w tmp, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	case BPF_W:
		emit_16(ctx, 0x2140 | tmp[1]);			/* move.l tmp, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	case BPF_DW:
		emit_16(ctx, 0x203c | (tmp[0] << 9));		/* move.l #imm, tmp */
		emit_32(ctx, insn->imm < 0 ? 0xffffffff : 0);

		emit_16(ctx, 0x2140 | tmp[0]);			/* move.l tmp, d16(%a0) */
		emit_16(ctx, insn->off);
		emit_16(ctx, 0x41e8);				/* lea 4(%a0), %a0 */
		emit_16(ctx, 4);
		emit_16(ctx, 0x2140 | tmp[1]);			/* move.l tmp, d16(%a0) */
		emit_16(ctx, insn->off);
		break;
	}
}

static void emit_atomic(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];

	if (is_stacked(dst[1])) {
		emit_16(ctx, 0x206e);				/* movea.l d16(%fp), %a0 */
		emit_16(ctx, (u16)dst[1]);
	} else {
		emit_16(ctx, 0x2040 | dst[1]);			/* movea.l dst, %a0 */
	}

	if (insn->off) {
		emit_16(ctx, 0x41e8);				/* lea d16(%a0), %a0 */
		emit_16(ctx, insn->off);
	}

	if (BPF_SIZE(insn->code) == BPF_W) {
		s8 s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);

		if (insn->imm != BPF_CMPXCHG) {
			emit_16(ctx, 0x48e7);			/* movem.l d0-d1, -(%sp) */
			emit_16(ctx, 0xc000);
		}

		emit_16(ctx, 0x2f00 | M68K_D0);			/* move.l %d0, -(%sp) */
		emit_16(ctx, 0x2f3c);				/* move.l #imm, -(%sp) */
		emit_32(ctx, insn->imm);
		emit_16(ctx, 0x2f00 | s_lo);			/* move.l s_lo, -(%sp) */
		emit_16(ctx, 0x2f08);				/* move.l %a0, -(%sp) */

		emit_16(ctx, 0x207c);				/* movea.l #func, %a0 */
		emit_32(ctx, (u32)jit_atomic32);
		emit_16(ctx, 0x4e90);				/* jsr (%a0) */

		emit_16(ctx, 0x4fef);				/* lea 16(%sp), %sp */
		emit_16(ctx, 16);

		if (insn->imm == BPF_CMPXCHG) {
			emit_16(ctx, 0x7200);			/* moveq #0, %d1 */
		} else {
			bool is_fetch = (insn->imm & BPF_FETCH) || insn->imm == BPF_XCHG;

			if (is_fetch)
				emit_16(ctx, 0x2600);		/* move.l %d0, %d3 */

			emit_16(ctx, 0x4cdf);			/* movem.l (%sp)+, d0-d1 */
			emit_16(ctx, 0x0003);

			if (is_fetch) {
				bpf_put_reg32(src[1], M68K_D3, ctx);
				emit_16(ctx, 0x7400);		/* moveq #0, %d2 */
				bpf_put_reg32(src[0], M68K_D2, ctx);
			}
		}

	} else if (BPF_SIZE(insn->code) == BPF_DW) {
		s8 s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);
		s8 s_hi = bpf_get_reg32(src[0], tmp2[0], ctx);

		if (insn->imm != BPF_CMPXCHG) {
			emit_16(ctx, 0x48e7);			/* movem.l d0-d1, -(%sp) */
			emit_16(ctx, 0xc000);
		}

		emit_16(ctx, 0x2f00 | M68K_D0);			/* move.l %d0, -(%sp) */
		emit_16(ctx, 0x2f00 | M68K_D1);			/* move.l %d1, -(%sp) */
		emit_16(ctx, 0x2f3c);				/* move.l #imm, -(%sp) */
		emit_32(ctx, insn->imm);
		emit_16(ctx, 0x2f00 | s_lo);			/* move.l s_lo, -(%sp) */
		emit_16(ctx, 0x2f00 | s_hi);			/* move.l s_hi, -(%sp) */
		emit_16(ctx, 0x2f08);				/* move.l %a0, -(%sp) */

		emit_16(ctx, 0x207c);				/* movea.l #func, %a0 */
		emit_32(ctx, (u32)jit_atomic64);
		emit_16(ctx, 0x4e90);				/* jsr (%a0) */

		emit_16(ctx, 0x4fef);				/* lea 24(%sp), %sp */
		emit_16(ctx, 24);

		if (insn->imm == BPF_CMPXCHG) {
			emit_16(ctx, 0xc141);			/* exg %d0, %d1 */
		} else {
			bool is_fetch = (insn->imm & BPF_FETCH) || insn->imm == BPF_XCHG;

			if (is_fetch) {
				emit_16(ctx, 0x2600);		/* move.l %d0, %d3 */
				emit_16(ctx, 0x2401);		/* move.l %d1, %d2 */
			}

			emit_16(ctx, 0x4cdf);			/* movem.l (%sp)+, d0-d1 */
			emit_16(ctx, 0x0003);

			if (is_fetch) {
				bpf_put_reg32(src[1], M68K_D2, ctx);
				bpf_put_reg32(src[0], M68K_D3, ctx);
			}
		}
	}
}

static void emit_tail_call(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 *r2 = bpf2m68k[BPF_REG_2];
	const s8 *r3 = bpf2m68k[BPF_REG_3];
	int jmp_out_1, jmp_out_2, jmp_out_3;

	if (is_stacked(r2[1])) {
		emit_16(ctx, 0x206e);				/* movea.l d16(%fp), %a0 */
		emit_16(ctx, (u16)r2[1]);
	} else {
		emit_16(ctx, 0x2040 | r2[1]);			/* movea.l r2, %a0 */
	}

	if (is_stacked(r3[1])) {
		emit_16(ctx, 0x242e);				/* move.l d16(%fp), %d2 */
		emit_16(ctx, (u16)r3[1]);
	} else {
		emit_16(ctx, 0x2400 | r3[1]);			/* move.l r3, %d2 */
	}

	emit_16(ctx, 0xb4a8);					/* cmp.l d16(%a0), %d2 */
	emit_16(ctx, offsetof(struct bpf_array, map.max_entries));
	emit_16(ctx, 0x6400);					/* bcc.w jmp_out_1 */
	jmp_out_1 = ctx->idx;
	emit_16(ctx, 0);

	emit_16(ctx, 0x262e);					/* move.l d16(%fp), %d3 */
	emit_16(ctx, (u16)STACK_OFFSET(BPF_TC_LO));
	emit_16(ctx, 0x4a83);					/* tst.l %d3 */
	emit_16(ctx, 0x6700);					/* beq.w jmp_out_2 */
	jmp_out_2 = ctx->idx;
	emit_16(ctx, 0);

	emit_16(ctx, 0x5383);					/* subq.l #1, %d3 */
	emit_16(ctx, 0x2d43);					/* move.l %d3, d16(%fp) */
	emit_16(ctx, (u16)STACK_OFFSET(BPF_TC_LO));

	emit_16(ctx, 0xd482);					/* add.l %d2, %d2 */
	emit_16(ctx, 0xd482);					/* add.l %d2, %d2 */
	emit_16(ctx, 0x43e8);					/* lea d16(%a0), %a1 */
	emit_16(ctx, offsetof(struct bpf_array, ptrs));
	emit_16(ctx, 0xd3c2);					/* adda.l %d2, %a1 */

	emit_16(ctx, 0x2051);					/* movea.l (%a1), %a0 */

	emit_16(ctx, 0x2408);					/* move.l %a0, %d2 */
	emit_16(ctx, 0x4a82);					/* tst.l %d2 */
	emit_16(ctx, 0x6700);					/* beq.w jmp_out_3 */
	jmp_out_3 = ctx->idx;
	emit_16(ctx, 0);

	emit_16(ctx, 0x2068);					/* movea.l d16(%a0), %a0 */
	emit_16(ctx, offsetof(struct bpf_prog, bpf_func));

	emit_16(ctx, 0x4ee8);					/* jmp d16(%a0) */
	emit_16(ctx, 44);

	if (ctx->target) {
		ctx->target[jmp_out_1] = (ctx->idx - jmp_out_1) * 2;
		ctx->target[jmp_out_2] = (ctx->idx - jmp_out_2) * 2;
		ctx->target[jmp_out_3] = (ctx->idx - jmp_out_3) * 2;
	}
}

static int emit_jmp(const struct bpf_insn *insn, struct jit_ctx *ctx, int curr_i)
{
	const s8 *dst = bpf2m68k[insn->dst_reg];
	const s8 *src = bpf2m68k[insn->src_reg];
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	const s8 *tmp2 = bpf2m68k[TMP_REG_2];
	s8 d_lo, d_hi = 0, s_lo, s_hi = 0;
	bool is_jmp32 = BPF_CLASS(insn->code) == BPF_JMP32;
	u8 op = BPF_OP(insn->code);
	int target_insn;

	if (is_jmp32 && op == BPF_JA)
		target_insn = curr_i + 1 + insn->imm;
	else
		target_insn = curr_i + 1 + insn->off;

	if (target_insn < 0 || target_insn > ctx->prog->len)
		return -EOPNOTSUPP;

	#define EMIT_JMP32(op_base) \
		do { \
			int disp = (ctx->offsets[target_insn] - (ctx->idx + 1)) * 2; \
			emit_16(ctx, (op_base) | 0x00ff); \
			emit_32(ctx, disp); \
		} while (0)

	if (op == BPF_JA) {
		EMIT_JMP32(0x6000);				/* bra.l */
		return 0;
	}

	d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
	if (!is_jmp32)
		d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);

	if (BPF_SRC(insn->code) == BPF_X) {
		s_lo = bpf_get_reg32(src[1], tmp2[1], ctx);
		if (!is_jmp32)
			s_hi = bpf_get_reg32(src[0], tmp2[0], ctx);
	} else {
		s_lo = tmp2[1];
		emit_16(ctx, 0x203c | (s_lo << 9));		/* move.l #imm, s_lo */
		emit_32(ctx, insn->imm);
		if (!is_jmp32) {
			s_hi = tmp2[0];
			emit_16(ctx, 0x203c | (s_hi << 9));	/* move.l #imm, s_hi */
			emit_32(ctx, insn->imm < 0 ? 0xffffffff : 0);
		}
	}

	if (op == BPF_JSET) {
		emit_16(ctx, 0x2000 | (tmp1[1] << 9) | d_lo);	/* move.l d_lo, tmp1_lo */
		emit_16(ctx, 0xc080 | (tmp1[1] << 9) | s_lo);	/* and.l s_lo, tmp1_lo */

		if (!is_jmp32) {
			EMIT_JMP32(0x6600);			/* bne.l */
			emit_16(ctx, 0x2000 | (tmp1[0] << 9) | d_hi); /* move.l d_hi, tmp1_hi */
			emit_16(ctx, 0xc080 | (tmp1[0] << 9) | s_hi); /* and.l s_hi, tmp1_hi */
		}
		EMIT_JMP32(0x6600);				/* bne.l */
		return 0;
	}

	if (is_jmp32) {
		emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo);	/* cmp.l s_lo, d_lo */
		switch (op) {
		case BPF_JEQ:
			EMIT_JMP32(0x6700);			/* beq.l */
			break;
		case BPF_JNE:
			EMIT_JMP32(0x6600);			/* bne.l */
			break;
		case BPF_JGT:
			EMIT_JMP32(0x6200);			/* bhi.l */
			break;
		case BPF_JGE:
			EMIT_JMP32(0x6400);			/* bcc.l */
			break;
		case BPF_JLT:
			EMIT_JMP32(0x6500);			/* bcs.l */
			break;
		case BPF_JLE:
			EMIT_JMP32(0x6300);			/* bls.l */
			break;
		case BPF_JSGT:
			EMIT_JMP32(0x6e00);			/* bgt.l */
			break;
		case BPF_JSGE:
			EMIT_JMP32(0x6c00);			/* bge.l */
			break;
		case BPF_JSLT:
			EMIT_JMP32(0x6d00);			/* blt.l */
			break;
		case BPF_JSLE:
			EMIT_JMP32(0x6f00);			/* ble.l */
			break;
		}
	} else {
		emit_16(ctx, 0xb080 | (d_hi << 9) | s_hi);	/* cmp.l s_hi, d_hi */

		switch (op) {
		case BPF_JEQ:
			emit_16(ctx, 0x6608);			/* bne.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6700);			/* beq.l */
			break;
		case BPF_JNE:
			EMIT_JMP32(0x6600);			/* bne.l */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6600);			/* bne.l */
			break;
		case BPF_JGT:
			EMIT_JMP32(0x6200);			/* bhi.l */
			emit_16(ctx, 0x6508);			/* bcs.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6200);			/* bhi.l */
			break;
		case BPF_JGE:
			EMIT_JMP32(0x6200);			/* bhi.l */
			emit_16(ctx, 0x6508);			/* bcs.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6400);			/* bcc.l */
			break;
		case BPF_JLT:
			EMIT_JMP32(0x6500);			/* bcs.l */
			emit_16(ctx, 0x6208);			/* bhi.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6500);			/* bcs.l */
			break;
		case BPF_JLE:
			EMIT_JMP32(0x6500);			/* bcs.l */
			emit_16(ctx, 0x6208);			/* bhi.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6300);			/* bls.l */
			break;
		case BPF_JSGT:
			EMIT_JMP32(0x6e00);			/* bgt.l */
			emit_16(ctx, 0x6d08);			/* blt.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6200);			/* bhi.l */
			break;
		case BPF_JSGE:
			EMIT_JMP32(0x6e00);			/* bgt.l */
			emit_16(ctx, 0x6d08);			/* blt.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6400);			/* bcc.l */
			break;
		case BPF_JSLT:
			EMIT_JMP32(0x6d00);			/* blt.l */
			emit_16(ctx, 0x6e08);			/* bgt.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6500);			/* bcs.l */
			break;
		case BPF_JSLE:
			EMIT_JMP32(0x6d00);			/* blt.l */
			emit_16(ctx, 0x6e08);			/* bgt.s .+8 */
			emit_16(ctx, 0xb080 | (d_lo << 9) | s_lo); /* cmp.l s_lo, d_lo */
			EMIT_JMP32(0x6300);			/* bls.l */
			break;
		}
	}
	#undef EMIT_JMP32
	return 0;
}

static int emit_call(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const s8 arg_regs[] = { BPF_REG_5, BPF_REG_4, BPF_REG_3, BPF_REG_2, BPF_REG_1 };
	const s8 *tmp1 = bpf2m68k[TMP_REG_1];
	bool extra_pass = ctx->target != NULL;
	u64 func_addr;
	bool fixed;
	int i, err;

	err = bpf_jit_get_func_addr(ctx->prog, insn, extra_pass, &func_addr, &fixed);
	if (err)
		return err;

	for (i = 0; i < 5; i++) {
		const s8 *reg = bpf2m68k[arg_regs[i]];
		s8 d_lo = bpf_get_reg32(reg[1], tmp1[1], ctx);
		s8 d_hi = bpf_get_reg32(reg[0], tmp1[0], ctx);

		emit_16(ctx, 0x2f00 | d_lo);			/* move.l d_lo, -(%sp) */
		emit_16(ctx, 0x2f00 | d_hi);			/* move.l d_hi, -(%sp) */
	}

	emit_16(ctx, 0x207c);					/* movea.l #func_addr, %a0 */
	emit_32(ctx, (u32)func_addr);

	emit_16(ctx, 0x4e90);					/* jsr (%a0) */

	emit_16(ctx, 0x4fef);					/* lea 40(%sp), %sp */
	emit_16(ctx, 40);

	emit_16(ctx, 0xc340);					/* exg %d0, %d1 */

	return 0;
}

static void build_prologue(struct jit_ctx *ctx)
{
	int bpf_stack = 512;
	int total_stack = SCRATCH_SIZE + bpf_stack;

	emit_16(ctx, 0x7021);					/* moveq #33, %d0 */

	emit_16(ctx, 0x4e56);					/* link %a6, #-total_stack */
	emit_16(ctx, -total_stack);

	emit_16(ctx, 0x48e7);					/* movem.l d2-d5, -(%sp) */
	emit_16(ctx, 0x3c00);

	emit_16(ctx, 0x2d40);					/* move.l %d0, off(%fp) */
	emit_16(ctx, (u16)STACK_OFFSET(BPF_TC_LO));

	emit_16(ctx, 0x202e);					/* move.l 8(%fp), %d0 */
	emit_16(ctx, 8);

	bpf_put_reg32(bpf2m68k[BPF_REG_1][1], M68K_D0, ctx);
	emit_16(ctx, 0x7000 | (M68K_D0 << 9));			/* moveq #0, %d0 */
	bpf_put_reg32(bpf2m68k[BPF_REG_1][0], M68K_D0, ctx);

	emit_16(ctx, 0x41ee);					/* lea -SCRATCH_SIZE(%fp), %a0 */
	emit_16(ctx, -SCRATCH_SIZE);
	emit_16(ctx, 0x2008);					/* move.l %a0, %d0 */

	bpf_put_reg32(bpf2m68k[BPF_REG_10][1], M68K_D0, ctx);
	emit_16(ctx, 0x7000 | (M68K_D0 << 9));			/* moveq #0, %d0 */
	bpf_put_reg32(bpf2m68k[BPF_REG_10][0], M68K_D0, ctx);
}

static void build_epilogue(struct jit_ctx *ctx)
{
	emit_16(ctx, 0x4cdf);					/* movem.l (%sp)+, d2-d5 */
	emit_16(ctx, 0x003c);

	emit_16(ctx, 0x4e5e);					/* unlk %fp */
	emit_16(ctx, 0x4e75);					/* rts */
}

static int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx, int i)
{
	u8 code = insn->code;

	switch (code) {
	case BPF_ALU | BPF_NEG:
		emit_alu32_neg(insn, ctx);
		break;
	case BPF_ALU64 | BPF_NEG:
		emit_alu64_neg(insn, ctx);
		break;

	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_OR  | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_X:
		emit_alu32_x(insn, ctx);
		break;

	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU | BPF_OR  | BPF_K:
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU | BPF_RSH | BPF_K:
	case BPF_ALU | BPF_ARSH | BPF_K:
		emit_alu32_k(insn, ctx);
		break;

	case BPF_ALU64 | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_OR  | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit_alu64_x(insn, ctx);
		break;

	case BPF_ALU64 | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_OR  | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
		emit_alu64_k(insn, ctx);
		break;

	case BPF_ALU64 | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit_alu64_shift(insn, ctx, false);
		break;

	case BPF_ALU64 | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_RSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		emit_alu64_shift(insn, ctx, true);
		break;

	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU | BPF_MOD | BPF_K:
		emit_math_call(insn, ctx, false);
		break;

	case BPF_ALU64 | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		emit_math_call(insn, ctx, true);
		break;

	case BPF_ALU | BPF_END | BPF_TO_BE:
	case BPF_ALU | BPF_END | BPF_TO_LE:
	case BPF_ALU64 | BPF_END | BPF_TO_BE:
	case BPF_ALU64 | BPF_END | BPF_TO_LE:
		emit_bpf_end(insn, ctx);
		break;

	case BPF_LD | BPF_IMM | BPF_DW: {
		const struct bpf_insn *insn1 = insn + 1;
		const s8 *dst = bpf2m68k[insn->dst_reg];
		const s8 *tmp1 = bpf2m68k[TMP_REG_1];
		s8 d_lo = bpf_get_reg32(dst[1], tmp1[1], ctx);
		s8 d_hi = bpf_get_reg32(dst[0], tmp1[0], ctx);

		emit_16(ctx, 0x203c | (d_lo << 9));			/* move.l #imm, d_lo */
		emit_32(ctx, insn->imm);
		emit_16(ctx, 0x203c | (d_hi << 9));			/* move.l #imm, d_hi */
		emit_32(ctx, insn1->imm);

		bpf_put_reg32(dst[1], d_lo, ctx);
		bpf_put_reg32(dst[0], d_hi, ctx);
		break;
	}

	case BPF_LDX | BPF_MEM | BPF_B:
	case BPF_LDX | BPF_MEM | BPF_H:
	case BPF_LDX | BPF_MEM | BPF_W:
	case BPF_LDX | BPF_MEM | BPF_DW:
	case BPF_LDX | BPF_MEMSX | BPF_B:
	case BPF_LDX | BPF_MEMSX | BPF_H:
	case BPF_LDX | BPF_MEMSX | BPF_W:
		emit_ldx(insn, ctx);
		break;

	case BPF_STX | BPF_MEM | BPF_B:
	case BPF_STX | BPF_MEM | BPF_H:
	case BPF_STX | BPF_MEM | BPF_W:
	case BPF_STX | BPF_MEM | BPF_DW:
		emit_stx(insn, ctx);
		break;

	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_DW:
		emit_st(insn, ctx);
		break;

	case BPF_STX | BPF_ATOMIC | BPF_W:
	case BPF_STX | BPF_ATOMIC | BPF_DW:
		emit_atomic(insn, ctx);
		break;

	case BPF_JMP | BPF_TAIL_CALL:
		emit_tail_call(insn, ctx);
		break;

	case BPF_JMP | BPF_JA:
	case BPF_JMP32 | BPF_JA:
	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_K:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_K:
	case BPF_JMP32 | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_K:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_K:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
	case BPF_JMP32 | BPF_JSET | BPF_X:
	case BPF_JMP32 | BPF_JSET | BPF_K:
		return emit_jmp(insn, ctx, i);

	case BPF_JMP | BPF_CALL:
		return emit_call(insn, ctx);

	case BPF_JMP | BPF_EXIT:
		build_epilogue(ctx);
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int build_body(struct jit_ctx *ctx)
{
	const struct bpf_prog *prog = ctx->prog;
	int i;

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		if (!ctx->target)
			ctx->offsets[i] = ctx->idx;

		ret = build_insn(insn, ctx, i);
		if (ret < 0)
			return ret;

		if (insn->code == (BPF_LD | BPF_IMM | BPF_DW)) {
			i++;
			if (!ctx->target)
				ctx->offsets[i] = ctx->idx;
		}
	}

	if (!ctx->target)
		ctx->offsets[prog->len] = ctx->idx;

	return 0;
}

bool bpf_jit_needs_zext(void)
{
	return true;
}

static void jit_fill_hole(void *area, unsigned int size)
{
	u16 *ptr;

	for (ptr = area; size >= 2; size -= 2)
		*ptr++ = 0x4afc;
}

struct bpf_prog *bpf_int_jit_compile(struct bpf_verifier_env *env, struct bpf_prog *prog)
{
	struct bpf_binary_header *header;
	struct jit_ctx ctx;
	unsigned int image_size;
	u8 *image_ptr;

	if (!prog->jit_requested)
		return prog;

	memset(&ctx, 0, sizeof(ctx));
	ctx.prog = prog;

	ctx.offsets = kcalloc(prog->len + 1, sizeof(int), GFP_KERNEL);
	if (!ctx.offsets)
		return prog;

	build_prologue(&ctx);
	if (build_body(&ctx) < 0)
		goto out_off;
	build_epilogue(&ctx);

	image_size = ctx.idx * 2;
	header = bpf_jit_binary_alloc(image_size, &image_ptr, 2, jit_fill_hole);
	if (!header)
		goto out_off;

	ctx.target = (u16 *)image_ptr;
	ctx.idx = 0;

	build_prologue(&ctx);
	if (build_body(&ctx) < 0) {
		bpf_jit_binary_free(header);
		goto out_off;
	}
	build_epilogue(&ctx);

	flush_icache_range((u32)header, (u32)(ctx.target + ctx.idx));

	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, image_size, 2, ctx.target);

	if (bpf_jit_binary_lock_ro(header)) {
		bpf_jit_binary_free(header);
		goto out_off;
	}

	prog->bpf_func = (void *)ctx.target;
	prog->jited = 1;
	prog->jited_len = image_size;

out_off:
	kfree(ctx.offsets);
	return prog;
}
