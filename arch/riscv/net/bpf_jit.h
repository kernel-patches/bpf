/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common functionality for RV32 and RV64 BPF JIT compilers
 *
 * Copyright (c) 2019 Björn Töpel <bjorn.topel@gmail.com>
 *
 */

#ifndef _BPF_JIT_H
#define _BPF_JIT_H

#include <linux/bpf.h>
#include <linux/filter.h>
#include <asm/cacheflush.h>
#include <asm/reg.h>
#include <asm/insn.h>

struct rv_jit_context {
	struct bpf_prog *prog;
	u16 *insns;		/* RV insns */
	int ninsns;
	int prologue_len;
	int epilogue_offset;
	int *offset;		/* BPF to RV */
	int nexentries;
	unsigned long flags;
	int stack_size;
};

/* Convert from ninsns to bytes. */
static inline int ninsns_rvoff(int ninsns)
{
	return ninsns << 1;
}

struct rv_jit_data {
	struct bpf_binary_header *header;
	u8 *image;
	struct rv_jit_context ctx;
};

static inline void bpf_fill_ill_insns(void *area, unsigned int size)
{
	memset(area, 0, size);
}

static inline void bpf_flush_icache(void *start, void *end)
{
	flush_icache_range((unsigned long)start, (unsigned long)end);
}

/* Emit a 4-byte riscv instruction. */
static inline void emit(const u32 insn, struct rv_jit_context *ctx)
{
	if (ctx->insns) {
		ctx->insns[ctx->ninsns] = insn;
		ctx->insns[ctx->ninsns + 1] = (insn >> 16);
	}

	ctx->ninsns += 2;
}

/* Emit a 2-byte riscv compressed instruction. */
static inline void emitc(const u16 insn, struct rv_jit_context *ctx)
{
	BUILD_BUG_ON(!rvc_enabled());

	if (ctx->insns)
		ctx->insns[ctx->ninsns] = insn;

	ctx->ninsns++;
}

static inline int epilogue_offset(struct rv_jit_context *ctx)
{
	int to = ctx->epilogue_offset, from = ctx->ninsns;

	return ninsns_rvoff(to - from);
}

/* Return -1 or inverted cond. */
static inline int invert_bpf_cond(u8 cond)
{
	switch (cond) {
	case BPF_JEQ:
		return BPF_JNE;
	case BPF_JGT:
		return BPF_JLE;
	case BPF_JLT:
		return BPF_JGE;
	case BPF_JGE:
		return BPF_JLT;
	case BPF_JLE:
		return BPF_JGT;
	case BPF_JNE:
		return BPF_JEQ;
	case BPF_JSGT:
		return BPF_JSLE;
	case BPF_JSLT:
		return BPF_JSGE;
	case BPF_JSGE:
		return BPF_JSLT;
	case BPF_JSLE:
		return BPF_JSGT;
	}
	return -1;
}

static inline bool is_6b_int(long val)
{
	return -(1L << 5) <= val && val < (1L << 5);
}

static inline bool is_7b_uint(unsigned long val)
{
	return val < (1UL << 7);
}

static inline bool is_8b_uint(unsigned long val)
{
	return val < (1UL << 8);
}

static inline bool is_9b_uint(unsigned long val)
{
	return val < (1UL << 9);
}

static inline bool is_10b_int(long val)
{
	return -(1L << 9) <= val && val < (1L << 9);
}

static inline bool is_10b_uint(unsigned long val)
{
	return val < (1UL << 10);
}

static inline bool is_12b_int(long val)
{
	return -(1L << 11) <= val && val < (1L << 11);
}

static inline int is_12b_check(int off, int insn)
{
	if (!is_12b_int(off)) {
		pr_err("bpf-jit: insn=%d 12b < offset=%d not supported yet!\n",
		       insn, (int)off);
		return -1;
	}
	return 0;
}

static inline bool is_13b_int(long val)
{
	return -(1L << 12) <= val && val < (1L << 12);
}

static inline bool is_21b_int(long val)
{
	return -(1L << 20) <= val && val < (1L << 20);
}

static inline int rv_offset(int insn, int off, struct rv_jit_context *ctx)
{
	int from, to;

	off++; /* BPF branch is from PC+1, RV is from PC */
	from = (insn > 0) ? ctx->offset[insn - 1] : ctx->prologue_len;
	to = (insn + off > 0) ? ctx->offset[insn + off - 1] : ctx->prologue_len;
	return ninsns_rvoff(to - from);
}

/* Helper functions that emit RVC instructions when possible. */

static inline void emit_jalr(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd == RV_REG_RA && rs && !imm)
		emitc(rvc_jalr(rs), ctx);
	else if (rvc_enabled() && !rd && rs && !imm)
		emitc(rvc_jr(rs), ctx);
	else
		emit(rv_jalr(rd, rs, imm), ctx);
}

static inline void emit_mv(u8 rd, u8 rs, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rs)
		emitc(rvc_mv(rd, rs), ctx);
	else
		emit(rv_addi(rd, rs, 0), ctx);
}

static inline void emit_add(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd == rs1 && rs2)
		emitc(rvc_add(rd, rs2), ctx);
	else
		emit(rv_add(rd, rs1, rs2), ctx);
}

static inline void emit_addi(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd == RV_REG_SP && rd == rs && is_10b_int(imm) && imm && !(imm & 0xf))
		emitc(rvc_addi16sp(imm), ctx);
	else if (rvc_enabled() && is_creg(rd) && rs == RV_REG_SP && is_10b_uint(imm) &&
		 !(imm & 0x3) && imm)
		emitc(rvc_addi4spn(rd, imm), ctx);
	else if (rvc_enabled() && rd && rd == rs && imm && is_6b_int(imm))
		emitc(rvc_addi(rd, imm), ctx);
	else
		emit(rv_addi(rd, rs, imm), ctx);
}

static inline void emit_li(u8 rd, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && is_6b_int(imm))
		emitc(rvc_li(rd, imm), ctx);
	else
		emit(rv_addi(rd, RV_REG_ZERO, imm), ctx);
}

static inline void emit_lui(u8 rd, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd != RV_REG_SP && is_6b_int(imm) && imm)
		emitc(rvc_lui(rd, imm), ctx);
	else
		emit(rv_lui(rd, imm), ctx);
}

static inline void emit_slli(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd == rs && imm && (u32)imm < __riscv_xlen)
		emitc(rvc_slli(rd, imm), ctx);
	else
		emit(rv_slli(rd, rs, imm), ctx);
}

static inline void emit_andi(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs && is_6b_int(imm))
		emitc(rvc_andi(rd, imm), ctx);
	else
		emit(rv_andi(rd, rs, imm), ctx);
}

static inline void emit_srli(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs && imm && (u32)imm < __riscv_xlen)
		emitc(rvc_srli(rd, imm), ctx);
	else
		emit(rv_srli(rd, rs, imm), ctx);
}

static inline void emit_srai(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs && imm && (u32)imm < __riscv_xlen)
		emitc(rvc_srai(rd, imm), ctx);
	else
		emit(rv_srai(rd, rs, imm), ctx);
}

static inline void emit_sub(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_sub(rd, rs2), ctx);
	else
		emit(rv_sub(rd, rs1, rs2), ctx);
}

static inline void emit_or(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_or(rd, rs2), ctx);
	else
		emit(rv_or(rd, rs1, rs2), ctx);
}

static inline void emit_and(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_and(rd, rs2), ctx);
	else
		emit(rv_and(rd, rs1, rs2), ctx);
}

static inline void emit_xor(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_xor(rd, rs2), ctx);
	else
		emit(rv_xor(rd, rs1, rs2), ctx);
}

static inline void emit_lw(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && rd && is_8b_uint(off) && !(off & 0x3))
		emitc(rvc_lwsp(rd, off), ctx);
	else if (rvc_enabled() && is_creg(rd) && is_creg(rs1) && is_7b_uint(off) && !(off & 0x3))
		emitc(rvc_lw(rd, off, rs1), ctx);
	else
		emit(rv_lw(rd, off, rs1), ctx);
}

static inline void emit_sw(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && is_8b_uint(off) && !(off & 0x3))
		emitc(rvc_swsp(off, rs2), ctx);
	else if (rvc_enabled() && is_creg(rs1) && is_creg(rs2) && is_7b_uint(off) && !(off & 0x3))
		emitc(rvc_sw(rs1, off, rs2), ctx);
	else
		emit(rv_sw(rs1, off, rs2), ctx);
}

/* RV64-only helper functions. */
#if __riscv_xlen == 64

static inline void emit_addiw(u8 rd, u8 rs, s32 imm, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rd && rd == rs && is_6b_int(imm))
		emitc(rvc_addiw(rd, imm), ctx);
	else
		emit(rv_addiw(rd, rs, imm), ctx);
}

static inline void emit_ld(u8 rd, s32 off, u8 rs1, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && rd && is_9b_uint(off) && !(off & 0x7))
		emitc(rvc_ldsp(rd, off), ctx);
	else if (rvc_enabled() && is_creg(rd) && is_creg(rs1) && is_8b_uint(off) && !(off & 0x7))
		emitc(rvc_ld(rd, off, rs1), ctx);
	else
		emit(rv_ld(rd, off, rs1), ctx);
}

static inline void emit_sd(u8 rs1, s32 off, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && rs1 == RV_REG_SP && is_9b_uint(off) && !(off & 0x7))
		emitc(rvc_sdsp(off, rs2), ctx);
	else if (rvc_enabled() && is_creg(rs1) && is_creg(rs2) && is_8b_uint(off) && !(off & 0x7))
		emitc(rvc_sd(rs1, off, rs2), ctx);
	else
		emit(rv_sd(rs1, off, rs2), ctx);
}

static inline void emit_subw(u8 rd, u8 rs1, u8 rs2, struct rv_jit_context *ctx)
{
	if (rvc_enabled() && is_creg(rd) && rd == rs1 && is_creg(rs2))
		emitc(rvc_subw(rd, rs2), ctx);
	else
		emit(rv_subw(rd, rs1, rs2), ctx);
}

#endif /* __riscv_xlen == 64 */

void bpf_jit_build_prologue(struct rv_jit_context *ctx);
void bpf_jit_build_epilogue(struct rv_jit_context *ctx);

int bpf_jit_emit_insn(const struct bpf_insn *insn, struct rv_jit_context *ctx,
		      bool extra_pass);

#endif /* _BPF_JIT_H */
