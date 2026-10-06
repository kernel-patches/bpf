/* SPDX-License-Identifier: GPL-2.0 */
/* x86-64 code for the kfuncs in bpf_insn_kfuncs.c, see struct bpf_kfunc_body */
#include <linux/cpufeature.h>
#include <linux/log2.h>
#include <linux/unaligned.h>

static u8 *x86_rex(u8 *p, bool w, u8 reg, u8 rm)
{
	u8 b = 0x40 | (w ? 8 : 0) | (reg & 8 ? 4 : 0) | (rm & 8 ? 1 : 0);

	if (b != 0x40)
		*p++ = b;
	return p;
}

/* 64-bit op %reg, %rm */
static u8 *x86_op_rr(u8 *p, u8 op, u8 reg, u8 rm)
{
	p = x86_rex(p, true, reg, rm);
	*p++ = op;
	*p++ = 0xc0 | (reg & 7) << 3 | (rm & 7);
	return p;
}

/*
 * ModRM, SIB and displacement of disp(%base, %index, 1 << scale), with @reg in
 * the reg field. An @index of 4 (%rsp) is none.
 */
static u8 *x86_mem(u8 *p, u8 reg, u8 base, u8 index, u8 scale, s32 disp)
{
	u8 mod = !disp && (base & 7) != 5 ? 0 : disp == (s8)disp ? 1 : 2;
	bool sib = index != 4 || (base & 7) == 4;

	*p++ = mod << 6 | (reg & 7) << 3 | (sib ? 4 : base & 7);
	if (sib)
		*p++ = scale << 6 | (index & 7) << 3 | (base & 7);
	if (mod == 1)
		*p++ = disp;
	if (mod == 2) {
		put_unaligned_le32(disp, p);
		p += 4;
	}
	return p;
}

static int rol64_emit(const u8 *reg, const s32 *imm, u8 *buf)
{
	u8 dst = reg[0], src = reg[1], n = imm[BPF_REG_2] & 63, *p = buf;

	if (n && dst != src && cpu_feature_enabled(X86_FEATURE_BMI2)) {
		/* rorx $(64 - n), %src, %dst */
		*p++ = 0xc4;
		*p++ = (dst & 8 ? 0 : 0x80) | 0x40 | (src & 8 ? 0 : 0x20) | 0x03;
		*p++ = 0xfb;
		*p++ = 0xf0;
		*p++ = 0xc0 | (dst & 7) << 3 | (src & 7);
		*p++ = 64 - n;
		return p - buf;
	}
	if (dst != src || !n)
		p = x86_op_rr(p, 0x89, src, dst);	/* mov %src, %dst */
	if (n) {
		/* rol $n, %dst */
		p = x86_rex(p, true, 0, dst);
		*p++ = 0xc1;
		*p++ = 0xc0 | (dst & 7);
		*p++ = n;
	}
	return p - buf;
}

/* cmovcc %src, %dst */
static u8 *x86_cmov(u8 *p, u8 cc, u8 dst, u8 src)
{
	p = x86_rex(p, true, dst, src);
	*p++ = 0x0f;
	*p++ = 0x40 | cc;
	*p++ = 0xc0 | (dst & 7) << 3 | (src & 7);
	return p;
}

/*
 * dst = cc ? a : b, after the test or compare at @p. The flags come first, so
 * the result may take the register of an operand they read. A result in the
 * register of a takes b with the inverse condition, which a copy of the
 * compiled kfunc cannot do.
 */
static int x86_select(u8 *buf, u8 *p, u8 cc, u8 dst, u8 a, u8 b)
{
	if (dst == a)
		return x86_cmov(p, cc ^ 1, dst, b) - buf;
	if (dst != b)
		p = x86_op_rr(p, 0x89, b, dst);	/* mov %b, %dst */
	return x86_cmov(p, cc, dst, a) - buf;
}

static int select64_emit(const u8 *reg, const s32 *imm, u8 *buf)
{
	u8 cond = reg[1];

	/* test %cond, %cond; cmovne */
	return x86_select(buf, x86_op_rr(buf, 0x85, cond, cond), 0x5, reg[0],
			   reg[2], reg[3]);
}

/* R4 is free for the control word, as there are three arguments */
static int extract64_emit(const u8 *reg, const s32 *imm, u8 *buf)
{
	u8 dst = reg[0], src = reg[1], ctl = dst != src ? dst : reg[4];
	u32 start = imm[BPF_REG_2], len = imm[BPF_REG_3];
	u8 *p = buf;

	if (!cpu_feature_enabled(X86_FEATURE_BMI1) || start > 63 || !len || len > 64 - start)
		return -EOPNOTSUPP;
	/* mov $(start | len << 8), %ctl */
	p = x86_rex(p, false, 0, ctl);
	*p++ = 0xb8 | (ctl & 7);
	put_unaligned_le32(start | len << 8, p);
	p += 4;
	/* bextr %ctl, %src, %dst */
	*p++ = 0xc4;
	*p++ = (dst & 8 ? 0 : 0x80) | 0x40 | (src & 8 ? 0 : 0x20) | 0x02;
	*p++ = 0x80 | (~ctl & 0xf) << 3;
	*p++ = 0xf7;
	*p++ = 0xc0 | (dst & 7) << 3 | (src & 7);
	return p - buf;
}

static int load_be64_emit(const u8 *reg, const s32 *imm, u8 *buf)
{
	u8 dst = reg[0], base = reg[1], *p = buf;

	if (!cpu_feature_enabled(X86_FEATURE_MOVBE))
		return -EOPNOTSUPP;
	/* movbe off(%base), %dst */
	p = x86_rex(p, true, dst, base);
	*p++ = 0x0f;
	*p++ = 0x38;
	*p++ = 0xf0;
	return x86_mem(p, dst, base, 4, 0, imm[BPF_REG_2]) - buf;
}

static int lea64_emit(const u8 *reg, const s32 *imm, u8 *buf)
{
	u8 dst = reg[0], base = reg[1], index = reg[2], *p = buf;
	u32 scale = imm[BPF_REG_3];

	/* %rsp cannot be an index, and the scale is 1, 2, 4 or 8 */
	if (index == 4 || !is_power_of_2(scale) || scale > 8)
		return -EOPNOTSUPP;
	/* lea disp(%base, %index, scale), %dst */
	*p++ = 0x48 | (dst & 8 ? 4 : 0) | (index & 8 ? 2 : 0) | (base & 8 ? 1 : 0);
	*p++ = 0x8d;
	return x86_mem(p, dst, base, index, ilog2(scale), imm[BPF_REG_4]) - buf;
}
