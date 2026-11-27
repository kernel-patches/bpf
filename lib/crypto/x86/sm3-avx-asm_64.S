/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * SM3 AVX accelerated transform.
 * specified in: https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02
 *
 * Copyright (C) 2021 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 * Copyright (C) 2021 Tianjia Zhang <tianjia.zhang@linux.alibaba.com>
 */

/* Based on SM3 AES/BMI2 accelerated work by libgcrypt at:
 *  https://gnupg.org/software/libgcrypt/index.html
 */

#include <linux/linkage.h>
#include <asm/frame.h>

/* State structure */

#define state_h0 0
#define state_h1 4
#define state_h2 8
#define state_h3 12
#define state_h4 16
#define state_h5 20
#define state_h6 24
#define state_h7 28

/* Register macros */

#define RSTATE %rdi
#define RDATA  %rsi
#define KREG   %edx

#define t0 %eax
#define t1 %ebx
#define t2 %ecx

#define a %r8d
#define b %r9d
#define c %r10d
#define d %r11d
#define e %r12d
#define f %r13d
#define g %r14d
#define h %r15d

#define W0 %xmm0
#define W1 %xmm1
#define W2 %xmm2
#define W3 %xmm3
#define W4 %xmm4
#define W5 %xmm5

#define XTMP0 %xmm6
#define XTMP1 %xmm7
#define XTMP2 %xmm8
#define XTMP3 %xmm9
#define XTMP4 %xmm10
#define XTMP5 %xmm11
#define XTMP6 %xmm12

#define BSWAP_REG %xmm15

/* Stack structure */

#define STACK_W_SIZE        (32 * 2 * 3)
#define STACK_REG_SAVE_SIZE (64)

#define STACK_W             (0)
#define STACK_REG_SAVE      (STACK_W + STACK_W_SIZE)
#define STACK_SIZE          (STACK_REG_SAVE + STACK_REG_SAVE_SIZE)

/* Instruction helpers. */

#define roll2(v, reg)		\
	roll $(v), reg;

#define roll3mov(v, src, dst)	\
	movl src, dst;		\
	roll $(v), dst;

#define roll3(v, src, dst)	\
	rorxl $(32-(v)), src, dst;

#define addl2(a, out)		\
	leal (a, out), out;

/* Round function macros. */

#define GG1(x, y, z, o, t)	\
	movl x, o;		\
	xorl y, o;		\
	xorl z, o;

#define FF1(x, y, z, o, t) GG1(x, y, z, o, t)

#define GG2(x, y, z, o, t)	\
	andnl z, x, o;		\
	movl y, t;		\
	andl x, t;		\
	addl2(t, o);

#define FF2(x, y, z, o, t)	\
	movl y, o;		\
	xorl x, o;		\
	movl y, t;		\
	andl x, t;		\
	andl z, o;		\
	xorl t, o;

#define R(i, a, b, c, d, e, f, g, h, woff, widx)			\
	/* rol(a, 12) => t0 */						\
	roll3mov(12, a, t0); /* rorxl here would reduce perf by 6% on zen3 */ \
	/* rol(t0 + e + K[round], 7) => t1 */				\
	leal (t0, KREG), t1;						\
	roll2(1, KREG);							\
	addl e, t1;							\
	roll2(7, t1);							\
	/* h + w1 => h */						\
	addl ((woff) + (widx) * 4)(%rsp), h;				\
	/* h + t1 => h */						\
	addl2(t1, h);							\
	/* t1 ^ t0 => t0 */						\
	xorl t1, t0;							\
	/* w1w2 + d => d */						\
	addl ((woff) + 32 + (widx) * 4)(%rsp), d;			\
	/* FF##i(a,b,c) => t1 */					\
	FF##i(a, b, c, t1, t2);						\
	/* d + t1 => d */						\
	addl2(t1, d);							\
	/* GG#i(e,f,g) => t2 */						\
	GG##i(e, f, g, t2, t1);						\
	/* h + t2 => h */						\
	addl2(t2, h);							\
	/* rol (f, 19) => f */						\
	roll2(19, f);							\
	/* d + t0 => d */						\
	addl2(t0, d);							\
	/* rol (b, 9) => b */						\
	roll2(9, b);							\
	/* P0(h) => h */						\
	roll3(9, h, t2);						\
	roll3(17, h, t1);						\
	xorl t2, h;							\
	xorl t1, h;

#define R1(a, b, c, d, e, f, g, h, round, widx, wtype) \
	R(1, a, b, c, d, e, f, g, h, wtype##_W1_OFF(round), widx)

#define R2(a, b, c, d, e, f, g, h, wslot, widx) \
	R(2, a, b, c, d, e, f, g, h, STACK_W + (wslot) * 64, widx)

/* Input expansion macros. */

/* Byte-swapped input offset and address. */
#define IW_W1_OFF(round) \
	(STACK_W + ((round) / 4) * 64)
#define IW_W_ADDR(round, widx, offs) \
	(IW_W1_OFF(round) + (offs) + ((widx) * 4))(%rsp)

/* Expanded input offset and address. */
#define XW_W1_OFF(round) \
	(STACK_W + ((((round) / 3) - 4) % 2) * 64)
#define XW_W_ADDR(round, widx, offs) \
	(XW_W1_OFF(round) + (offs) + ((widx) * 4))(%rsp)

/* Rounds 1-12, byte-swapped input block addresses. */
#define IW_W1_ADDR(round, widx)   IW_W_ADDR(round, widx, 0)
#define IW_W1W2_ADDR(round, widx) IW_W_ADDR(round, widx, 32)

/* Rounds 1-12, expanded input block addresses. */
#define XW_W1_ADDR(round, widx)   XW_W_ADDR(round, widx, 0)
#define XW_W1W2_ADDR(round, widx) XW_W_ADDR(round, widx, 32)

/* Input block loading. */
#define LOAD_W_XMM_1()							\
	vmovdqu 0*16(RDATA), XTMP0; /* XTMP0: w3, w2, w1, w0 */		\
	vmovdqu 1*16(RDATA), XTMP1; /* XTMP1: w7, w6, w5, w4 */		\
	vmovdqu 2*16(RDATA), XTMP2; /* XTMP2: w11, w10, w9, w8 */	\
	vmovdqu 3*16(RDATA), XTMP3; /* XTMP3: w15, w14, w13, w12 */	\
	vpshufb BSWAP_REG, XTMP0, XTMP0;				\
	vpshufb BSWAP_REG, XTMP1, XTMP1;				\
	vpshufb BSWAP_REG, XTMP2, XTMP2;				\
	vpshufb BSWAP_REG, XTMP3, XTMP3;				\
	vpxor XTMP0, XTMP1, XTMP4;					\
	vpxor XTMP1, XTMP2, XTMP5;					\
	vpxor XTMP2, XTMP3, XTMP6;					\
	leaq 64(RDATA), RDATA;						\
	vmovdqa XTMP0, IW_W1_ADDR(0, 0);				\
	vmovdqa XTMP4, IW_W1W2_ADDR(0, 0);				\
	vmovdqa XTMP1, IW_W1_ADDR(4, 0);				\
	vmovdqa XTMP5, IW_W1W2_ADDR(4, 0);

#define LOAD_W_XMM_2()				\
	vmovdqa XTMP2, IW_W1_ADDR(8, 0);	\
	vmovdqa XTMP6, IW_W1W2_ADDR(8, 0);

#define LOAD_W_XMM_3()							\
	vpshufd $0b00000000, XTMP0, W0; /* W0: xx, w0, xx, xx */	\
	vpshufd $0b11111001, XTMP0, W1; /* W1: xx, w3, w2, w1 */	\
	vmovdqa XTMP1, W2;              /* W2: xx, w6, w5, w4 */	\
	vpalignr $12, XTMP1, XTMP2, W3; /* W3: xx, w9, w8, w7 */	\
	vpalignr $8, XTMP2, XTMP3, W4;  /* W4: xx, w12, w11, w10 */	\
	vpshufd $0b11111001, XTMP3, W5; /* W5: xx, w15, w14, w13 */

/* Message scheduling. Note: 3 words per XMM register. */
#define SCHED_W_0(round, w0, w1, w2, w3, w4, w5)			\
	/* Load (w[i - 16]) => XTMP0 */					\
	vpshufd $0b10111111, w0, XTMP0;					\
	vpalignr $12, XTMP0, w1, XTMP0; /* XTMP0: xx, w2, w1, w0 */	\
	/* Load (w[i - 13]) => XTMP1 */					\
	vpshufd $0b10111111, w1, XTMP1;					\
	vpalignr $12, XTMP1, w2, XTMP1;					\
	/* w[i - 9] == w3 */						\
	/* XMM3 ^ XTMP0 => XTMP0 */					\
	vpxor w3, XTMP0, XTMP0;

#define SCHED_W_1(round, w0, w1, w2, w3, w4, w5)	\
	/* w[i - 3] == w5 */				\
	/* rol(XMM5, 15) ^ XTMP0 => XTMP0 */		\
	vpslld $15, w5, XTMP2;				\
	vpsrld $(32-15), w5, XTMP3;			\
	vpxor XTMP2, XTMP3, XTMP3;			\
	vpxor XTMP3, XTMP0, XTMP0;			\
	/* rol(XTMP1, 7) => XTMP1 */			\
	vpslld $7, XTMP1, XTMP5;			\
	vpsrld $(32-7), XTMP1, XTMP1;			\
	vpxor XTMP5, XTMP1, XTMP1;			\
	/* XMM4 ^ XTMP1 => XTMP1 */			\
	vpxor w4, XTMP1, XTMP1;				\
	/* w[i - 6] == XMM4 */				\
	/* P1(XTMP0) ^ XTMP1 => XMM0 */			\
	vpslld $15, XTMP0, XTMP5;			\
	vpsrld $(32-15), XTMP0, XTMP6;			\
	vpslld $23, XTMP0, XTMP2;			\
	vpsrld $(32-23), XTMP0, XTMP3;			\
	vpxor XTMP0, XTMP1, XTMP1;			\
	vpxor XTMP6, XTMP5, XTMP5;			\
	vpxor XTMP3, XTMP2, XTMP2;			\
	vpxor XTMP2, XTMP5, XTMP5;			\
	vpxor XTMP5, XTMP1, w0;

#define SCHED_W_2(round, w0, w1, w2, w3, w4, w5)	\
	/* W1 in XMM12 */				\
	vpshufd $0b10111111, w4, XTMP4;			\
	vpalignr $12, XTMP4, w5, XTMP4;			\
	vmovdqa XTMP4, XW_W1_ADDR((round), 0);		\
	/* W1 ^ W2 => XTMP1 */				\
	vpxor w0, XTMP4, XTMP1;				\
	vmovdqa XTMP1, XW_W1W2_ADDR((round), 0);


.section	.rodata.cst16, "aM", @progbits, 16
.align 16

.Lbe32mask:
	.long 0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f

.text

/*
 * Transform nblocks*64 bytes (nblocks*16 32-bit words) at DATA.
 *
 * void sm3_transform_avx(struct sm3_block_state *state,
 *                        const u8 *data, size_t nblocks);
 */
SYM_FUNC_START(sm3_transform_avx)
	/* input:
	 *	%rdi: state
	 *	%rsi: data
	 *	%rdx: nblocks
	 */
	vzeroupper;

	pushq %rbp;
	movq %rsp, %rbp;

	subq $STACK_SIZE, %rsp;
	andq $(~63), %rsp;

	movq %rbx, (STACK_REG_SAVE + 0 * 8)(%rsp);
	movq %r15, (STACK_REG_SAVE + 1 * 8)(%rsp);
	movq %r14, (STACK_REG_SAVE + 2 * 8)(%rsp);
	movq %r13, (STACK_REG_SAVE + 3 * 8)(%rsp);
	movq %r12, (STACK_REG_SAVE + 4 * 8)(%rsp);

	/* Store pointer to the end of the data. */
	shlq $6, %rdx;
	addq RDATA, %rdx;
	movq %rdx, (STACK_REG_SAVE + 5 * 8)(%rsp);

	vmovdqa .Lbe32mask (%rip), BSWAP_REG;

	/* Get the values of the chaining variables. */
	movl state_h0(RSTATE), a;
	movl state_h1(RSTATE), b;
	movl state_h2(RSTATE), c;
	movl state_h3(RSTATE), d;
	movl state_h4(RSTATE), e;
	movl state_h5(RSTATE), f;
	movl state_h6(RSTATE), g;
	movl state_h7(RSTATE), h;

.align 16
.Loop:
	/* Load data part1. */
	LOAD_W_XMM_1();

	movl $0x79cc4519, KREG;

	/* Transform 0-3 + Load data part2. */
	R1(a, b, c, d, e, f, g, h, 0, 0, IW); LOAD_W_XMM_2();
	R1(d, a, b, c, h, e, f, g, 1, 1, IW);
	R1(c, d, a, b, g, h, e, f, 2, 2, IW);
	R1(b, c, d, a, f, g, h, e, 3, 3, IW); LOAD_W_XMM_3();

	/* Transform 4-7 + Precalc 12-14. */
	R1(a, b, c, d, e, f, g, h, 4, 0, IW);
	R1(d, a, b, c, h, e, f, g, 5, 1, IW);
	R1(c, d, a, b, g, h, e, f, 6, 2, IW); SCHED_W_0(12, W0, W1, W2, W3, W4, W5);
	R1(b, c, d, a, f, g, h, e, 7, 3, IW); SCHED_W_1(12, W0, W1, W2, W3, W4, W5);

	/* Transform 8-11 + Precalc 12-17. */
	R1(a, b, c, d, e, f, g, h, 8, 0, IW); SCHED_W_2(12, W0, W1, W2, W3, W4, W5);
	R1(d, a, b, c, h, e, f, g, 9, 1, IW); SCHED_W_0(15, W1, W2, W3, W4, W5, W0);
	R1(c, d, a, b, g, h, e, f, 10, 2, IW); SCHED_W_1(15, W1, W2, W3, W4, W5, W0);
	R1(b, c, d, a, f, g, h, e, 11, 3, IW); SCHED_W_2(15, W1, W2, W3, W4, W5, W0);

	/* Transform 12-14 + Precalc 18-20 */
	R1(a, b, c, d, e, f, g, h, 12, 0, XW); SCHED_W_0(18, W2, W3, W4, W5, W0, W1);
	R1(d, a, b, c, h, e, f, g, 13, 1, XW); SCHED_W_1(18, W2, W3, W4, W5, W0, W1);
	R1(c, d, a, b, g, h, e, f, 14, 2, XW); SCHED_W_2(18, W2, W3, W4, W5, W0, W1);

	/* Transform 15 */
	R1(b, c, d, a, f, g, h, e, 15, 0, XW);

	/* Rounds 16-63: 4 iterations of 12 rounds. */
	movl $0x9d8a7a87, KREG;

.align 16
.Lloop_r2:
	/*
	 * SCHED_W_* use iteration-0 round numbers (21..30); XW_W1_OFF(round)
	 * alternates every 3 rounds and repeats every 6, which divides 12.
	 */
	R2(a, b, c, d, e, f, g, h, 1, 1); SCHED_W_0(21, W3, W4, W5, W0, W1, W2);
	R2(d, a, b, c, h, e, f, g, 1, 2); SCHED_W_1(21, W3, W4, W5, W0, W1, W2);
	R2(c, d, a, b, g, h, e, f, 0, 0); SCHED_W_2(21, W3, W4, W5, W0, W1, W2);

	R2(b, c, d, a, f, g, h, e, 0, 1); SCHED_W_0(24, W4, W5, W0, W1, W2, W3);
	R2(a, b, c, d, e, f, g, h, 0, 2); SCHED_W_1(24, W4, W5, W0, W1, W2, W3);
	R2(d, a, b, c, h, e, f, g, 1, 0); SCHED_W_2(24, W4, W5, W0, W1, W2, W3);

	R2(c, d, a, b, g, h, e, f, 1, 1); SCHED_W_0(27, W5, W0, W1, W2, W3, W4);
	R2(b, c, d, a, f, g, h, e, 1, 2); SCHED_W_1(27, W5, W0, W1, W2, W3, W4);
	R2(a, b, c, d, e, f, g, h, 0, 0); SCHED_W_2(27, W5, W0, W1, W2, W3, W4);

	R2(d, a, b, c, h, e, f, g, 0, 1); SCHED_W_0(30, W0, W1, W2, W3, W4, W5);
	R2(c, d, a, b, g, h, e, f, 0, 2); SCHED_W_1(30, W0, W1, W2, W3, W4, W5);
	R2(b, c, d, a, f, g, h, e, 1, 0); SCHED_W_2(30, W0, W1, W2, W3, W4, W5);

	/* Rotate W0..W5 by 4 positions: (W0..W5) <- (W4, W5, W0, W1, W2, W3). */
	vmovdqa W0, XTMP0;
	vmovdqa W1, XTMP1;
	vmovdqa W4, W0;
	vmovdqa W5, W1;
	vmovdqa W2, W4;
	vmovdqa W3, W5;
	vmovdqa XTMP0, W2;
	vmovdqa XTMP1, W3;

	/* Stop when KREG reaches the "round 64" value. */
	cmpl $0x7a879d8a, KREG;
	jne .Lloop_r2;

	/* Update the chaining variables. */
	xorl state_h0(RSTATE), a;
	xorl state_h1(RSTATE), b;
	xorl state_h2(RSTATE), c;
	xorl state_h3(RSTATE), d;
	movl a, state_h0(RSTATE);
	movl b, state_h1(RSTATE);
	movl c, state_h2(RSTATE);
	movl d, state_h3(RSTATE);
	xorl state_h4(RSTATE), e;
	xorl state_h5(RSTATE), f;
	xorl state_h6(RSTATE), g;
	xorl state_h7(RSTATE), h;
	movl e, state_h4(RSTATE);
	movl f, state_h5(RSTATE);
	movl g, state_h6(RSTATE);
	movl h, state_h7(RSTATE);

	/* Continue if there are more blocks to process. */
	cmpq (STACK_REG_SAVE + 5 * 8)(%rsp), RDATA;
	jne .Loop;

	vzeroall;

	movq (STACK_REG_SAVE + 0 * 8)(%rsp), %rbx;
	movq (STACK_REG_SAVE + 1 * 8)(%rsp), %r15;
	movq (STACK_REG_SAVE + 2 * 8)(%rsp), %r14;
	movq (STACK_REG_SAVE + 3 * 8)(%rsp), %r13;
	movq (STACK_REG_SAVE + 4 * 8)(%rsp), %r12;

	vmovdqa %xmm0, IW_W1_ADDR(0, 0);
	vmovdqa %xmm0, IW_W1W2_ADDR(0, 0);
	vmovdqa %xmm0, IW_W1_ADDR(4, 0);
	vmovdqa %xmm0, IW_W1W2_ADDR(4, 0);
	vmovdqa %xmm0, IW_W1_ADDR(8, 0);
	vmovdqa %xmm0, IW_W1W2_ADDR(8, 0);

	movq %rbp, %rsp;
	popq %rbp;
	RET;
SYM_FUNC_END(sm3_transform_avx)
