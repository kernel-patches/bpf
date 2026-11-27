/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SM3 secure hash, as specified by OSCCA GM/T 0004-2012 SM3 and described
 * at https://datatracker.ietf.org/doc/html/draft-sca-cfrg-sm3-02
 *
 * Copyright (C) 2017 ARM Limited or its affiliates.
 * Copyright (C) 2017 Gilad Ben-Yossef <gilad@benyossef.com>
 * Copyright (C) 2021 Tianjia Zhang <tianjia.zhang@linux.alibaba.com>
 */

#include <crypto/sm3.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/unaligned.h>

static const struct sm3_block_state sm3_iv = {
	.h = {
		SM3_IVA, SM3_IVB, SM3_IVC, SM3_IVD,
		SM3_IVE, SM3_IVF, SM3_IVG, SM3_IVH,
	},
};

/*
 * Transform the message X which consists of 16 32-bit-words. See
 * GM/T 004-2012 for details.
 */
#define R(i, a, b, c, d, e, f, g, h, t, w1, w2)			\
	do {							\
		ss1 = rol32((rol32((a), 12) + (e) + (t)), 7);	\
		(t) = rol32((t), 1);				\
		ss2 = ss1 ^ rol32((a), 12);			\
		d += FF ## i(a, b, c) + ss2 + ((w1) ^ (w2));	\
		h += GG ## i(e, f, g) + ss1 + (w1);		\
		b = rol32((b), 9);				\
		f = rol32((f), 19);				\
		h = P0((h));					\
	} while (0)

#define R1(a, b, c, d, e, f, g, h, t, w1, w2) \
	R(1, a, b, c, d, e, f, g, h, t, w1, w2)
#define R2(a, b, c, d, e, f, g, h, t, w1, w2) \
	R(2, a, b, c, d, e, f, g, h, t, w1, w2)

#define FF1(x, y, z)  (x ^ y ^ z)
#define FF2(x, y, z)  ((x & y) | (x & z) | (y & z))

#define GG1(x, y, z)  FF1(x, y, z)
#define GG2(x, y, z)  ((x & y) | (~x & z))

/* Message expansion */
#define P0(x) ((x) ^ rol32((x), 9) ^ rol32((x), 17))
#define P1(x) ((x) ^ rol32((x), 15) ^ rol32((x), 23))
#define I(i)  (W[i] = get_unaligned_be32(data + (i) * 4))
#define W1(i) (W[(i) & 0x0f])
#define W2(i) (W[(i) & 0x0f] =					\
		P1(W[(i) & 0x0f]				\
			^ W[((i) - 9) & 0x0f]			\
			^ rol32(W[((i) - 3) & 0x0f], 15))	\
		^ rol32(W[((i) - 13) & 0x0f], 7)		\
		^ W[((i) - 6) & 0x0f])

static void sm3_block_generic(struct sm3_block_state *state,
			      const u8 data[SM3_BLOCK_SIZE], u32 W[16])
{
	u32 a, b, c, d, e, f, g, h, ss1, ss2, t;
	int i;

	a = state->h[0];
	b = state->h[1];
	c = state->h[2];
	d = state->h[3];
	e = state->h[4];
	f = state->h[5];
	g = state->h[6];
	h = state->h[7];

	t = 0x79cc4519;
	R1(a, b, c, d, e, f, g, h, t, I(0), I(4));
	R1(d, a, b, c, h, e, f, g, t, I(1), I(5));
	R1(c, d, a, b, g, h, e, f, t, I(2), I(6));
	R1(b, c, d, a, f, g, h, e, t, I(3), I(7));
	R1(a, b, c, d, e, f, g, h, t, W1(4), I(8));
	R1(d, a, b, c, h, e, f, g, t, W1(5), I(9));
	R1(c, d, a, b, g, h, e, f, t, W1(6), I(10));
	R1(b, c, d, a, f, g, h, e, t, W1(7), I(11));
	R1(a, b, c, d, e, f, g, h, t, W1(8), I(12));
	R1(d, a, b, c, h, e, f, g, t, W1(9), I(13));
	R1(c, d, a, b, g, h, e, f, t, W1(10), I(14));
	R1(b, c, d, a, f, g, h, e, t, W1(11), I(15));
	R1(a, b, c, d, e, f, g, h, t, W1(12), W2(16));
	R1(d, a, b, c, h, e, f, g, t, W1(13), W2(17));
	R1(c, d, a, b, g, h, e, f, t, W1(14), W2(18));
	R1(b, c, d, a, f, g, h, e, t, W1(15), W2(19));

	t = 0x9d8a7a87;
	for (i = 0; i < 3; i++) {
		R2(a, b, c, d, e, f, g, h, t, W1(0), W2(4));
		R2(d, a, b, c, h, e, f, g, t, W1(1), W2(5));
		R2(c, d, a, b, g, h, e, f, t, W1(2), W2(6));
		R2(b, c, d, a, f, g, h, e, t, W1(3), W2(7));
		R2(a, b, c, d, e, f, g, h, t, W1(4), W2(8));
		R2(d, a, b, c, h, e, f, g, t, W1(5), W2(9));
		R2(c, d, a, b, g, h, e, f, t, W1(6), W2(10));
		R2(b, c, d, a, f, g, h, e, t, W1(7), W2(11));
		R2(a, b, c, d, e, f, g, h, t, W1(8), W2(12));
		R2(d, a, b, c, h, e, f, g, t, W1(9), W2(13));
		R2(c, d, a, b, g, h, e, f, t, W1(10), W2(14));
		R2(b, c, d, a, f, g, h, e, t, W1(11), W2(15));
		R2(a, b, c, d, e, f, g, h, t, W1(12), W2(16));
		R2(d, a, b, c, h, e, f, g, t, W1(13), W2(17));
		R2(c, d, a, b, g, h, e, f, t, W1(14), W2(18));
		R2(b, c, d, a, f, g, h, e, t, W1(15), W2(19));
	}

	state->h[0] ^= a;
	state->h[1] ^= b;
	state->h[2] ^= c;
	state->h[3] ^= d;
	state->h[4] ^= e;
	state->h[5] ^= f;
	state->h[6] ^= g;
	state->h[7] ^= h;
}
#undef R
#undef R1
#undef R2
#undef I
#undef W1
#undef W2

static void __maybe_unused sm3_blocks_generic(struct sm3_block_state *state,
					      const u8 *data, size_t nblocks)
{
	u32 W[16];

	do {
		sm3_block_generic(state, data, W);
		data += SM3_BLOCK_SIZE;
	} while (--nblocks);

	memzero_explicit(W, sizeof(W));
}

#ifdef CONFIG_CRYPTO_LIB_SM3_ARCH
#include "sm3.h" /* $(SRCARCH)/sm3.h */
#else
#define sm3_blocks sm3_blocks_generic
#endif

void sm3_init(struct sm3_ctx *ctx)
{
	ctx->state = sm3_iv;
	ctx->bytecount = 0;
}
EXPORT_SYMBOL_GPL(sm3_init);

void sm3_update(struct sm3_ctx *ctx, const u8 *data, size_t len)
{
	size_t partial = ctx->bytecount % SM3_BLOCK_SIZE;

	ctx->bytecount += len;

	if (partial + len >= SM3_BLOCK_SIZE) {
		size_t nblocks;

		if (partial) {
			size_t l = SM3_BLOCK_SIZE - partial;

			memcpy(&ctx->buf[partial], data, l);
			data += l;
			len -= l;

			sm3_blocks(&ctx->state, ctx->buf, 1);
		}

		nblocks = len / SM3_BLOCK_SIZE;
		len %= SM3_BLOCK_SIZE;

		if (nblocks) {
			sm3_blocks(&ctx->state, data, nblocks);
			data += nblocks * SM3_BLOCK_SIZE;
		}
		partial = 0;
	}
	if (len)
		memcpy(&ctx->buf[partial], data, len);
}
EXPORT_SYMBOL_GPL(sm3_update);

static void __sm3_final(struct sm3_ctx *ctx, u8 out[SM3_DIGEST_SIZE])
{
	u64 bitcount = ctx->bytecount << 3;
	size_t partial = ctx->bytecount % SM3_BLOCK_SIZE;

	ctx->buf[partial++] = 0x80;
	if (partial > SM3_BLOCK_SIZE - 8) {
		memset(&ctx->buf[partial], 0, SM3_BLOCK_SIZE - partial);
		sm3_blocks(&ctx->state, ctx->buf, 1);
		partial = 0;
	}
	memset(&ctx->buf[partial], 0, SM3_BLOCK_SIZE - 8 - partial);
	*(__be64 *)&ctx->buf[SM3_BLOCK_SIZE - 8] = cpu_to_be64(bitcount);
	sm3_blocks(&ctx->state, ctx->buf, 1);

	for (size_t i = 0; i < SM3_DIGEST_SIZE; i += 4)
		put_unaligned_be32(ctx->state.h[i / 4], out + i);
}

void sm3_final(struct sm3_ctx *ctx, u8 out[SM3_DIGEST_SIZE])
{
	__sm3_final(ctx, out);
	sm3_zeroize_ctx(ctx);
}
EXPORT_SYMBOL_GPL(sm3_final);

void sm3(const u8 *data, size_t len, u8 out[SM3_DIGEST_SIZE])
{
	struct sm3_ctx ctx;

	sm3_init(&ctx);
	sm3_update(&ctx, data, len);
	sm3_final(&ctx, out);
}
EXPORT_SYMBOL_GPL(sm3);

#ifdef sm3_mod_init_arch
static int __init sm3_mod_init(void)
{
	sm3_mod_init_arch();
	return 0;
}
subsys_initcall(sm3_mod_init);

static void __exit sm3_mod_exit(void)
{
}
module_exit(sm3_mod_exit);
#endif

MODULE_DESCRIPTION("SM3 library functions");
MODULE_LICENSE("GPL v2");
