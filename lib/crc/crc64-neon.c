// SPDX-License-Identifier: GPL-2.0-only
/*
 * Accelerated CRC64 (NVMe) using ARM NEON C intrinsics
 */

#include <linux/types.h>
#include <asm/neon-intrinsics.h>

#include "crc64-neon.h"

u64 crc64_nvme_neon(u64 crc, const u8 *p, size_t len);

/* x^575 mod G, x^511 mod G */
static const uint64_t fold_consts_4x_val[2] = { 0x0c32cdb31e18a84aULL,
						0x62242240ace5045aULL };
/* x^319 mod G, x^255 mod G */
static const uint64_t fold_consts_2x_val[2] = { 0xb0bc2e589204f500ULL,
						0xe1e0bb9d45d7a44cULL };
/* x^191 mod G, x^127 mod G */
static const u64 fold_consts_val[2] = { 0xeadc41fd2ba3d420ULL,
					0x21e9761e252621acULL };
/* floor(x^127 / G), (G - x^64) / x */
static const u64 bconsts_val[2] = { 0x27ecfa329aef9f77ULL,
				    0x34d926535897936aULL };

static __always_inline uint64x2_t fold_single_round(uint64x2_t fold,
						    uint64x2_t temp,
						    uint64x2_t consts)
{
	uint64x2_t temp1 = pmull64(consts, fold);
	uint64x2_t temp2 = pmull64_high(consts, fold);

	return temp ^ temp1 ^ temp2;
}

/*
 * Fold in the final 1 <= len <= 15 bytes. With A = fold, the remaining
 * polynomial is A*x^(8*len) + B. Rewrite it as C1*x^128 + C2, where
 * C1 = floor(A / x^(128 - 8*len)) and C2 = (A*x^(8*len) mod x^128) + B,
 * then fold C1 into C2. t1 selects the len highest-degree bytes of A to
 * form C1; ~t1 selects the remaining bytes to form A*x^(8*len) mod x^128,
 * since tbl returns 0 for any index >= 16. The sign of t1 then selects
 * which bytes of C2 come from B.
 */
static __always_inline uint64x2_t fold_partial_block(uint64x2_t fold,
						     uint64x2_t consts,
						     const u8 *p,
						     size_t len)
{
	static const u8 crc_neon_shift_tab[32] = {
		0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
		0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};

	uint8x16_t last16, f, t1, t2, a, b;
	int8x16_t  mask;

	last16 = vld1q_u8(p + len - 16);
	f      = vreinterpretq_u8_u64(fold);
	t1     = vld1q_u8(crc_neon_shift_tab + len);
	a      = vqtbl1q_u8(f,  t1);
	t2     = vqtbl1q_u8(f, ~t1);
	mask   = vreinterpretq_s8_u8(t1) >> 7;
	t1     = vreinterpretq_u8_s8(mask);
	b      = vbslq_u8(t1, t2, last16);

	return fold_single_round(vreinterpretq_u64_u8(a),
				 vreinterpretq_u64_u8(b),
				 consts);
}

u64 crc64_nvme_neon(u64 crc, const u8 *p, size_t len)
{
	/* Assumes len >= 128. */
	uint64x2_t fold_consts = vld1q_u64(fold_consts_val);
	uint64x2_t fold_consts_4x = vld1q_u64(fold_consts_4x_val);
	uint64x2_t fold_consts_2x = vld1q_u64(fold_consts_2x_val);
	uint64x2_t v0 = { crc, 0 };
	uint64x2_t zero = { };
	uint64x2_t v1, v2, v3;

	v0 ^= vreinterpretq_u64_u8(vld1q_u8(p));
	v1  = vreinterpretq_u64_u8(vld1q_u8(p + 16));
	v2  = vreinterpretq_u64_u8(vld1q_u8(p + 32));
	v3  = vreinterpretq_u64_u8(vld1q_u8(p + 48));

	p += 64;
	len -= 64;
	do {
		uint64x2_t t0 = vreinterpretq_u64_u8(vld1q_u8(p +  0));
		uint64x2_t t1 = vreinterpretq_u64_u8(vld1q_u8(p + 16));
		uint64x2_t t2 = vreinterpretq_u64_u8(vld1q_u8(p + 32));
		uint64x2_t t3 = vreinterpretq_u64_u8(vld1q_u8(p + 48));

		v0 = fold_single_round(v0, t0, fold_consts_4x);
		v1 = fold_single_round(v1, t1, fold_consts_4x);
		v2 = fold_single_round(v2, t2, fold_consts_4x);
		v3 = fold_single_round(v3, t3, fold_consts_4x);
		p += 64;
		len -= 64;
	} while (len >= 64);

	v0 = fold_single_round(v0, v2, fold_consts_2x);
	v1 = fold_single_round(v1, v3, fold_consts_2x);

	if (len >= 32) {
		uint64x2_t t0 = vreinterpretq_u64_u8(vld1q_u8(p +  0));
		uint64x2_t t1 = vreinterpretq_u64_u8(vld1q_u8(p + 16));

		v0 = fold_single_round(v0, t0, fold_consts_2x);
		v1 = fold_single_round(v1, t1, fold_consts_2x);
		p += 32;
		len -= 32;
	}

	v0 = fold_single_round(v0, v1, fold_consts);

	if (len >= 16) {
		uint64x2_t t0 = vreinterpretq_u64_u8(vld1q_u8(p));

		v0 = fold_single_round(v0, t0, fold_consts);
		p += 16;
		len -= 16;
	}

	if (len)
		v0 = fold_partial_block(v0, fold_consts, p, len);

	/* Multiply the 128-bit value by x^64 and reduce it back to 128 bits. */
	v0 = vextq_u64(v0, zero, 1) ^ pmull64_hi_lo(fold_consts, v0);

	/* Final Barrett reduction */
	uint64x2_t bconsts = vld1q_u64(bconsts_val);
	uint64x2_t final = pmull64(bconsts, v0);

	v0 ^= vextq_u64(zero, final, 1) ^ pmull64_hi_lo(bconsts, final);

	return vgetq_lane_u64(v0, 1);
}
