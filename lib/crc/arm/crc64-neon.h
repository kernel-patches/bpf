// SPDX-License-Identifier: GPL-2.0-only

static inline uint64x2_t pmull64(uint64x2_t a, uint64x2_t b)
{
	uint64_t l = vgetq_lane_u64(a, 0);
	uint64_t m = vgetq_lane_u64(b, 0);
	uint64x2_t result;

	asm("vmull.p64	%q0, %P1, %P2" : "=w"(result) : "w"(l), "w"(m));

	return result;
}

static inline uint64x2_t pmull64_high(uint64x2_t a, uint64x2_t b)
{
	uint64_t l = vgetq_lane_u64(a, 1);
	uint64_t m = vgetq_lane_u64(b, 1);
	uint64x2_t result;

	asm("vmull.p64	%q0, %P1, %P2" : "=w"(result) : "w"(l), "w"(m));

	return result;
}

static inline uint64x2_t pmull64_hi_lo(uint64x2_t a, uint64x2_t b)
{
	uint64_t l = vgetq_lane_u64(a, 1);
	uint64_t m = vgetq_lane_u64(b, 0);
	uint64x2_t result;

	asm("vmull.p64	%q0, %P1, %P2" : "=w"(result) : "w"(l), "w"(m));

	return result;
}

/*
 * AArch32 does not provide this intrinsic natively because it does not
 * implement the underlying instruction. AArch32 only provides a 64-bit
 * wide vtbl.8 instruction, so use that instead.
 */
static inline uint8x16_t vqtbl1q_u8(uint8x16_t a, uint8x16_t b)
{
	union {
		uint8x16_t	val;
		uint8x8x2_t	pair;
	} __a = { a };

	return vcombine_u8(vtbl2_u8(__a.pair, vget_low_u8(b)),
			   vtbl2_u8(__a.pair, vget_high_u8(b)));
}
