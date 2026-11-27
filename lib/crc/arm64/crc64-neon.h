// SPDX-License-Identifier: GPL-2.0-only

/*
 * The PMULL helpers below use inline asm instead of the vmull_p64() and
 * vmull_high_p64() intrinsics. vmull_p64() takes poly64_t scalars, so the low
 * lanes have to be extracted with vgetq_lane_u64(). For the fold constants,
 * compilers fold that extraction into a 64-bit immediate: recent GCC and Clang
 * build it in a GPR with mov/movk and transfer it with fmov (Clang also
 * rebuilds the high half used by pmull2 with mov/movk and dup), instead of
 * loading the constant pair with a single ldr. With asm operating on whole
 * vector registers, the constants are loaded from .rodata and pmull reads
 * the low lanes in place.
 */

static inline uint64x2_t pmull64(uint64x2_t a, uint64x2_t b)
{
	uint64x2_t r;

	asm("pmull %0.1q, %1.1d, %2.1d" : "=w"(r) : "w" (a), "w" (b));
	return r;
}

static inline uint64x2_t pmull64_high(uint64x2_t a, uint64x2_t b)
{
	uint64x2_t r;

	asm("pmull2 %0.1q, %1.2d, %2.2d" : "=w"(r) : "w" (a), "w" (b));
	return r;
}

static inline uint64x2_t pmull64_hi_lo(uint64x2_t a, uint64x2_t b)
{
	return pmull64(vextq_u64(a, a, 1), b);
}
