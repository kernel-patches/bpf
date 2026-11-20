// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bits.h>
#include <linux/bpf_verifier.h> /* for imod() */

#define T 32
#include "cnum_defs.h"
#undef T

#define T 64
#include "cnum_defs.h"
#undef T

struct cnum32 cnum32_from_cnum64(struct cnum64 cnum)
{
	if (cnum64_is_empty(cnum))
		return CNUM32_EMPTY;

	if (cnum.size >= U32_MAX)
		return (struct cnum32){ .base = 0, .size = U32_MAX };
	else
		return (struct cnum32){ .base = (u32)cnum.base, .size = cnum.size };
}

/* The zero extension of each value of 'cnum'. An arc that crosses U32_MAX/0 gives [0, U32_MAX]. */
struct cnum64 cnum64_zext32(struct cnum32 cnum)
{
	if (cnum32_is_empty(cnum))
		return CNUM64_EMPTY;
	return cnum64_from_urange(cnum32_umin(cnum), cnum32_umax(cnum));
}

/*
 * The sign extension of each value of 'cnum'.
 * An arc that crosses S32_MAX/S32_MIN gives [S32_MIN, S32_MAX].
 */
struct cnum64 cnum64_sext32(struct cnum32 cnum)
{
	if (cnum32_is_empty(cnum))
		return CNUM64_EMPTY;
	return cnum64_from_srange(cnum32_smin(cnum), cnum32_smax(cnum));
}

/*
 * The smallest arc with { x << 32 : x in 'cnum' }. The circle of 2^32 numbers is laid on the circle
 * of 2^64 numbers: sums, the order of signed and of unsigned numbers and the places where they wrap
 * stay.
 */
struct cnum64 cnum64_lshift32(struct cnum32 cnum)
{
	if (cnum32_is_empty(cnum))
		return CNUM64_EMPTY;
	return (struct cnum64){ .base = (u64)cnum.base << 32, .size = (u64)cnum.size << 32 };
}

/* { x >> 32 : x in 'cnum' } */
struct cnum32 cnum32_rshift32(struct cnum64 cnum)
{
	u32 base = cnum.base >> 32;
	u32 size = ((cnum.base + cnum.size) >> 32) - base;

	if (cnum64_is_empty(cnum))
		return CNUM32_EMPTY;
	/* less than 1 << 32 numbers are missing, or the arc ends one before its base */
	if (cnum.size >> 32 == U32_MAX || size == U32_MAX)
		return CNUM32_UNBOUNDED;
	return (struct cnum32){ .base = base, .size = size };
}

/*
 * Suppose 'a' and 'b' are laid out as follows:
 *
 *                                                          64-bit number axis --->
 *
 * N*2^32                   (N+1)*2^32                (N+2)*2^32                (N+3)*2^32
 * ||------|---|=====|-------||----------|=====|-------||----------|=====|----|--||
 *         |   |< b >|                   |< b >|                   |< b >|    |
 *         |   |                                                         |    |
 *         |<--+--------------------------- a ---------------------------+--->|
 *             |                                                         |
 *             |<-------------------------- t -------------------------->|
 *
 * In such a case it is possible to infer a more tight representation t
 * such that ∀ v ∈ a, (u32)v ∈ b: v ∈ t.
 */
struct cnum64 cnum64_cnum32_intersect(struct cnum64 a, struct cnum32 b)
{
	/*
	 * To simplify reasoning, rotate the circles so that [virtual] a1 starts
	 * at u32 boundary, b1 represents b in this new frame of reference.
	 */
	struct cnum32 b1 = { b.base - (u32)a.base, b.size };
	struct cnum64 t = a;
	u64 d, b1_max;

	if (cnum64_is_empty(a) || cnum32_is_empty(b))
		return CNUM64_EMPTY;

	if (cnum32_urange_overflow(b1)) {
		b1_max = (u32)b1.base + (u32)b1.size; /* overflow here is fine and necessary */
		if ((u32)a.size > b1_max && (u32)a.size < b1.base) {
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||=====|------------|=====||=====|---------|---|=====||
			 *  |b1 ->|            |<- b1||b1 ->|         |   |<- b1|
			 *  |<----------------- a1 ------------------>|
			 *  |<-------------- t ------------>|<-- d -->| (after adjustment)
			 *                                  ^
			 *                                b1_max
			 */
			d = (u32)a.size - b1_max;
			t.size -= d;
		} else {
			/*
			 * No adjustments possible in the following cases:
			 *
			 * ||=====|------------|=====||===|=|-------------|=|===||
			 *  |b1 ->|            |<- b1||b1 +>|             |<+ b1|
			 *  |<----------------- a1 ------>|                 |
			 *  |<----------------- (or) a1 ------------------->|
			 */
		}
	} else {
		if (t.size < b1.base)
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||----------|--|=======|--||------>
			 *  |<-- a1 -->|  |<- b ->|
			 */
			return CNUM64_EMPTY;
		/*
		 * N*2^32                   (N+1)*2^32
		 * ||-------------|========|-||-----| -------|========|-||
		 *  |             |<- b1 ->|        |        |<- b1 ->|
		 *  |<------------+ a1 ------------>|
		 *                |<------ t ------>| (after adjustment)
		 */
		t.base += b1.base;
		t.size -= b1.base;
		b1_max = b1.base + b1.size;
		d = 0;
		if ((u32)a.size < b1.base)
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||-------------|========|-||------|-------|========|-||
			 *  |             |<- b1 ->|         |       |<- b1 ->|
			 *  |<------------+-- a1 --+-------->|
			 *                |<- t  ->|<-- d -->| (after adjustment)
			 */
			d = (u32)a.size + (BIT_ULL(32) - b1_max);
		else if ((u32)a.size >= b1_max)
			/*
			 * N*2^32                   (N+1)*2^32
			 * ||--|========|------------||--|========|-------|-----||
			 *  |  |<- b1 ->|                |<- b1 ->|       |
			 *  |<-+------------------ a1 ------------+------>|
			 *     |<-------------- t --------------->|<- d ->| (after adjustment)
			 */
			d = (u32)a.size - b1_max;
		if (t.size < d)
			return CNUM64_EMPTY;
		t.size -= d;
	}
	return t;
}

/* Intersect 'in' with the set of integers defined by equation 'base + step * k'. */
struct cnum64 cnum64_intersect_linear(struct cnum64 in, u16 base, u16 step)
{
	s64 smin = cnum64_smin(in);
	s64 smax = cnum64_smax(in);
	s64 lo, hi;
	u16 d;

	if (step <= 1 || cnum64_is_empty(in) || cnum64_srange_overflow(in))
		return in;
	/*
	 * Round smin up to the next value congruent to 'base' modulo 'step',
	 * i.e. increase smin by d = (base - smin) mod step:
	 *
	 *                 |<---- d ---->|
	 *     |-----------|=============|...
	 * base+step*k    smin       base+step*(k+1)
	 */
	d = imod(base - imod(smin, step), step);
	if ((u64)smax - (u64)smin < d)
		return CNUM64_EMPTY;
	lo = smin + d;
	/*
	 * Round smax down to the previous value congruent to 'base' modulo 'step',
	 * i.e. decrease smax by d = (smax - base) mod step:
	 *
	 *     |<--- d --->|
	 *  ...|===========|-------------|
	 * base+step*k    smax       base+step*(k+1)
	 */
	d = imod(imod(smax, step) - base, step);
	hi = smax - d;
	return cnum64_from_srange(lo, hi);
}
