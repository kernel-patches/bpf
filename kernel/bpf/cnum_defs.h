/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef T
#error "Define T (bit width: 32, 64) before including cnum_defs.h"
#endif

#include <linux/cnum.h>
#include <linux/limits.h>
#include <linux/minmax.h>
#include <linux/compiler_types.h>

#if T == 32
#define ut2 u64
#define st2 s64
#define utt u32
#define stt s32
#define EMPTY CNUM32_EMPTY
#elif T == 64
#define ut2 unsigned __int128
#define st2 signed __int128
#define utt u64
#define stt s64
#define EMPTY CNUM64_EMPTY
#else
#error "Unsupported T value, cannot define ut2/st2"
#endif

#define cnum_t  __PASTE(cnum, T)
#define ut      __PASTE(u, T)
#define st      __PASTE(s, T)
#define UT_MAX  __PASTE(__PASTE(U, T), _MAX)
#define ST_MAX  __PASTE(__PASTE(S, T), _MAX)
#define ST_MIN  __PASTE(__PASTE(S, T), _MIN)
#define FN(name) __PASTE(__PASTE(cnum, T), __PASTE(_, name))

struct cnum_t FN(from_urange)(ut min, ut max)
{
	return (struct cnum_t){ .base = min, .size = (utt)max - min };
}

struct cnum_t FN(from_srange)(st min, st max)
{
	ut size = (ut)max - (ut)min;
	ut base = size == UT_MAX ? 0 : (ut)min;

	return (struct cnum_t){ .base = base, .size = size };
}

/* True if this cnum represents two unsigned ranges. */
static inline bool FN(urange_overflow)(struct cnum_t cnum)
{
	/* Same as cnum.base + cnum.size > UT_MAX but avoids overflow */
	return cnum.size > UT_MAX - (utt)cnum.base;
}

/*
 * cnum{T}_umin / cnum{T}_umax query an unsigned range represented by this cnum.
 * If cnum represents a range crossing the UT_MAX/0 boundary, the unbound range
 * [0..UT_MAX] is returned.
 */
ut FN(umin)(struct cnum_t cnum)
{
	return FN(urange_overflow)(cnum) ? 0 : cnum.base;
}

ut FN(umax)(struct cnum_t cnum)
{
	return FN(urange_overflow)(cnum) ? UT_MAX : cnum.base + cnum.size;
}

/* True if this cnum represents two signed ranges. */
static inline bool FN(srange_overflow)(struct cnum_t cnum)
{
	return FN(contains)(cnum, (ut)ST_MAX) && FN(contains)(cnum, (ut)ST_MIN);
}

/*
 * cnum{T}_smin / cnum{T}_smax query a signed range represented by this cnum.
 * If cnum represents a range crossing the ST_MAX/ST_MIN boundary, the unbound range
 * [ST_MIN..ST_MAX] is returned.
 */
st FN(smin)(struct cnum_t cnum)
{
	return FN(srange_overflow)(cnum)
	       ? ST_MIN
	       : min((st)cnum.base, (st)(cnum.base + cnum.size));
}

st FN(smax)(struct cnum_t cnum)
{
	return FN(srange_overflow)(cnum)
	       ? ST_MAX
	       : max((st)cnum.base, (st)(cnum.base + cnum.size));
}

/*
 * If there exists a cnum representing an intersection of cnums 'a' and 'b',
 * returns this intersection in 'out' and returns true.
 * If such cnum does not exist:
 * - if intersection is empty, returns false.
 * - if intersection produces two ranges, returns smaller of
 *   'a' or 'b' in 'out'.
 */
struct cnum_t FN(intersect)(struct cnum_t a, struct cnum_t b)
{
	struct cnum_t b1;
	ut dbase;

	if (FN(is_empty)(a) || FN(is_empty)(b))
		return EMPTY;

	if (a.base > b.base)
		swap(a, b);

	/*
	 * Rotate frame of reference such that a.base is 0.
	 * 'b1' is 'b' in this frame of reference.
	 */
	dbase = b.base - a.base;
	b1 = (struct cnum_t){ dbase, b.size };
	if (FN(urange_overflow)(b1)) {
		if (b1.base <= a.size) {
			/*
			 * Rotated frame (a.base at origin):
			 *
			 * 0                                       UT_MAX
			 * |--------------------------------------------|
			 * [=== a ==========================]           |
			 * [= b1 tail =]  [========= b1 main ==========>]
			 *                 ^-- b1.base <= a.size
			 *
			 * 'a' and 'b' intersect in two disjoint arcs,
			 * can't represent as single cnum, over-approximate
			 * the result.
			 */
			return a.size <= b.size ? a : b;
		} else {
			/*
			 * Rotated frame (a.base at origin):
			 *
			 * 0                                       UT_MAX
			 * |--------------------------------------------|
			 * [=== a =============]  |                     |
			 * [= b1 tail =]          [======= b1 main ====>]
			 *                         ^-- b1.base > a.size
			 *
			 * Only 'b' tail intersects 'a'.
			 */
			return (struct cnum_t) {
				.base = a.base,
				.size = min(a.size, (ut)(b1.base + b1.size)),
			};
		}
	} else if (a.size >= b1.base) {
		/*
		 * Rotated frame (a.base at origin):
		 *
		 * 0                                             UT_MAX
		 * |--------------------------------------------------|
		 * [=== a ==================================]         |
		 *                   [== b1 =====================]
		 *
		 * 0                                             UT_MAX
		 * |--------------------------------------------------|
		 * [=== a ==================================]         |
		 *                   [== b1 ====]
		 *                   ^-- b1.base <= a.size
		 *                   |<-- a.size - dbase -->|
		 *
		 * 'a' and 'b' intersect as one cnum.
		 */
		return (struct cnum_t) {
			.base = b.base,
			.size = min((ut)(a.size - dbase), b.size),
		};
	} else {
		return EMPTY;
	}
}

static inline struct cnum_t FN(normalize)(struct cnum_t cnum)
{
	if (cnum.size == UT_MAX && cnum.base != 0 && cnum.base != (ut)ST_MAX)
		cnum.base = 0;
	return cnum;
}

struct cnum_t FN(add)(struct cnum_t a, struct cnum_t b)
{
	if (FN(is_empty)(a) || FN(is_empty)(b))
		return EMPTY;
	if (a.size > UT_MAX - b.size)
		return (struct cnum_t){ 0, (utt)UT_MAX };
	else
		return FN(normalize)((struct cnum_t){ a.base + b.base, a.size + b.size });
}

struct cnum_t FN(negate)(struct cnum_t a)
{
	if (FN(is_empty)(a))
		return EMPTY;
	return FN(normalize)((struct cnum_t){ -((utt)a.base + a.size), a.size });
}

bool FN(is_empty)(struct cnum_t cnum)
{
	return cnum.base == EMPTY.base && cnum.size == EMPTY.size;
}

bool FN(contains)(struct cnum_t cnum, ut v)
{
	if (FN(is_empty)(cnum))
		return false;
	if (FN(urange_overflow)(cnum))
		return v >= cnum.base || v <= (ut)((utt)cnum.base + cnum.size);
	else
		return v >= cnum.base && v <= (ut)((utt)cnum.base + cnum.size);
}

bool FN(is_const)(struct cnum_t cnum)
{
	return cnum.size == 0;
}

/* true if every value in b is also in a */
static inline bool FN(contains_cnum)(struct cnum_t a, struct cnum_t b)
{
	struct cnum_t b1;

	if (FN(is_empty)(a) || FN(is_empty)(b))
		return FN(is_empty)(a) && FN(is_empty)(b);
	b1 = (struct cnum_t){ b.base - a.base, b.size };
	if (FN(urange_overflow)(b1))
		return a.size == UT_MAX;
	return b1.base + b1.size <= a.size;
}

static inline struct cnum_t FN(complement)(struct cnum_t cnum)
{
	if (FN(is_empty)(cnum))
		return (struct cnum_t){ 0, UT_MAX };
	if (cnum.size == UT_MAX)
		return EMPTY;
	return (struct cnum_t){
		.base = (ut)(cnum.base + cnum.size + 1),
		.size = (ut)(UT_MAX - cnum.size - 1),
	};
}

/* Gap from a's right end clockwise to b's start in a's frame. */
static inline struct cnum_t FN(gap)(struct cnum_t a, struct cnum_t b)
{
	struct cnum_t b1;
	ut x;

	if (FN(is_empty)(a) || FN(is_empty)(b))
		return EMPTY;
	b1 = (struct cnum_t){ b.base - a.base, b.size };
	/* a contains b.base */
	if (b1.base <= a.size)
		return EMPTY;
	/* b wraps in a's frame, its tail covers the gap */
	if (FN(urange_overflow)(b1))
		return EMPTY;
	x = (ut)(a.base + a.size + 1);
	if (x == b.base)
		return EMPTY;
	return (struct cnum_t){ x, (ut)(b.base - x - 1) };
}

/* Extend a to also cover b, keeping a.base fixed. */
static inline struct cnum_t FN(extend)(struct cnum_t a, struct cnum_t b)
{
	struct cnum_t b1;

	if (FN(is_empty)(a))
		return b;
	if (FN(is_empty)(b))
		return a;
	b1 = (struct cnum_t){ b.base - a.base, b.size };
	/* b in a's frame wraps past UT_MAX: must cover everything from a.base */
	if (FN(urange_overflow)(b1))
		return FN(normalize)((struct cnum_t){ a.base, UT_MAX });
	/* extend a's right bound to the further of a's or b's end */
	return FN(normalize)((struct cnum_t){ a.base, max(a.size, (ut)(b1.base + b1.size)) });
}

static inline struct cnum_t FN(bigger)(struct cnum_t a, struct cnum_t b)
{
	if (FN(is_empty)(a))
		return b;
	if (FN(is_empty)(b))
		return a;
	return a.size >= b.size ? a : b;
}

/*
 * Compute the tightest single cnum over-approximating the union of all arcs.
 * Arcs are assumed to be sorted by cnum[*].base in ascending order.
 *
 * Strategy: find the largest gap between arcs on the circular number line,
 * then return its complement. The result is the smallest arc that covers
 * all input arcs.
 */
static struct cnum_t FN(union)(struct cnum_t *cnum, u32 cnt)
{
	struct cnum_t dzone = EMPTY, g = EMPTY;
	u32 i;

	/* Seed dzone with all wrapping arcs (crossing the UT_MAX/0 boundary). */
	for (i = 0; i < cnt; i++)
		if (FN(urange_overflow)(cnum[i]))
			dzone = FN(extend)(dzone, cnum[i]);

	/*
	 * Scan arcs left to right, extending dzone to cover each one.
	 * Before absorbing each arc, record the gap between dzone's
	 * right edge and the arc's left edge; keep the largest gap seen.
	 */
	for (i = 0; i < cnt; i++) {
		g = FN(bigger)(g, FN(gap)(dzone, cnum[i]));
		dzone = FN(extend)(dzone, cnum[i]);
	}

	/*
	 * The complement of dzone is the remaining uncovered arc after
	 * the left-to-right scan (wrapping from last back to first).
	 * Pick the largest gap overall, then complement it to get the union.
	 */
	g = FN(bigger)(g, FN(complement)(dzone));
	return FN(complement)(g);
}

/*
 * Split arc 'a' into up to 3 sub-arcs at the UT_MAX/0 and ST_MAX/ST_MIN
 * boundaries. Returns the number of chunks (1..3).
 */
static int FN(cut)(struct cnum_t a, struct cnum_t chunks[3])
{
	int ncuts = 0;

	if (FN(srange_overflow)(a)) {
		chunks[ncuts++] = FN(from_urange)(a.base, ST_MAX);
		a = FN(from_urange)(ST_MIN, a.base + a.size);
	}
	if (FN(urange_overflow)(a)) {
		chunks[ncuts++] = FN(from_urange)(a.base, UT_MAX);
		a = FN(from_urange)(0, a.base + a.size);
	}
	chunks[ncuts++] = a;
	return ncuts;
}

static struct cnum_t FN(mk_mul_u)(utt a, utt b, utt c, utt d)
{
	ut2 size = (ut2)c * d - (ut2)a * b;

	if (size > UT_MAX)
		return (struct cnum_t){ 0, UT_MAX };
	return (struct cnum_t){ a * b, size };
}

static struct cnum_t FN(mk_mul_s)(stt a, stt b, stt c, stt d)
{
	st2 size = (st2)c * d - (st2)a * b;

	if (size > UT_MAX)
		return (struct cnum_t){ 0, UT_MAX };
	return (struct cnum_t){ a * b, size };
}

static struct cnum_t FN(mul_chunk)(struct cnum_t a, struct cnum_t b)
{
	struct cnum_t u, s;
	stt a_min = (st)a.base;
	stt a_max = (st)((utt)a.base + a.size);
	stt b_min = (st)b.base;
	stt b_max = (st)((utt)b.base + b.size);
	bool a_pos = a_min >= 0 && a_max >= 0;
	bool a_neg = a_min <  0 && a_max <  0;
	bool b_pos = b_min >= 0 && b_max >= 0;
	bool b_neg = b_min <  0 && b_max <  0;

	u = FN(mk_mul_u)(a.base, b.base, (utt)a.base + a.size, (utt)b.base + b.size);
	if (a_pos && b_pos)
		s = FN(mk_mul_u)(a_min, b_min, a_max, b_max);
	else if (a_neg && b_neg)
		s = FN(mk_mul_s)(a_max, b_max, a_min, b_min);
	else if (a_neg && b_pos)
		s = FN(mk_mul_s)(a_min, b_max, a_max, b_min);
	else if (a_pos && b_neg)
		s = FN(mk_mul_s)(a_max, b_min, a_min, b_max);
	else
		s = (struct cnum_t){ 0, UT_MAX };

	return FN(intersect)(u, s);
}

struct cnum_t FN(mul)(struct cnum_t a, struct cnum_t b)
{
	struct cnum_t ca[3], cb[3], cr[9];
	int na, nb, nr, i, j;

	if (FN(is_empty)(a) || FN(is_empty)(b))
		return EMPTY;

	na = FN(cut)(a, ca);
	nb = FN(cut)(b, cb);
	nr = 0;
	for (i = 0; i < na; i++)
		for (j = 0; j < nb; j++)
			cr[nr++] = FN(mul_chunk)(ca[i], cb[j]);
	/* sort by cr[*].base in ascending order */
	for (i = 1; i < nr; i++)
		for (j = i; j > 0 && cr[j].base < cr[j-1].base; j--)
			swap(cr[j], cr[j-1]);
	return FN(union)(cr, nr);
}

#undef EMPTY
#undef cnum_t
#undef ut
#undef st
#undef ut2
#undef st2
#undef utt
#undef stt
#undef UT_MAX
#undef ST_MAX
#undef ST_MIN
#undef FN
