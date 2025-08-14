// SPDX-License-Identifier: GPL-2.0-only
/* tnum: tracked (or tristate) numbers
 *
 * A tnum tracks knowledge about the bits of a value.  Each bit can be either
 * known (0 or 1), or unknown (x).  Arithmetic operations on tnums will
 * propagate the unknown bits such that the tnum result represents all the
 * possible results for possible values of the operands.
 */
#include <linux/kernel.h>
#include <linux/tnum.h>

#define TNUM(_v, _m)	(struct tnum){.value = _v, .mask = _m}
/* A completely unknown value */
const struct tnum tnum_unknown = { .value = 0, .mask = -1 };

struct tnum tnum_const(u64 value)
{
	return TNUM(value, 0);
}

struct tnum tnum_range(u64 min, u64 max)
{
	u64 chi = min ^ max, delta;
	u8 bits = fls64(chi);

	/* special case, needed because 1ULL << 64 is undefined */
	if (bits > 63)
		return tnum_unknown;
	/* e.g. if chi = 4, bits = 3, delta = (1<<3) - 1 = 7.
	 * if chi = 0, bits = 0, delta = (1<<0) - 1 = 0, so we return
	 *  constant min (since min == max).
	 */
	delta = (1ULL << bits) - 1;
	return TNUM(min & ~delta, delta);
}

struct tnum tnum_lshift(struct tnum a, u8 shift)
{
	return TNUM(a.value << shift, a.mask << shift);
}

struct tnum tnum_rshift(struct tnum a, u8 shift)
{
	return TNUM(a.value >> shift, a.mask >> shift);
}

struct tnum tnum_arshift(struct tnum a, u8 min_shift, u8 insn_bitness)
{
	/* if a.value is negative, arithmetic shifting by minimum shift
	 * will have larger negative offset compared to more shifting.
	 * If a.value is nonnegative, arithmetic shifting by minimum shift
	 * will have larger positive offset compare to more shifting.
	 */
	if (insn_bitness == 32)
		return TNUM((u32)(((s32)a.value) >> min_shift),
			    (u32)(((s32)a.mask)  >> min_shift));
	else
		return TNUM((s64)a.value >> min_shift,
			    (s64)a.mask  >> min_shift);
}

struct tnum tnum_add(struct tnum a, struct tnum b)
{
	u64 sm, sv, sigma, chi, mu;

	sm = a.mask + b.mask;
	sv = a.value + b.value;
	sigma = sm + sv;
	chi = sigma ^ sv;
	mu = chi | a.mask | b.mask;
	return TNUM(sv & ~mu, mu);
}

struct tnum tnum_sub(struct tnum a, struct tnum b)
{
	u64 dv, alpha, beta, chi, mu;

	dv = a.value - b.value;
	alpha = dv + a.mask;
	beta = dv - b.mask;
	chi = alpha ^ beta;
	mu = chi | a.mask | b.mask;
	return TNUM(dv & ~mu, mu);
}

struct tnum tnum_neg(struct tnum a)
{
	return tnum_sub(TNUM(0, 0), a);
}

struct tnum tnum_and(struct tnum a, struct tnum b)
{
	u64 alpha, beta, v;

	alpha = a.value | a.mask;
	beta = b.value | b.mask;
	v = a.value & b.value;
	return TNUM(v, alpha & beta & ~v);
}

struct tnum tnum_or(struct tnum a, struct tnum b)
{
	u64 v, mu;

	v = a.value | b.value;
	mu = a.mask | b.mask;
	return TNUM(v, mu & ~v);
}

struct tnum tnum_xor(struct tnum a, struct tnum b)
{
	u64 v, mu;

	v = a.value ^ b.value;
	mu = a.mask | b.mask;
	return TNUM(v & ~mu, mu);
}

/* Perform long multiplication, iterating through the trits in a. A small trick
 * inside the loop finds two possible partial products and takes their union,
 * improving the precision significantly.
 * A comment inside refers to a paper by Harishankar et al.:
 * https://arxiv.org/abs/2105.05398
 */
struct tnum tnum_mul(struct tnum a, struct tnum b)
{
	struct tnum acc = TNUM(0, 0);

	while (a.value || a.mask) {
		/* LSB of tnum a is a certain 1 */
		if (a.value & 1) {
			acc = tnum_add(acc, b);
		}
		/* LSB of tnum a is uncertain */
		else if (a.mask & 1) {
			/* Simply multiplying b with LSB(a)'s uncertainty results in decreased
			 * precision, as explained in an open question ("How can we incorporate
			 * correlation in unknown bits across partial products?") left by
			 * Harishankar et al. However, we know for sure that LSB(a) is either
			 * 0 or 1, from which we could find two possible partial products and
			 * take a union. This improves the precision in a significant number of
			 * cases.
			 *
			 * The first partial product (acc_0) is for the case LSB(a) = 0;
			 * but acc_0 = acc + 0 * b = acc.
			 */

			/* In case LSB(a) is 1 */
			u64 itermask = b.value | b.mask;
			struct tnum iterprod = TNUM(b.value & ~itermask, itermask);
			struct tnum acc_1 = tnum_add(acc, iterprod);

			acc = tnum_union(acc, acc_1);
		}
		/* Note: no case for LSB is certain 0 */
		a = tnum_rshift(a, 1);
		b = tnum_lshift(b, 1);
	}
	return acc;
}

/* Note that if a and b disagree - i.e. one has a 'known 1' where the other has
 * a 'known 0' - this will return a 'known 1' for that bit.
 */
struct tnum tnum_intersect(struct tnum a, struct tnum b)
{
	u64 v, mu;

	v = a.value | b.value;
	mu = a.mask & b.mask;
	return TNUM(v & ~mu, mu);
}

struct tnum tnum_union(struct tnum a, struct tnum b)
{
	u64 v = a.value & b.value;
	u64 mu = (a.value ^ b.value) | a.mask | b.mask;

	return TNUM(v & ~mu, mu);
}

struct tnum tnum_cast(struct tnum a, u8 size)
{
	a.value &= (1ULL << (size * 8)) - 1;
	a.mask &= (1ULL << (size * 8)) - 1;
	return a;
}

bool tnum_is_aligned(struct tnum a, u64 size)
{
	if (!size)
		return true;
	return !((a.value | a.mask) & (size - 1));
}

bool tnum_in(struct tnum a, struct tnum b)
{
	if (b.mask & ~a.mask)
		return false;
	b.value &= ~a.mask;
	return a.value == b.value;
}

int tnum_sbin(char *str, size_t size, struct tnum a)
{
	size_t n;

	for (n = 64; n; n--) {
		if (n < size) {
			if (a.mask & 1)
				str[n - 1] = 'x';
			else if (a.value & 1)
				str[n - 1] = '1';
			else
				str[n - 1] = '0';
		}
		a.mask >>= 1;
		a.value >>= 1;
	}
	str[min(size - 1, (size_t)64)] = 0;
	return 64;
}

struct tnum tnum_subreg(struct tnum a)
{
	return tnum_cast(a, 4);
}

struct tnum tnum_clear_subreg(struct tnum a)
{
	return tnum_lshift(tnum_rshift(a, 32), 32);
}

struct tnum tnum_with_subreg(struct tnum reg, struct tnum subreg)
{
	return tnum_or(tnum_clear_subreg(reg), tnum_subreg(subreg));
}

struct tnum tnum_const_subreg(struct tnum a, u32 value)
{
	return tnum_with_subreg(a, tnum_const(value));
}
