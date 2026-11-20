// SPDX-License-Identifier: GPL-2.0-only
/*
 * Each state has a table of equations. An equation relates two or three numbers.
 *
 *	xreg = coef * sym + off				r2 = 4 * sym0 + 8
 *	sym  = coef * sym + coef * sym + off	(sum)	sym2 = sym0 + sym1
 *	sym  = what an insn makes of two exprs	(op)	sym3 = (sym2 + 7) & 0xf8
 *
 * An xreg is a register, a stack slot or the trip index of a loop. The number in a pointer is
 * its offset. A sym is a number that the program had or could have had. The state says: there
 * are numbers for the syms, in their ranges, for which all equations hold (mod 2^64).
 *
 *	insn	deletes the equation of the xreg that it writes, the result gets a new equation
 *	jump	refines an xreg -> its sym -> the other syms -> their xregs
 *	join	guesses the equations, see equation_join.c
 *	prune	checks them, see check_equations()
 */
#include <linux/bpf.h>
#include <linux/cnum.h>
#include <linux/filter.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/tnum.h>
#include "equation.h"

static u64 low_bits(u32 bits)
{
	return bits ? GENMASK_ULL(bits - 1, 0) : 0;
}

/* Arithmetic */

static bool scalar_is_unknown(const struct scalar *s)
{
	return s->r64.size == U64_MAX && s->r32.size == U32_MAX && tnum_is_unknown(s->var_off) &&
	       s->step == 1;
}

static void scalar_scale(struct scalar *dst, const struct scalar *src, s64 coef)
{
	struct cnum64 r64 = src->r64;
	struct cnum32 r32 = src->r32;
	s32 coef32 = coef;
	u64 size;

	if (coef == 1) {
		*dst = *src;
		return;
	}
	if ((coef & 1) && scalar_is_unknown(src))
		return scalar_set_unknown(dst);
	*dst = *src;
	scalar_step_scale(dst, coef);
	dst->r64 = CNUM64_UNBOUNDED;
	dst->r32 = CNUM32_UNBOUNDED;
	if (!check_mul_overflow(abs64(coef), r64.size, &size) && size != U64_MAX)
		dst->r64 = (struct cnum64){ coef * (r64.base + (coef < 0 ? r64.size : 0)), size };
	size = abs64(coef32) * r32.size;
	if (size < U32_MAX)
		dst->r32 = (struct cnum32){ coef32 * (r32.base + (coef32 < 0 ? r32.size : 0)),
					    size };
	dst->var_off = tnum_mul(tnum_const(abs64(coef)), dst->var_off);
	if (coef < 0)
		dst->var_off = tnum_neg(dst->var_off);
}

/* @dst = @a + @coef * @b. It is not reduced, see scalar_add(). */
static void scalar_add_scaled(struct scalar *dst, const struct scalar *a,
			      const struct scalar *b, s64 coef)
{
	struct scalar tmp;

	if (scalar_is_unknown(a) || ((coef & 1) && scalar_is_unknown(b)))
		return scalar_set_unknown(dst);
	scalar_scale(&tmp, b, coef);
	scalar_add(dst, a, &tmp);
}

static void scalar_add_const(struct scalar *dst, u64 off)
{
	struct scalar tmp;

	if (!off || scalar_is_unknown(dst))
		return;
	scalar_set_const(&tmp, off);
	scalar_add(dst, dst, &tmp);
}

static void scalar_set_below(struct scalar *dst, u64 end)
{
	scalar_set_unknown(dst);
	dst->r64 = cnum64_from_urange(0, end - 1);
	scalar_bounds_sync(dst);
}

/* The ends of the ranges have the low bits that are known. False: there is no such number. */
static bool scalar_align_bounds(struct scalar *s)
{
	u64 low = (s->var_off.mask & -s->var_off.mask) - 1;
	u64 up = (s->var_off.value - s->r64.base) & low;
	u64 down = (s->r64.base + s->r64.size - s->var_off.value) & low;
	u32 up32 = (s->var_off.value - s->r32.base) & low;
	u32 down32 = (s->r32.base + s->r32.size - s->var_off.value) & low;

	if (up > s->r64.size || down > s->r64.size - up ||
	    up32 > s->r32.size || down32 > s->r32.size - up32)
		return false;
	if (!up && !down && !up32 && !down32)
		return true;
	s->r64 = (struct cnum64){ s->r64.base + up, s->r64.size - up - down };
	s->r32 = (struct cnum32){ s->r32.base + up32, s->r32.size - up32 - down32 };
	return scalar_intersect(s, s, 64);
}

/* The number is in @s and in @bounds. Returns true if @s got smaller. */
static bool refine_bounds(struct bpf_equations *eqs, struct scalar *s, const struct scalar *bounds)
{
	struct scalar new;

	if (scalar_subsumes(bounds, s))
		return false;
	new = *s;
	if (!scalar_intersect(&new, bounds, 64) || !scalar_align_bounds(&new)) {
		eqs->infeasible = true;
		return false;
	}
	if (scalar_equal(s, &new))
		return false;
	*s = new;
	eqs->normalized = false;
	return true;
}

/* @coef * (the number in @s) is in @bounds */
static bool refine_from_product(struct bpf_equations *eqs, struct scalar *s, s64 coef,
				const struct scalar *bounds)
{
	u64 span, lo, hi, step = abs64(coef);
	struct scalar new;
	struct tnum bits;

	if (is_plus_minus_one(coef)) {
		scalar_scale(&new, bounds, coef);
		return refine_bounds(eqs, s, &new);
	}
	/* the products are on an arc of @span + 1 numbers. [lo, hi] is @bounds from its start */
	if (check_mul_overflow(step, s->r64.size, &span) || bounds->r64.size == U64_MAX) {
		if (hweight64(step) != 1)
			return false;
		/* a shift to the left: the bits that stay are known */
		bits = tnum_rshift(coef < 0 ? tnum_neg(bounds->var_off) : bounds->var_off,
				   ilog2(step));
		scalar_set_unknown(&new);
		new.var_off = (struct tnum){ bits.value, bits.mask | ~(U64_MAX >> ilog2(step)) };
		return refine_bounds(eqs, s, &new);
	}
	lo = bounds->r64.base - coef * (s->r64.base + (coef < 0 ? s->r64.size : 0));
	hi = lo + bounds->r64.size;
	if (hi < lo && lo <= span)
		return false;
	lo = hi < lo || !lo ? 0 : div64_u64(lo - 1, step) + 1;
	hi = div64_u64(min(hi, span), step);
	if (lo > hi) {
		eqs->infeasible = true;
		return false;
	}
	scalar_set_unknown(&new);
	new.r64.base = s->r64.base + (coef > 0 ? lo : s->r64.size - hi);
	new.r64.size = hi - lo;
	return new.r64.size != U64_MAX && refine_bounds(eqs, s, &new);
}

/* @expr = (@expr - @off) / @coef. False if the result is not an expr. */
bool bpf_expr_div_exact(struct expr *expr, u64 off, s64 coef)
{
	struct expr quot;

	if (!coef)
		return false;
	if (is_plus_minus_one(coef))
		quot = make_expr(expr->coef * coef, expr->var, (expr->off - off) * coef);
	else
		quot = make_expr(div64_s64(expr->coef, coef), expr->var,
				 div64_s64(expr->off - off, coef));
	if (quot.coef * coef != expr->coef || quot.off * coef != expr->off - off)
		return false;
	*expr = quot;
	return true;
}

/*
 * @a - @b as an expr. There can be more than one. False: no more.
 * The search goes around the table once, from the equation that @pos starts with.
 */
bool bpf_find_next_diff(struct bpf_verifier_env *env, const struct bpf_equations *eqs,
			const struct expr *a, const struct expr *b, struct equation_pos *pos,
			struct expr *diff)
{
	const struct bpf_sym_equation *sym_eq;
	u32 seen_cnt = pos->seen_cnt;
	struct expr factor;
	int i, j;

	if (!a->coef || !b->coef || a->var == b->var) {
		*diff = make_expr(a->coef - b->coef, a->coef ? a->var : b->var, a->off - b->off);
		return !pos->seen_cnt++;
	}
	if (!var_is_sym(a->var) || !var_is_sym(b->var) || over_limit(env))
		return false;
	while (pos->seen_cnt < eqs->sym_equation_cnt) {
		pos->next = pos->next < eqs->sym_equation_cnt ? pos->next : 0;
		sym_eq = eqs->sym_equations + pos->next++;
		pos->seen_cnt++;
		i = find_sym_pos(sym_eq, var_symno(a->var));
		j = i < 3 ? find_sym_pos(sym_eq, var_symno(b->var)) : 3;
		if (j == 3 || is_op(sym_eq))
			continue;
		factor = make_expr(0, 0, is_plus_minus_one(sym_eq->coef[j]) ? -b->coef : a->coef);
		if (!bpf_expr_div_exact(&factor, 0,
					sym_eq->coef[is_plus_minus_one(sym_eq->coef[j]) ? j :
						       i]) ||
		    factor.off * sym_eq->coef[i] != a->coef ||
		    factor.off * sym_eq->coef[j] != -b->coef)
			continue;
		*diff = sym_expr(-factor.off * sym_eq->coef[3 - i - j], sym_eq->sym[3 - i - j],
				 a->off - b->off - factor.off * sym_eq->off);
		bpf_add_cost(env, pos->seen_cnt - seen_cnt, BPF_COST_SCAN);
		return true;
	}
	bpf_add_cost(env, pos->seen_cnt - seen_cnt, BPF_COST_SCAN);
	return false;
}
