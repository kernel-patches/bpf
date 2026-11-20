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

/* The table */

/* Make room for @cnt elements. @array is the address of the pointer. New elements are not set. */
bool bpf_grow_array(struct bpf_verifier_env *env, void *array, u32 *cap, u32 cnt, size_t size)
{
	void *p;

	if (cnt <= *cap)
		return true;
	p = kvrealloc(*(void **)array, array_size(2 * cnt, size), BPF_VERIFIER_GFP);
	if (!p) {
		env->no_mem = true;
		return false;
	}
	*(void **)array = p;
	env->mem += (2 * cnt - *cap) * size;
	*cap = 2 * cnt;
	return true;
}

u32 bpf_equations_bytes(const struct bpf_equations *eqs)
{
	return eqs->xreg_equation_cap * sizeof(*eqs->xreg_equations) +
	       eqs->sym_equation_cap * sizeof(*eqs->sym_equations) +
	       eqs->sym_cap * sizeof(*eqs->syms);
}

/* @dst becomes a copy of @src. @grow: with room for more. */
static bool realloc_equations(struct bpf_verifier_env *env, struct bpf_equations *dst,
			      const struct bpf_equations *src, bool grow)
{
	struct bpf_equations new = *src;
	u32 bytes, spare;

	new.xreg_equation_cap = src->xreg_equation_cnt +
				(grow ? src->xreg_equation_cnt / 2 + 4 : 0);
	new.sym_equation_cap = src->sym_equation_cnt + (grow ? src->sym_equation_cnt / 2 + 4 : 0);
	new.sym_cap = src->sym_cnt + (grow ? src->sym_cnt / 2 + 4 : 0);
	bytes = kmalloc_size_roundup(bpf_equations_bytes(&new));
	spare = (bytes - bpf_equations_bytes(&new)) /
		(sizeof(*new.xreg_equations) + sizeof(*new.sym_equations) + sizeof(*new.syms));
	new.xreg_equation_cap += spare;
	new.sym_equation_cap += spare;
	new.sym_cap += spare;
	bpf_add_cost(env, BPF_COST_INSN + bytes / 64, BPF_COST_SCAN);
	new.xreg_equations = kvmalloc(bytes, BPF_VERIFIER_GFP);
	if (!new.xreg_equations) {
		env->no_mem = true;
		return false;
	}
	new.sym_equations = (void *)(new.xreg_equations + new.xreg_equation_cap);
	new.syms = (void *)(new.sym_equations + new.sym_equation_cap);
	memcpy(new.xreg_equations, src->xreg_equations,
	       src->xreg_equation_cnt * sizeof(*src->xreg_equations));
	memcpy(new.sym_equations, src->sym_equations,
	       src->sym_equation_cnt * sizeof(*src->sym_equations));
	memcpy(new.syms, src->syms, src->sym_cnt * sizeof(*src->syms));
	kvfree(dst->xreg_equations);
	*dst = new;
	return true;
}

int bpf_equations_copy(struct bpf_verifier_env *env, struct bpf_equations *dst,
		       const struct bpf_equations *src)
{
	if (src->sym_cnt)
		return realloc_equations(env, dst, src, false) ? 0 : -ENOMEM;
	bpf_equations_free(dst);
	dst->infeasible = src->infeasible;
	return 0;
}

u64 bpf_new_sym(struct bpf_verifier_env *env, struct bpf_equations *eqs,
		const struct scalar *bounds)
{
	struct bpf_equation_env *eq_env = env->eq_env;
	struct scalar copy = *bounds;

	if (!bpf_grow_array(env, &eq_env->scratch, &eq_env->scratch_cap,
			    eqs->sym_cnt + 1, sizeof(*eq_env->scratch)) ||
	    (eqs->sym_cnt == eqs->sym_cap &&
	     !realloc_equations(env, eqs, eqs, true)))
		return VAR_NONE;
	eq_env->scratch[eqs->sym_cnt].refined_sweep = 0;
	copy.grew_once = false;
	eqs->syms[eqs->sym_cnt] = copy;
	eqs->normalized = false;
	return VAR_SYM | eqs->sym_cnt++;
}

/* Put a sym with coef 1 or -1 on the left side. False if there is none, or it says nothing. */
static bool isolate_sym(struct bpf_sym_equation *sym_eq)
{
	int i, j, lhs = -1;
	s64 sign;

	for (i = 0; i < 3; i++) {
		for (j = i + 1; j < 3; j++) {
			if (sym_eq->sym[j] != sym_eq->sym[i])
				continue;
			sym_eq->coef[i] += sym_eq->coef[j];
			sym_eq->coef[j] = 0;
		}
		if (lhs < 0 && is_plus_minus_one(sym_eq->coef[i]))
			lhs = i;
	}
	if (lhs < 0)
		return false;
	for (i = lhs; i > 0; i--) {
		swap(sym_eq->coef[i], sym_eq->coef[i - 1]);
		swap(sym_eq->sym[i], sym_eq->sym[i - 1]);
	}
	if (!sym_eq->coef[1]) {
		swap(sym_eq->coef[1], sym_eq->coef[2]);
		swap(sym_eq->sym[1], sym_eq->sym[2]);
	}
	sign = -sym_eq->coef[0];
	for (i = 0; i < 3; i++) {
		sym_eq->coef[i] *= sign;
		sym_eq->sym[i] = sym_eq->coef[i] ? sym_eq->sym[i] : NO_SYM;
	}
	sym_eq->off *= sign;
	return sym_eq->coef[1];
}

/* Delete the equations that are marked, and the equations of @insn_idx */
static void forget_sym_equations(struct bpf_verifier_env *env, struct bpf_equations *eqs,
				 s32 insn_idx)
{
	struct bpf_sym_equation *sym_eq, *next = eqs->sym_equations;

	for_each_sym_equation(env, eqs, sym_eq) {
		if (sym_eq->sym[0] == NO_SYM || sym_eq->insn_idx == insn_idx)
			continue;
		if (next != sym_eq)
			*next = *sym_eq;
		next++;
	}
	eqs->sym_equation_cnt = next - eqs->sym_equations;
}

/* An insn deletes the equations of its earlier visit. normalize_equations() limits the table. */
static bool append_sym_equation(struct bpf_verifier_env *env, struct bpf_equations *eqs,
				struct bpf_sym_equation sym_eq)
{
	if (env->no_mem)
		return false;
	if (sym_eq.insn_idx >= 0 && !env->eq_env->equation_added)
		forget_sym_equations(env, eqs, sym_eq.insn_idx);
	env->eq_env->equation_added = true;
	if (eqs->sym_equation_cnt == eqs->sym_equation_cap &&
	    !realloc_equations(env, eqs, eqs, true))
		return false;
	eqs->sym_equations[eqs->sym_equation_cnt++] = sym_eq;
	eqs->normalized = false;
	return true;
}

bool bpf_add_sym_equation(struct bpf_verifier_env *env, struct bpf_equations *eqs,
			  struct bpf_sym_equation sym_eq)
{
	return isolate_sym(&sym_eq) && append_sym_equation(env, eqs, sym_eq);
}

/* @res is what @insn makes of @op */
bool bpf_add_op(struct bpf_verifier_env *env, struct bpf_equations *eqs, s32 insn,
		const struct expr *op, const struct expr *res)
{
	return res->coef == 1 && !res->off && var_is_sym(res->var) &&
	       res->var != op[0].var && res->var != op[1].var &&
	       append_sym_equation(env, eqs, (struct bpf_sym_equation){
		{ 1, op[0].coef, op[1].coef },
		{ res->var, op[0].var, op[1].var },
		insn, op[0].off, op[1].off });
}

/* An insn like @insn made @res of @op, or it makes a constant */
bool bpf_find_op(struct bpf_verifier_env *env, const struct bpf_equations *eqs, s32 insn,
		 const struct expr *op, struct expr *res)
{
	const struct bpf_insn *a = &env->prog->insnsi[insn], *b;
	u8 same = BPF_OP(a->code) == BPF_END ? 0xff : ~BPF_X;
	const struct bpf_sym_equation *sym_eq;
	struct scalar bounds, src;
	struct expr expr[2];

	if (!op[0].coef && !op[1].coef) {
		scalar_set_const(&bounds, op[0].off);
		scalar_set_const(&src, op[1].off);
		scalar_alu(&bounds, &src, a);
		*res = make_expr(0, 0, bounds.var_off.value);
		return tnum_is_const(bounds.var_off);
	}
	if (over_limit(env))
		return false;
	for_each_sym_equation(env, eqs, sym_eq) {
		if (!is_op(sym_eq) || sym_eq->sym[0] == NO_SYM)
			continue;
		b = &env->prog->insnsi[sym_eq->insn_idx];
		expr[0] = rhs_expr(sym_eq, 0);
		expr[1] = rhs_expr(sym_eq, 1);
		if (((a->code ^ b->code) & same) || a->off != b->off ||
		    !expr_equal(&expr[0], &op[0]) || !expr_equal(&expr[1], &op[1]))
			continue;
		*res = sym_expr(1, sym_eq->sym[0], 0);
		return true;
	}
	return false;
}

/* The equation of @xreg, or of the first xreg after it */
static struct bpf_xreg_equation *xreg_equation_pos(const struct bpf_equations *eqs, u64 xreg)
{
	u32 lo = 0, hi = eqs->xreg_equation_cnt, mid;

	while (lo < hi) {
		mid = (lo + hi) / 2;
		if (eqs->xreg_equations[mid].xreg < xreg)
			lo = mid + 1;
		else
			hi = mid;
	}
	return eqs->xreg_equations + lo;
}

struct bpf_xreg_equation *bpf_find_xreg_equation(const struct bpf_equations *eqs, u64 xreg)
{
	struct bpf_xreg_equation *xreg_eq = xreg_equation_pos(eqs, xreg);

	return xreg_eq < eqs->xreg_equations + eqs->xreg_equation_cnt &&
	       xreg_eq->xreg == xreg ? xreg_eq : NULL;
}

/* @xreg holds @expr. It has no equation if @expr has no sym. */
void bpf_set_xreg_equation(struct bpf_verifier_env *env, struct bpf_equations *eqs, u64 xreg,
			   const struct expr *expr, bool is_ptr)
{
	struct bpf_xreg_equation *xreg_eq, *end;
	bool found, insert = expr && var_is_sym(expr->var);

	if (insert && eqs->xreg_equation_cnt == eqs->xreg_equation_cap)
		insert = realloc_equations(env, eqs, eqs, true);
	xreg_eq = xreg_equation_pos(eqs, xreg);
	end = eqs->xreg_equations + eqs->xreg_equation_cnt;
	found = xreg_eq < end && xreg_eq->xreg == xreg;
	if (found != insert) {
		bpf_add_cost(env, end - xreg_eq, BPF_COST_SCAN);
		memmove(xreg_eq + insert, xreg_eq + found,
			(end - xreg_eq - found) * sizeof(*xreg_eq));
		eqs->xreg_equation_cnt += insert - found;
	}
	if (insert)
		*xreg_eq = (struct bpf_xreg_equation){ xreg, expr->coef, expr->off,
						       var_symno(expr->var), is_ptr };
	eqs->normalized &= !found && !insert;
}

void bpf_equations_free(struct bpf_equations *eqs)
{
	kvfree(eqs->xreg_equations);
	memset(eqs, 0, sizeof(*eqs));
}

/* The cpu can speculate past the jump that refines the offset */
static bool ptr_off_is_tracked(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	return env->bypass_spec_v1 && bpf_reg_has_range(reg) && reg->type != PTR_TO_INSN &&
	       !(reg->type & PTR_UNTRUSTED);
}

/* The bounds of @var. NULL if there are none. */
struct scalar *bpf_find_var_bounds(struct bpf_verifier_env *env,
				   const struct bpf_verifier_state *st, u64 var, bool *is_ptr)
{
	u32 fr = var >> 32, idx = var;
	struct bpf_reg_state *reg;
	struct bpf_func_state *f;

	*is_ptr = false;
	if (var_is_sym(var))
		return &st->equations.syms[idx];
	f = fr <= st->curframe ? st->frame[fr] : NULL;
	if (!f)
		return NULL;
	if (idx >= BPF_XREG_TRIP)
		return idx - BPF_XREG_TRIP < f->loop_stack_cnt ?
		       &f->loop_stack[idx - BPF_XREG_TRIP].trip_index : NULL;
	reg = idx < MAX_BPF_REG ? &f->regs[idx] : !bpf_xreg_is_slot(idx) ? NULL :
	      bpf_get_spilled_reg(bpf_xreg_to_spi(idx), f, BIT(STACK_SPILL));
	if (!reg || reg->type == NOT_INIT)
		return NULL;
	*is_ptr = reg->type != SCALAR_VALUE;
	return !*is_ptr || ptr_off_is_tracked(env, reg) ? scalar_of(reg) : NULL;
}

/* A hidden register has no value, see MAX_BPF_XREG */
u64 bpf_reg_to_xreg(const struct bpf_verifier_state *st, u32 regno)
{
	return regno <= BPF_REG_FP ? bpf_xreg(st->curframe, regno) : VAR_NONE;
}

/* A pointer that became a scalar is another number */
static struct scalar *equation_xreg_bounds(struct bpf_verifier_env *env,
					   const struct bpf_verifier_state *st,
					   const struct bpf_xreg_equation *xreg_eq)
{
	bool is_ptr;
	struct scalar *s = bpf_find_var_bounds(env, st, xreg_eq->xreg, &is_ptr);

	return is_ptr == xreg_eq->is_ptr ? s : NULL;
}

/* The value of @xreg: a constant, the right side of its equation, or the xreg itself */
bool bpf_xreg_expr(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, u64 xreg,
		   struct expr *expr, bool *is_ptr)
{
	const struct scalar *s = bpf_find_var_bounds(env, st, xreg, is_ptr);
	const struct bpf_xreg_equation *xreg_eq;

	bpf_add_cost(env, 1, BPF_COST_XREG);
	if (!s)
		return false;
	if (tnum_is_const(s->var_off)) {
		*expr = make_expr(0, 0, s->var_off.value);
		return true;
	}
	xreg_eq = bpf_find_xreg_equation(&st->equations, xreg);
	*expr = xreg_eq && xreg_eq->is_ptr == *is_ptr ?
		sym_expr(xreg_eq->coef, xreg_eq->sym, xreg_eq->off) : make_expr(1, xreg, 0);
	return true;
}

/* It is not reduced */
static void eval_expr_nosync(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			     const struct expr *expr, struct scalar *bounds)
{
	bool is_ptr;

	bpf_add_cost(env, 1, BPF_COST_XREG);
	if (!expr->coef)
		return scalar_set_const(bounds, expr->off);
	scalar_scale(bounds, var_is_sym(expr->var) ? &st->equations.syms[var_symno(expr->var)] :
		     bpf_find_var_bounds(env, st, expr->var, &is_ptr), expr->coef);
	scalar_add_const(bounds, expr->off);
}

void bpf_eval_expr(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		   const struct expr *expr, struct scalar *bounds)
{
	eval_expr_nosync(env, st, expr, bounds);
	if (!expr->coef || (expr->coef == 1 && !expr->off) || scalar_is_unknown(bounds))
		return;
	bpf_add_cost(env, 4, BPF_COST_XREG);
	scalar_bounds_sync(bounds);
}

void bpf_eval_diff(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		   const struct expr *a, const struct expr *b, struct scalar *bounds)
{
	struct scalar b_bounds;

	eval_expr_nosync(env, st, a, bounds);
	eval_expr_nosync(env, st, b, &b_bounds);
	scalar_add_scaled(bounds, bounds, &b_bounds, -1);
	if (!scalar_is_unknown(bounds))
		scalar_bounds_sync(bounds);
}

/* Jumps refine */

/*
 * Packet pointers that share an id move together, see find_good_pkt_pointers().
 * Do not reduce them one by one: the known bits cut one range and leave the other.
 *	p = 20..40, bit 4 is set	q = p - 16 = 4..24, not 4..12
 */
static bool refine_ptr(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
		       struct scalar *s, const struct scalar *bounds)
{
	struct bpf_reg_state *ptr = container_of(&s->var_off, struct bpf_reg_state, var_off), *reg;
	struct scalar new = *s, shift;
	struct cnum64 old = s->r64;
	struct bpf_func_state *f;
	struct tnum known;
	s64 smax;

	/* a constant offset has to fit in an int */
	if (!refine_bounds(&st->equations, &new, bounds) ||
	    cnum64_smin(new.r64) <= -BPF_MAX_VAR_OFF || cnum64_smax(new.r64) >= BPF_MAX_VAR_OFF)
		return false;
	if (!type_is_pkt_pointer(ptr->type)) {
		*s = new;
		return true;
	}
	bpf_add_cost(env, bpf_xreg_cnt(st), BPF_COST_SCAN);
	bpf_for_each_reg_in_vstate(st, f, reg, ({
		if (reg->type != ptr->type || reg->id != ptr->id)
			continue;
		smax = reg_smax(reg);
		scalar_set_const(&shift, reg->r64.base - old.base);
		known = reg->var_off;
		scalar_add(scalar_of(reg), &shift, &new);
		known = tnum_intersect(known, reg->var_off);
		if (!tnum_subreg_is_const(known))
			reg->var_off = known;
		bpf_trim_pkt_range(reg, smax);
	}));
	return true;
}

/* All states share the marks. If propagate_bounds() does not follow, clear the mark. */
static void mark_sym_refined(struct bpf_verifier_env *env, u32 sym, u32 sweep)
{
	struct bpf_equation_env *eq_env = env->eq_env;

	if (eq_env->scratch[sym].refined_sweep)
		return;
	eq_env->scratch[sym].refined_sweep = sweep;
	if (sweep > 1)
		eq_env->scratch[eq_env->refined_cnt++].queued_sym = sym;
}

/* @expr is in @bounds. If its sym got smaller, @sweep has to look at the equations of the sym. */
static void refine_sym(struct bpf_verifier_env *env, struct bpf_equations *eqs,
		       struct expr expr, struct scalar bounds, u32 sweep)
{
	scalar_add_const(&bounds, -expr.off);
	if (refine_from_product(eqs, &eqs->syms[var_symno(expr.var)], expr.coef, &bounds))
		mark_sym_refined(env, var_symno(expr.var), sweep);
}

/* eval_expr_nosync(), and what the jump tells about a multiple of its operand */
static void expr_bounds_after_jump(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				   const struct expr *expr, struct scalar *bounds)
{
	const struct expr *jump_expr = &env->eq_env->jump_expr;
	struct scalar tmp;
	s64 coef;

	eval_expr_nosync(env, st, expr, bounds);
	if (!jump_expr->coef || !expr->coef || expr->var != jump_expr->var)
		return;
	coef = div64_s64(expr->coef, jump_expr->coef);
	if (coef * jump_expr->coef != expr->coef)
		return;
	scalar_scale(&tmp, &env->eq_env->jump_bounds, coef);
	scalar_add_const(&tmp, expr->off - coef * jump_expr->off);
	refine_bounds(&st->equations, bounds, &tmp);
}

static bool sym_is_refined(struct bpf_verifier_env *env, u32 sym, u32 sweep)
{
	return sym != NO_SYM && (!sweep || env->eq_env->scratch[sym].refined_sweep == sweep);
}

/* What @op makes of its operands. False: they have no number. */
static bool run_op(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
		   const struct bpf_sym_equation *op, struct scalar *res)
{
	struct expr expr[2] = { rhs_expr(op, 0), rhs_expr(op, 1) };
	struct scalar src;

	bpf_add_cost(env, 1, BPF_COST_INSN);
	expr_bounds_after_jump(env, st, &expr[0], res);
	expr_bounds_after_jump(env, st, &expr[1], &src);
	if (!scalar_intersect(res, res, 64) || !scalar_intersect(&src, &src, 64))
		return false;
	scalar_alu(res, &src, &env->prog->insnsi[op->insn_idx]);
	return true;
}

static void refine_syms_by_equation(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				    struct bpf_sym_equation *sym_eq, u32 sweep)
{
	struct expr expr[2] = { rhs_expr(sym_eq, 0), rhs_expr(sym_eq, 1) };
	struct bpf_equations *eqs = &st->equations;
	struct scalar operand[2], bounds, *lhs = &eqs->syms[sym_eq->sym[0]];
	bool refined[3];
	int i;

	for (i = 0; i < 3; i++)
		refined[i] = sym_is_refined(env, sym_eq->sym[i], sweep);
	if ((!refined[0] || is_op(sym_eq)) && !refined[1] && !refined[2])
		return;
	if (is_op(sym_eq)) {
		if (run_op(env, st, sym_eq, &bounds) && refine_bounds(eqs, lhs, &bounds))
			mark_sym_refined(env, sym_eq->sym[0], sweep + 1);
		return;
	}
	bpf_add_cost(env, 1, BPF_COST_INSN);
	expr_bounds_after_jump(env, st, &expr[0], &operand[0]);
	expr_bounds_after_jump(env, st, &expr[1], &operand[1]);
	for (i = 1; i >= 0; i--) {
		if (!expr[i].coef || !(refined[0] || refined[2 - i]))
			continue;
		scalar_add_scaled(&bounds, lhs, &operand[!i], -1);
		if (!refine_bounds(eqs, &operand[i], &bounds))
			continue;
		refined[i + 1] = true;
		refine_sym(env, eqs, expr[i], operand[i], sweep + 1);
	}
	scalar_add_scaled(&bounds, &operand[0], &operand[1], 1);
	if (tnum_is_const(operand[1].var_off)) {
		sym_eq->off += operand[1].var_off.value;
		sym_eq->coef[2] = 0;
		sym_eq->sym[2] = NO_SYM;
	}
	if ((refined[1] || refined[2]) && refine_bounds(eqs, lhs, &bounds))
		mark_sym_refined(env, sym_eq->sym[0], sweep + 1);
}

static void refine_sym_from_xreg(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				 const struct bpf_xreg_equation *xreg_eq)
{
	struct expr expr = sym_expr(xreg_eq->coef, xreg_eq->sym, xreg_eq->off);
	const struct scalar *s = equation_xreg_bounds(env, st, xreg_eq);
	struct scalar bounds;

	if (!s)
		return;
	bpf_add_cost(env, 2, BPF_COST_XREG);
	eval_expr_nosync(env, st, &expr, &bounds);
	if (refine_bounds(&st->equations, &bounds, s))
		refine_sym(env, &st->equations, expr, bounds, 1);
}

/* The number in the xreg of @xreg_eq is in @bounds */
static void refine_xreg(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			const struct bpf_xreg_equation *xreg_eq, const struct scalar *bounds)
{
	struct scalar *s = equation_xreg_bounds(env, st, xreg_eq);
	u32 xregno = xreg_eq->xreg;

	bpf_add_cost(env, 4, BPF_COST_XREG);
	if (!s || over_limit(env) ||
	    !(xreg_eq->is_ptr ? refine_ptr(env, st, s, bounds) :
	      refine_bounds(&st->equations, s, bounds)) ||
	    xreg_eq->xreg >> 32 != st->curframe)
		return;
	if (xregno < BPF_REG_FP)
		mark_reg_scratched(env, xregno);
	else if (xregno < BPF_XREG_TRIP)
		mark_stack_slot_scratched(env, bpf_xreg_to_spi(xregno));
}

/* Link the equations that use a sym. A link is 3 * equation + position of the sym + 1. */
static bool link_sym_equations(struct bpf_verifier_env *env, const struct bpf_equations *eqs)
{
	struct bpf_equation_env *eq_env = env->eq_env;
	u32 i = 3 * eqs->sym_equation_cnt, sym;

	if (!bpf_grow_array(env, &eq_env->use_links, &eq_env->use_link_cap, i,
			    sizeof(*eq_env->use_links)))
		return false;
	bpf_add_cost(env, eqs->sym_equation_cnt, BPF_COST_COPY);
	for (sym = 0; sym < eqs->sym_cnt; sym++)
		eq_env->scratch[sym].first_use = 0;
	while (i--) {
		sym = eqs->sym_equations[i / 3].sym[i % 3];
		if (sym == NO_SYM)
			continue;
		eq_env->use_links[i] = eq_env->scratch[sym].first_use;
		eq_env->scratch[sym].first_use = i + 1;
	}
	return true;
}

/* Each sweep goes one equation further. A sym propagates once. @all: to all xregs. */
static void propagate_bounds(struct bpf_verifier_env *env, struct bpf_verifier_state *st, bool all)
{
	struct bpf_equation_env *eq_env = env->eq_env;
	struct sym_scratch *scratch = eq_env->scratch, *refined;
	struct bpf_equations *eqs = &st->equations;
	struct bpf_xreg_equation *xreg_eq;
	struct bpf_sym_equation *sym_eq;
	struct scalar bounds;
	struct expr expr;
	u32 i, link;

	bpf_add_cost(env, eqs->sym_cnt, BPF_COST_SCAN);
	for (i = eq_env->refined_cnt = 0; i < eqs->sym_cnt; i++)
		if (scratch[i].refined_sweep)
			scratch[eq_env->refined_cnt++].queued_sym = i;
	if (!eq_env->refined_cnt && !all)
		return;
	for (i = 0;
	     i < eq_env->refined_cnt && (i || link_sym_equations(env, eqs)) &&
	     !over_limit(env); i++) {
		refined = &scratch[scratch[i].queued_sym];
		for (link = refined->first_use; link--; link = eq_env->use_links[link]) {
			sym_eq = &eqs->sym_equations[link / 3];
			/* once in a sweep */
			if ((link % 3 < 1 ||
			     !sym_is_refined(env, sym_eq->sym[0], refined->refined_sweep)) &&
			    (link % 3 < 2 ||
			     !sym_is_refined(env, sym_eq->sym[1], refined->refined_sweep)))
				refine_syms_by_equation(env, st, sym_eq, refined->refined_sweep);
		}
	}
	for_each_xreg_equation(env, eqs, xreg_eq) {
		if (!all && !scratch[xreg_eq->sym].refined_sweep)
			continue;
		expr = sym_expr(xreg_eq->coef, xreg_eq->sym, xreg_eq->off);
		expr_bounds_after_jump(env, st, &expr, &bounds);
		refine_xreg(env, st, xreg_eq, &bounds);
	}
	for (i = 0; i < eqs->sym_cnt; i++)
		scratch[i].refined_sweep = 0;
}

static void refine_from_reg(struct bpf_verifier_env *env, struct bpf_verifier_state *st, u32 regno)
{
	const struct bpf_xreg_equation *xreg_eq =
		bpf_find_xreg_equation(&st->equations, bpf_reg_to_xreg(st, regno));
	struct bpf_reg_state *reg = &st->frame[st->curframe]->regs[regno];
	struct scalar bounds = *scalar_of(reg);
	struct bpf_equation_env *eq_env = env->eq_env;
	struct expr expr;
	u64 span;

	if (reg->type == SCALAR_VALUE && scalar_align_bounds(&bounds))
		*scalar_of(reg) = bounds;
	else if (reg->type != SCALAR_VALUE && ptr_off_is_tracked(env, reg) &&
		 !type_is_pkt_pointer(reg->type) && scalar_align_bounds(&bounds))
		refine_ptr(env, st, scalar_of(reg), &bounds);
	if (!xreg_eq)
		return;
	refine_sym_from_xreg(env, st, xreg_eq);
	if (is_plus_minus_one(xreg_eq->coef) || xreg_eq->is_ptr ||
	    !equation_xreg_bounds(env, st, xreg_eq))
		return;
	/* the sym cannot show it if the product wraps */
	expr = sym_expr(xreg_eq->coef, xreg_eq->sym, xreg_eq->off);
	bpf_eval_expr(env, st, &expr, &bounds);
	if (scalar_subsumes(scalar_of(reg), &bounds) &&
	    !check_mul_overflow(abs64(expr.coef),
				st->equations.syms[xreg_eq->sym].r64.size, &span))
		return;
	eq_env->jump_expr = expr;
	eq_env->jump_bounds = *scalar_of(reg);
	mark_sym_refined(env, xreg_eq->sym, 1);
	propagate_bounds(env, st, false);
	eq_env->jump_expr.coef = 0;
}

/* Apply all equations */
void bpf_equations_refine_all(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_xreg_equation *xreg_eq;
	struct bpf_sym_equation *sym_eq;

	st->equations.needs_refine = false;
	for_each_xreg_equation(env, &st->equations, xreg_eq)
		refine_sym_from_xreg(env, st, xreg_eq);
	for_each_sym_equation(env, &st->equations, sym_eq)
		refine_syms_by_equation(env, st, sym_eq, 0);
	propagate_bounds(env, st, true);
}

static bool sym_has_xreg(struct bpf_verifier_env *env, const struct bpf_equations *eqs, u32 sym)
{
	const struct bpf_xreg_equation *xreg_eq;

	if (over_limit(env))
		return true;
	for_each_xreg_equation(env, eqs, xreg_eq)
		if (xreg_eq->sym == sym)
			return true;
	return false;
}

/*
 * A truncation is a sum 'low bits = x - 2^n * high bits', see expr_low_bits(). Go back to x if
 * only the low @bits bits matter, and no xreg holds the low bits. @all: also if an xreg does.
 *	w2 = w1; w2 += -1; w2 &= 255;		the low 8 bits of r1 - 1
 */
static void skip_truncation(struct bpf_verifier_env *env, const struct bpf_equations *eqs,
			    struct expr *expr, u32 bits, bool all)
{
	const struct bpf_sym_equation *sym_eq = eqs->sym_equations + eqs->sym_equation_cnt;

	if (over_limit(env))
		return;
	bpf_add_cost(env, eqs->sym_equation_cnt, BPF_COST_COPY);
	while (sym_eq-- > eqs->sym_equations)
		if (var_is_sym(expr->var) && sym_eq->sym[0] == var_symno(expr->var) &&
		    !is_op(sym_eq) && !((expr->coef * sym_eq->coef[2]) & low_bits(bits)) &&
		    (all || !sym_has_xreg(env, eqs, sym_eq->sym[0])))
			*expr = expr_scale(rhs_expr(sym_eq, 0), expr->coef, expr->off);
}

/* "@a - @b @op 0" holds */
static void refine_diff(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			const struct expr *a, const struct expr *b, u8 op, bool jmp32)
{
	struct equation_pos pos = {};
	struct scalar bounds, zero;
	struct expr diff;

	while (bpf_find_next_diff(env, &st->equations, a, b, &pos, &diff)) {
		bpf_eval_expr(env, st, &diff, &bounds);
		scalar_set_const(&zero, 0);
		scalars_refine_cond_op(&bounds, &zero, op, jmp32);
		if (!scalar_intersect(&bounds, &bounds, 64)) {
			st->equations.infeasible = true;
			return;
		}
		if (!var_is_sym(diff.var))
			continue;
		refine_sym(env, &st->equations, diff, bounds, 1);
		propagate_bounds(env, st, false);
	}
}

/* "@x != @low" holds. If @low is (u32)@x, then @x is above U32_MAX. */
static void refine_carry(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			 struct expr x, struct expr low, const struct bpf_reg_state *low_reg)
{
	struct expr untruncated = x;
	struct scalar bounds;

	if (reg_umax(low_reg) > U32_MAX || !var_is_sym(x.var))
		return;
	skip_truncation(env, &st->equations, &low, 32, true);
	skip_truncation(env, &st->equations, &untruncated, 32, true);
	if (low.var != untruncated.var || (u32)(low.coef - untruncated.coef) ||
	    (u32)(low.off - untruncated.off))
		return;
	scalar_set_unknown(&bounds);
	bounds.r64 = cnum64_from_urange(BIT_ULL(32), U64_MAX);
	refine_sym(env, &st->equations, x, bounds, 1);
	propagate_bounds(env, st, false);
}

/* The jump compares two numbers, or the offsets of two pointers into one object */
static bool compares_numbers(const struct bpf_verifier_state *st, const struct bpf_insn *insn)
{
	const struct bpf_reg_state *dst = &st->frame[st->curframe]->regs[insn->dst_reg];
	const struct bpf_reg_state *src = &st->frame[st->curframe]->regs[insn->src_reg];

	if (dst->type == SCALAR_VALUE)
		return src->type == SCALAR_VALUE;
	return BPF_CLASS(insn->code) == BPF_JMP && bpf_same_memory_origin(dst, src);
}

/*
 * @st went through the jump at @idx, and its operands are refined. A jump that compares two
 * numbers compares their difference with 0:
 *	end = p + sym0; ... if (p != end)		sym0 != 0
 */
void bpf_equations_jump(struct bpf_verifier_env *env, struct bpf_verifier_state *st, int idx,
			bool taken)
{
	const struct bpf_insn *insn = &env->prog->insnsi[idx];
	const struct bpf_reg_state *dst = &st->frame[st->curframe]->regs[insn->dst_reg];
	const struct bpf_reg_state *src = &st->frame[st->curframe]->regs[insn->src_reg];
	u8 op = taken ? BPF_OP(insn->code) : bpf_rev_opcode(BPF_OP(insn->code));
	bool jmp32 = BPF_CLASS(insn->code) == BPF_JMP32;
	bool src_is_reg = BPF_SRC(insn->code) == BPF_X, is_ptr;
	s64 max = jmp32 ? S32_MAX : S64_MAX / 2, min = -max - 1;
	struct expr a, b, untruncated[2];
	struct cnum64 lim;

	if (!env->eq_env)
		return;
	refine_from_reg(env, st, insn->dst_reg);
	if (src_is_reg)
		refine_from_reg(env, st, insn->src_reg);
	if (!st->equations.xreg_equation_cnt)
		return;
	propagate_bounds(env, st, false);
	if (!src_is_reg || BPF_OP(insn->code) == BPF_JSET || !compares_numbers(st, insn) ||
	    !bpf_xreg_expr(env, st, bpf_reg_to_xreg(st, insn->dst_reg), &a, &is_ptr) ||
	    !bpf_xreg_expr(env, st, bpf_reg_to_xreg(st, insn->src_reg), &b, &is_ptr))
		return;
	if (op == BPF_JEQ || op == BPF_JNE) {
		jmp32 |= scalars_fit_in_bits(scalar_of(dst), scalar_of(src), 32);
	} else {
		/* the difference does not wrap. An object is not in the first page. */
		if (is_ptr)
			lim = cnum64_from_srange(-SZ_4K, BPF_MAX_VAR_OFF);
		else if (op != bpf_signed_opcode(op))
			lim = cnum64_from_srange(0, max * 2 + 1);
		else
			lim = cnum64_from_srange(min, max);
		if (!cnum64_is_subset(lim, dst->r64) || !cnum64_is_subset(lim, src->r64))
			return;
		op = bpf_signed_opcode(op);
		jmp32 = false;
	}
	refine_diff(env, st, &a, &b, op, jmp32);
	if (op == BPF_JNE && !jmp32) {
		refine_carry(env, st, a, b, src);
		refine_carry(env, st, b, a, dst);
	}
	if (!jmp32)
		return;
	/* w1 += 1; if w1 != w2: the equation is for the number before the truncation */
	untruncated[0] = a;
	untruncated[1] = b;
	skip_truncation(env, &st->equations, &untruncated[0], 32, true);
	skip_truncation(env, &st->equations, &untruncated[1], 32, true);
	if (!expr_equal(&untruncated[0], &a))
		refine_diff(env, st, &untruncated[0], &b, op, true);
	if (!expr_equal(&untruncated[1], &b))
		refine_diff(env, st, &a, &untruncated[1], op, true);
	if (!expr_equal(&untruncated[0], &a) && !expr_equal(&untruncated[1], &b))
		refine_diff(env, st, &untruncated[0], &untruncated[1], op, true);
}

/* The largest sum of two arguments of a call: numbers, or offsets of pointers. Modulo 2^64. */
s64 bpf_equations_max_sum(struct bpf_verifier_env *env, int regno1, int regno2)
{
	struct bpf_equation_env *eq_env = env->eq_env;
	struct bpf_verifier_state *st = env->cur_state;
	struct equation_pos pos = {};
	struct expr neg, sum;
	struct scalar bounds;
	s64 max = S64_MAX;

	if (!eq_env || regno1 < 0 || regno2 < 0 ||
	    (~eq_env->has_arg_expr & (BIT(regno1) | BIT(regno2))))
		return max;
	neg = expr_scale(eq_env->arg_expr[regno2], -1, 0);
	while (bpf_find_next_diff(env, &st->equations, &eq_env->arg_expr[regno1], &neg, &pos,
				  &sum)) {
		bpf_eval_expr(env, st, &sum, &bounds);
		max = min(max, cnum64_smax(bounds.r64));
	}
	return max;
}

/* Insns write */

void bpf_equations_forget_xreg(struct bpf_verifier_env *env,
			       struct bpf_verifier_state *st, u64 xreg)
{
	bpf_set_xreg_equation(env, &st->equations, xreg, NULL, false);
}

/* @to gets the number of @from */
static void copy_xreg_equation(struct bpf_verifier_env *env, struct bpf_equations *eqs,
			       u64 to, u64 from)
{
	const struct bpf_xreg_equation *xreg_eq = bpf_find_xreg_equation(eqs, from);
	struct expr expr;

	if (!xreg_eq)
		return bpf_set_xreg_equation(env, eqs, to, NULL, false);
	expr = sym_expr(xreg_eq->coef, xreg_eq->sym, xreg_eq->off);
	bpf_set_xreg_equation(env, eqs, to, &expr, xreg_eq->is_ptr);
}

/* The number in @xreg is copied to another xreg. It needs a sym if it is @live_after. */
static bool assign_sym(struct bpf_verifier_env *env, u64 xreg, bool live_after, struct expr *expr,
		       bool *is_ptr)
{
	struct bpf_verifier_state *st = env->cur_state;

	if (!bpf_xreg_expr(env, st, xreg, expr, is_ptr))
		return false;
	if (expr->var != xreg)
		return true;
	if (!live_after)
		return false;
	expr->var = bpf_new_sym(env, &st->equations, bpf_find_var_bounds(env, st, xreg, is_ptr));
	bpf_set_xreg_equation(env, &st->equations, xreg, expr, *is_ptr);
	return var_is_sym(expr->var);
}

static bool reg_is_live_after(struct bpf_verifier_env *env, u32 regno)
{
	return env->insn_aux_data[env->insn_idx + 1].live_regs_before & BIT(regno);
}

/* Register @regno is spilled */
void bpf_equations_spill(struct bpf_verifier_env *env, struct bpf_func_state *frame, int spi,
			 int regno)
{
	struct bpf_verifier_state *st = env->cur_state;
	u64 slot = bpf_xreg(frame->frameno, bpf_spi_to_xreg(spi));
	struct expr expr;
	bool is_ptr;

	if (env->eq_env && regno >= 0 && !st->speculative &&
	    assign_sym(env, bpf_reg_to_xreg(st, regno), reg_is_live_after(env, regno),
		       &expr, &is_ptr))
		bpf_set_xreg_equation(env, &st->equations, slot, &expr, is_ptr);
	else
		bpf_equations_forget_xreg(env, st, slot);
}

/* The low @size bytes of what is loaded are from the spilled register */
void bpf_equations_fill(struct bpf_verifier_env *env, struct bpf_func_state *frame,
			int spi, int size)
{
	if (!env->eq_env)
		return;
	env->eq_env->fill_xreg = bpf_xreg(frame->frameno, bpf_spi_to_xreg(spi));
	env->eq_env->fill_bits = size * BITS_PER_BYTE;
}

/* Note the operands. Delete the equations of the registers that the insn writes. */
void bpf_equations_before_insn(struct bpf_verifier_env *env)
{
	const struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);
	bool src_is_reg = BPF_SRC(insn->code) == BPF_X && op != BPF_END;
	bool alu = class == BPF_ALU || class == BPF_ALU64;
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_equation_env *eq_env = env->eq_env;
	u32 def = env->insn_aux_data[env->insn_idx].def_regs, fr = st->curframe, i, r;
	struct bpf_equations *eqs = &st->equations;
	bool is_ptr;

	if (!eq_env)
		return;
	if (st->speculative || eqs->sym_cnt > 2 * eqs->clean_sym_cnt + MAX_BPF_REG)
		bpf_equations_clean(env, st);
	eq_env->insn_idx = env->insn_idx;
	eq_env->fill_xreg = VAR_NONE;
	eq_env->has_arg_expr = 0;
	eq_env->equation_added = eq_env->divided = false;
	for (i = 0; i < 2; i++) {
		r = i ? insn->src_reg : insn->dst_reg;
		eq_env->has_expr[i] = eq_env->is_ptr[i] = false;
		if (!alu || st->speculative)
			continue;
		if (i && !src_is_reg) {
			eq_env->operand_expr[1] = make_expr(0, 0, insn->imm);
			scalar_set_const(&eq_env->operand_bounds[1], insn->imm);
			eq_env->has_expr[1] = true;
		} else if (r <= BPF_REG_FP && cur_regs(env)[r].type != NOT_INIT) {
			eq_env->operand_bounds[i] = *scalar_of(&cur_regs(env)[r]);
			eq_env->has_expr[i] =
				assign_sym(env, bpf_reg_to_xreg(st, r), false,
					   &eq_env->operand_expr[i], &eq_env->is_ptr[i]);
		}
	}
	if (class == BPF_JMP && op == BPF_EXIT && fr && !st->frame[fr]->in_callback_fn)
		copy_xreg_equation(env, eqs, bpf_xreg(fr - 1, BPF_REG_0), bpf_xreg(fr, BPF_REG_0));
	if (class == BPF_JMP && op == BPF_CALL) {
		i = xreg_equation_pos(eqs, bpf_xreg(fr + 1, 0)) - eqs->xreg_equations;
		eqs->normalized &= i == eqs->xreg_equation_cnt;
		eqs->xreg_equation_cnt = i;
		for (r = BPF_REG_1; r <= BPF_REG_5 && i; r++)
			if (bpf_xreg_expr(env, st, bpf_xreg(fr, r), &eq_env->arg_expr[r], &is_ptr))
				eq_env->has_arg_expr |= BIT(r);
	}
	for (r = 0; r < BPF_REG_FP && def >> r && eqs->xreg_equation_cnt; r++) {
		if (!(def & BIT(r)))
			continue;
		/* the arguments are in the frame of the callee, if it gets one */
		if (r && (bpf_pseudo_call(insn) || bpf_is_callx(insn)))
			copy_xreg_equation(env, eqs, bpf_xreg(fr + 1, r), bpf_xreg(fr, r));
		bpf_equations_forget_xreg(env, st, bpf_xreg(fr, r));
	}
}

/* @expr = @divisor * quot + rem. Returns the expr of a new sym: @quot or @rem. */
static bool add_divmod_equation(struct bpf_verifier_env *env, struct expr *expr, u64 divisor,
				const struct scalar *quot, const struct scalar *rem, bool want_quot)
{
	struct bpf_equations *eqs = &env->cur_state->equations;
	struct bpf_sym_equation sym_eq = { { -1, expr->coef, -divisor }, { 0, expr->var },
					     env->eq_env->insn_idx, expr->off };
	int i;

	sym_eq.sym[0] = bpf_new_sym(env, eqs, rem);
	sym_eq.sym[2] = bpf_new_sym(env, eqs, quot);
	*expr = sym_expr(1, sym_eq.sym[want_quot ? 2 : 0], 0);
	env->eq_env->divided = true;
	if (!bpf_add_sym_equation(env, eqs, sym_eq))
		return false;
	refine_syms_by_equation(env, env->cur_state,
				&eqs->sym_equations[eqs->sym_equation_cnt - 1], 0);
	for (i = 0; i < 3; i++)
		if (sym_eq.coef[i])
			env->eq_env->scratch[sym_eq.sym[i]].refined_sweep = 0;
	return true;
}

/* Make @expr an expr of the left side of @sym_eq that has the same low @bits bits */
static bool rewrite_expr_by_truncation(const struct bpf_sym_equation *sym_eq,
				       struct expr *expr, u32 bits)
{
	struct expr factor = make_expr(0, 0, expr->coef);

	if (sym_eq->sym[1] != var_symno(expr->var) ||
	    !bpf_expr_div_exact(&factor, 0, sym_eq->coef[1]) ||
	    ((factor.off * sym_eq->coef[2]) & low_bits(bits)))
		return false;
	*expr = sym_expr(factor.off, sym_eq->sym[0], expr->off - factor.off * sym_eq->off);
	return true;
}

static void set_operand(struct bpf_sym_equation *op, int i, const struct expr *expr)
{
	op->coef[i + 1] = expr->coef;
	op->sym[i + 1] = expr->var;
	*(i ? &op->off_src : &op->off) = expr->off;
}

/* How many low bits of its operands does the insn of @op read? */
static u32 bits_read(struct bpf_verifier_env *env, const struct bpf_sym_equation *op)
{
	const struct bpf_insn *insn = &env->prog->insnsi[op->insn_idx];
	u32 bits = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;

	if (BPF_OP(insn->code) == BPF_END)
		return insn->imm;
	if (BPF_OP(insn->code) == BPF_MOV)
		return insn->off ?: bits;
	if (BPF_OP(insn->code) == BPF_AND && !op->coef[2])
		return min_t(u32, fls64(op->off_src), bits);
	return bits;
}

static void op_skips_truncations(struct bpf_verifier_env *env, struct bpf_equations *eqs,
				 struct bpf_sym_equation *op)
{
	u32 i, bits = bits_read(env, op);
	struct expr expr;

	for (i = 0; i < 2 && bits < 64; i++) {
		expr = rhs_expr(op, i);
		if (!expr.coef)
			continue;
		skip_truncation(env, eqs, &expr, bits, false);
		set_operand(op, i, &expr);
	}
}

/*
 * A test of @truncation tells more, if @op reads no other bits:
 *	r2 = r1; r2 &= 0xf8; r1 &= 0xff; if r1 > 8 goto out;
 */
static void read_from_truncation(struct bpf_verifier_env *env, struct bpf_sym_equation *op,
				 const struct bpf_sym_equation *truncation)
{
	struct expr expr;
	int i;

	for (i = 0; i < 2 && is_op(op) && truncation->sym[0] != op->sym[0]; i++) {
		expr = rhs_expr(op, i);
		if (expr.coef && rewrite_expr_by_truncation(truncation, &expr, bits_read(env, op)))
			set_operand(op, i, &expr);
	}
}

/* @res and @candidate have the same low @bits bits. If they are equal @expr gets @candidate. */
static bool take_expr_if_fits(struct bpf_verifier_env *env, const struct scalar *res,
			      struct expr *expr, struct expr candidate, u32 bits)
{
	struct scalar bounds;

	bpf_eval_expr(env, env->cur_state, &candidate, &bounds);
	if (!scalars_fit_in_bits(&bounds, res, bits))
		return false;
	*expr = candidate;
	return true;
}

/* @res is an extension of the low @bits bits of @expr. Make @expr the value of @res. */
static bool expr_low_bits(struct bpf_verifier_env *env, struct scalar *res,
			  struct expr *expr, u32 bits)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_sym_equation *sym_eq;
	struct scalar bounds;
	struct expr operand;

	if (bits == 64)
		return true;
	if (!(expr->coef & low_bits(bits)))
		return false;
	if (take_expr_if_fits(env, res, expr, *expr, bits))
		return true;
	operand = *expr;
	skip_truncation(env, &st->equations, &operand, bits, true);
	if (take_expr_if_fits(env, res, expr, operand, bits))
		return true;
	skip_truncation(env, &st->equations, expr, bits, false);
	for_each_sum(env, &st->equations, sym_eq) {
		operand = *expr;
		if (rewrite_expr_by_truncation(sym_eq, &operand, bits) &&
		    take_expr_if_fits(env, res, expr, operand, bits))
			return true;
	}
	scalar_set_unknown(&bounds);
	if (!add_divmod_equation(env, expr, BIT_ULL(bits), &bounds, res, false))
		return false;
	/* a number has a range for 32 bits */
	if (bits < 32)
		for_each_sym_equation(env, &st->equations, sym_eq)
			read_from_truncation(env, sym_eq, st->equations.sym_equations +
					     st->equations.sym_equation_cnt - 1);
	return true;
}

/* The source goes into the equation of the result */
static bool assign_sym_to_src(struct bpf_verifier_env *env)
{
	struct bpf_equation_env *eq_env = env->eq_env;
	const struct bpf_insn *insn = &env->prog->insnsi[eq_env->insn_idx];

	if (!eq_env->has_expr[1] && insn->src_reg != insn->dst_reg &&
	    reg_is_live_after(env, insn->src_reg))
		eq_env->has_expr[1] =
			assign_sym(env, bpf_reg_to_xreg(env->cur_state, insn->src_reg), true,
				   &eq_env->operand_expr[1], &eq_env->is_ptr[1]);
	return eq_env->has_expr[1];
}

static bool alu_add(struct bpf_verifier_env *env, struct expr *expr, s64 sign, u32 bits)
{
	struct bpf_equations *eqs = &env->cur_state->equations;
	struct bpf_equation_env *eq_env = env->eq_env;
	struct expr *a = &eq_env->operand_expr[0], *b = &eq_env->operand_expr[1], neg;
	struct scalar bounds;
	struct equation_pos pos = {};
	int i;

	for (i = 0; i < 2; i++) {
		if (i ? assign_sym_to_src(env) : eq_env->has_expr[0])
			continue;
		/* it is dead after the insn. Its range is the sum minus the other operand. */
		if ((bits == 64 ? !~eq_env->operand_bounds[i].r64.size :
		     eq_env->operand_bounds[i].r32.size == U32_MAX) ||
		    !(i || assign_sym_to_src(env)) || !eq_env->operand_expr[!i].coef)
			return false;
		eq_env->operand_expr[i] =
			make_expr(1,
				  bpf_new_sym(env, eqs, &eq_env->operand_bounds[i]), 0);
		if (env->no_mem)
			return false;
	}
	neg = expr_scale(*b, -sign, 0);
	if (bpf_find_next_diff(env, eqs, a, &neg, &pos, expr))
		return true;
	scalar_add_scaled(&bounds, &eq_env->operand_bounds[0], &eq_env->operand_bounds[1], sign);
	scalar_bounds_sync(&bounds);
	*expr = make_expr(1, bpf_new_sym(env, eqs, &bounds), 0);
	return bpf_add_sym_equation(env, eqs, (struct bpf_sym_equation){
		{ -1, a->coef, -neg.coef },
		{ expr->var, a->var, b->var }, eq_env->insn_idx, a->off - neg.off });
}

/* An insn that is a sum, a product with a constant, or the reverse of that */
static bool alu_linear(struct bpf_verifier_env *env, const struct bpf_insn *insn,
		       struct scalar *res, struct expr *expr)
{
	u32 bits = BPF_CLASS(insn->code) == BPF_ALU64 ? 64 : 32;
	struct bpf_equation_env *eq_env = env->eq_env;
	struct tnum a = eq_env->operand_bounds[0].var_off;
	struct tnum b = eq_env->operand_bounds[1].var_off;
	u8 op = BPF_OP(insn->code);
	struct scalar bounds;
	struct expr untruncated;
	u64 c;

	if (op == BPF_MOV) {
		if (insn->imm || !assign_sym_to_src(env))
			return false;
		*expr = eq_env->operand_expr[1];
		return expr_low_bits(env, res, expr, insn->off ?: bits);
	}
	if (insn->off)
		return false;
	if ((op == BPF_OR || op == BPF_XOR) && !((a.value | a.mask) & (b.value | b.mask)))
		op = BPF_ADD;
	if (op == BPF_ADD || op == BPF_SUB)
		return alu_add(env, expr, op == BPF_ADD ? 1 : -1, bits) &&
		       expr_low_bits(env, res, expr, bits);
	if (!eq_env->has_expr[0])
		return false;
	if (op == BPF_MUL && !eq_env->operand_expr[0].coef && assign_sym_to_src(env))
		swap(eq_env->operand_expr[0], eq_env->operand_expr[1]);
	if (!eq_env->has_expr[1] || eq_env->operand_expr[1].coef)
		return false;
	*expr = eq_env->operand_expr[0];
	c = eq_env->operand_expr[1].off & low_bits(bits);
	switch (op) {
	case BPF_NEG:
		*expr = expr_scale(*expr, -1, 0);
		return expr_low_bits(env, res, expr, bits);
	case BPF_LSH:
		if (c >= bits)
			return false;
		c = BIT_ULL(c);
		fallthrough;
	case BPF_MUL:
		*expr = expr_scale(*expr, bits == 32 ? (s32)c : c, 0);
		return expr_low_bits(env, res, expr, bits);
	case BPF_AND:
		if (c && !(c & (c + 1)))
			return expr_low_bits(env, res, expr, min_t(u32, fls64(c), bits));
		/* x & -8 == x - (x & 7) */
		scalar_set_unknown(&bounds);
		bounds.var_off = tnum_and(a, tnum_const(~c));
		scalar_bounds_sync(&bounds);
		return add_divmod_equation(env, expr, 1, res, &bounds, true);
	case BPF_RSH:
	case BPF_ARSH:
		if (!c || c >= bits)
			return false;
		/* w1 <<= 24; w1 s>>= 24; */
		untruncated = *expr;
		if (expr->coef & low_bits(c))
			skip_truncation(env, &env->cur_state->equations, &untruncated, bits, true);
		if (!((untruncated.coef | untruncated.off) & low_bits(c))) {
			*expr = make_expr(untruncated.coef >> c, untruncated.var,
					  (s64)untruncated.off >> c);
			return expr_low_bits(env, res, expr, bits - c);
		}
		c = BIT_ULL(c);
		fallthrough;
	case BPF_DIV:
		if (c < 2 || (bits == 32 && cnum64_umax(eq_env->operand_bounds[0].r64) >
					    (op == BPF_ARSH ? S32_MAX : U32_MAX)))
			return false;
		scalar_set_below(&bounds, c);
		return add_divmod_equation(env, expr, c, res, &bounds, true);
	}
	return false;
}

/* The operands of an op possibly skipped their truncations, see op_skips_truncations() */
static bool find_same_op(struct bpf_verifier_env *env, struct expr *expr)
{
	struct bpf_equations *eqs = &env->cur_state->equations;
	struct bpf_equation_env *eq_env = env->eq_env;
	struct bpf_sym_equation sym_eq = { .insn_idx = eq_env->insn_idx };
	struct expr op[2];
	int i;

	if (bpf_find_op(env, eqs, eq_env->insn_idx, eq_env->operand_expr, expr))
		return true;
	for (i = 0; i < 2; i++)
		set_operand(&sym_eq, i, &eq_env->operand_expr[i]);
	op_skips_truncations(env, eqs, &sym_eq);
	for (i = 0; i < 2; i++)
		op[i] = rhs_expr(&sym_eq, i);
	return bpf_find_op(env, eqs, eq_env->insn_idx, op, expr);
}

/*
 * The same as read_from_truncation(), the test is before @op:
 *	r2 = r1; r2 &= 0xff; if r2 > 0xdf goto out; r1 &= 0xf0;
 */
static void refine_op_by_truncations(struct bpf_verifier_env *env,
				     const struct bpf_sym_equation *op)
{
	struct bpf_equations *eqs = &env->cur_state->equations;
	struct bpf_sym_equation *sym_eq, copy;
	struct scalar bounds;

	if (bits_read(env, op) >= 32)
		return;
	for_each_sum(env, eqs, sym_eq) {
		copy = *op;
		read_from_truncation(env, &copy, sym_eq);
		if (memcmp(&copy, op, sizeof(copy)) && run_op(env, env->cur_state, &copy, &bounds))
			refine_bounds(eqs, &eqs->syms[op->sym[0]], &bounds);
	}
}

/*
 * A sum does not tell all about the result. A jump that refines the operands runs the op again:
 *	r2 = r1; r2 ^= 5; if r1 > 20 goto out;
 */
static bool alu_scalar(struct bpf_verifier_env *env, const struct bpf_insn *insn,
		       struct scalar *res, struct expr *expr)
{
	struct bpf_equations *eqs = &env->cur_state->equations;
	struct bpf_equation_env *eq_env = env->eq_env;
	bool ok;

	if (BPF_OP(insn->code) == BPF_MOV) {
		eq_env->operand_expr[0] = make_expr(0, 0, 0);
		eq_env->has_expr[0] = !insn->imm;
	}
	if (eq_env->has_expr[0] && eq_env->has_expr[1] && find_same_op(env, expr))
		return true;
	ok = alu_linear(env, insn, res, expr);
	if ((ok && !eq_env->divided) || !eq_env->has_expr[0] || !assign_sym_to_src(env))
		return ok;
	if (!ok)
		*expr = make_expr(1, bpf_new_sym(env, eqs, res), 0);
	if (!bpf_add_op(env, eqs, eq_env->insn_idx, eq_env->operand_expr, expr))
		return true;
	op_skips_truncations(env, eqs, &eqs->sym_equations[eqs->sym_equation_cnt - 1]);
	refine_op_by_truncations(env, &eqs->sym_equations[eqs->sym_equation_cnt - 1]);
	return true;
}

/* The insn is proven */
int bpf_equations_after_insn(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_equation_env *eq_env = env->eq_env;
	const struct bpf_insn *insn;
	struct scalar *res, bounds;
	bool is_ptr, ok, was_ptr;
	struct expr expr;
	u8 class, op;
	u64 dst;

	if (!eq_env)
		return 0;
	insn = &env->prog->insnsi[eq_env->insn_idx];
	dst = bpf_reg_to_xreg(st, insn->dst_reg);
	class = bpf_atomic_is_load_acq(insn) ? BPF_LDX : BPF_CLASS(insn->code);
	op = BPF_OP(insn->code);
	if ((class != BPF_ALU && class != BPF_ALU64 && class != BPF_LDX) || st->speculative)
		goto out;
	res = bpf_find_var_bounds(env, st, dst, &is_ptr);
	if (!res || tnum_is_const(res->var_off))
		goto out;
	bounds = *res;
	if (!is_ptr && scalar_align_bounds(&bounds))
		*res = bounds;
	else if (!is_ptr)
		st->equations.infeasible = true;
	if (class == BPF_LDX)
		ok = eq_env->fill_xreg != VAR_NONE &&
		     assign_sym(env, eq_env->fill_xreg, true, &expr, &was_ptr) &&
		     was_ptr == is_ptr && expr_low_bits(env, res, &expr, eq_env->fill_bits);
	else if (op == BPF_MOV ? is_ptr != eq_env->is_ptr[1] :
		 is_ptr != eq_env->is_ptr[0] + eq_env->is_ptr[1])
		ok = false;
	else if (is_ptr)
		ok = class == BPF_ALU64 && alu_linear(env, insn, res, &expr);
	else
		ok = alu_scalar(env, insn, res, &expr);
	if (!ok || (expr.coef && !var_is_sym(expr.var)))
		goto out;
	/* it was computed before */
	eval_expr_nosync(env, st, &expr, &bounds);
	if (!is_ptr)
		refine_bounds(&st->equations, res, &bounds);
	bpf_set_xreg_equation(env, &st->equations, dst, &expr, is_ptr);
out:
	return env->no_mem ? -ENOMEM : 0;
}

/* Clean up */

static bool sym_has_one_use(const struct sym_scratch *scratch, u32 sym)
{
	return sym != NO_SYM && scratch[sym].use_cnt == 1;
}

static void count_sym_uses(struct bpf_verifier_env *env, const struct bpf_equations *eqs)
{
	struct sym_scratch *scratch = env->eq_env->scratch;
	const struct bpf_xreg_equation *xreg_eq;
	const struct bpf_sym_equation *sym_eq;
	u32 i;

	bpf_add_cost(env, eqs->sym_cnt, BPF_COST_COPY);
	memset(scratch, 0, eqs->sym_cnt * sizeof(*scratch));
	for_each_xreg_equation(env, eqs, xreg_eq)
		if (xreg_eq->coef)
			scratch[xreg_eq->sym].use_cnt++;
	for_each_sym_equation(env, eqs, sym_eq) {
		for (i = 0; i < 3; i++)
			if (sym_eq->coef[i])
				scratch[sym_eq->sym[i]].use_cnt++;
		if (is_op(sym_eq))
			scratch[sym_eq->sym[0]].op = sym_eq;
	}
}

static void replace_operand(struct bpf_sym_equation *sym_eq, u32 sym, const struct expr *new_expr)
{
	struct expr expr;
	int i;

	for (i = 0; i < 2; i++) {
		if (sym_eq->sym[i + 1] != sym)
			continue;
		expr = expr_scale(*new_expr, sym_eq->coef[i + 1], rhs_expr(sym_eq, i).off);
		set_operand(sym_eq, i, &expr);
	}
	if (sym_eq->sym[0] == sym || sym_eq->sym[0] == var_symno(new_expr->var))
		sym_eq->sym[0] = NO_SYM;
}

/* Replace @sym with @expr */
static bool substitute_sym(struct bpf_verifier_env *env, struct bpf_equations *eqs, u32 sym,
			   const struct expr *expr, const struct bpf_sym_equation *def_equation)
{
	struct bpf_xreg_equation *xreg_eq;
	struct bpf_sym_equation *sym_eq, new;
	bool changed = false;
	int i;

	if (over_limit(env))
		return false;
	for_each_xreg_equation(env, eqs, xreg_eq) {
		if (xreg_eq->sym != sym)
			continue;
		xreg_eq->off += xreg_eq->coef * expr->off;
		xreg_eq->coef *= expr->coef;
		xreg_eq->sym = expr->var;
	}
	for_each_sym_equation(env, eqs, sym_eq) {
		i = find_sym_pos(sym_eq, sym);
		if (i == 3 || sym_eq == def_equation || sym_eq->sym[0] == NO_SYM)
			continue;
		if (is_op(sym_eq)) {
			replace_operand(sym_eq, sym, expr);
			continue;
		}
		new = *sym_eq;
		new.off += new.coef[i] * expr->off;
		new.coef[i] *= expr->coef;
		new.sym[i] = expr->var;
		if (isolate_sym(&new))
			*sym_eq = new;
		else if (i || !expr->coef || find_sym_pos(sym_eq, expr->var) < 3)
			sym_eq->sym[0] = NO_SYM;
		changed = true;
	}
	return changed;
}

/* The position of the sym that only @sym_eq uses. -1 if there is none. */
static int find_one_use_sym(const struct sym_scratch *scratch,
			    const struct bpf_sym_equation *sym_eq)
{
	int i;

	for (i = 2; i >= 0 && !sym_has_one_use(scratch, sym_eq->sym[i]); i--)
		;
	return i;
}

/* Another equation is for the same sum as @sym_eq. It gets the range of the sym at @one_use. */
static bool refine_same_sum(struct bpf_verifier_env *env, struct bpf_equations *eqs,
			    const struct bpf_sym_equation *sym_eq, int one_use)
{
	int i = !one_use, j = 2 - (one_use == 2);
	struct expr a = sym_expr(sym_eq->coef[i], sym_eq->sym[i], sym_eq->off), diff;
	struct expr b = sym_expr(-sym_eq->coef[j], sym_eq->sym[j], 0);
	struct equation_pos pos = {};
	struct scalar bounds;

	/* the other equation can be a wrong guess, and then both are lost */
	if (eqs == &env->eq_env->join_state.equations)
		return false;
	while (b.coef && bpf_find_next_diff(env, eqs, &a, &b, &pos, &diff)) {
		if (!is_plus_minus_one(diff.coef) || var_symno(diff.var) == NO_SYM ||
		    var_symno(diff.var) == sym_eq->sym[one_use])
			continue;
		scalar_scale(&bounds, &eqs->syms[sym_eq->sym[one_use]], -sym_eq->coef[one_use]);
		refine_sym(env, eqs, diff, bounds, 1);
		eqs->sym_equations[pos.next - 1].insn_idx = -1;
		return true;
	}
	return false;
}

/*
 * No xreg holds the sym at @pos of @def_equation any more. Eliminate it from the equations:
 *	p' = sym0 + len, sym0 = 8 * trip + sym1	->	p' = 8 * trip + sym2, sym2 is sym1 + len
 */
static bool eliminate_sym(struct bpf_verifier_env *env, struct bpf_equations *eqs,
			  struct bpf_sym_equation *def_equation, int pos)
{
	struct sym_scratch *scratch = env->eq_env->scratch;
	int one_use = find_one_use_sym(scratch, def_equation), i, j, k;
	struct bpf_sym_equation *sym_eq, def = *def_equation;
	struct scalar bounds, rest, *s;
	bool spare = def.insn_idx < 0;
	u32 one_use_sym;
	s64 factor;

	if (one_use < 0 || one_use == pos || !is_plus_minus_one(def.coef[pos]))
		return false;
	def_equation->sym[0] = NO_SYM;
	rest = eqs->syms[def.sym[one_use]];
	for_each_sum(env, eqs, sym_eq) {
		i = find_sym_pos(sym_eq, def.sym[pos]);
		if (i == 3 || sym_eq == def_equation)
			continue;
		j = find_one_use_sym(scratch, sym_eq);
		for (k = 0; k < 3 && j < 0 && spare; k++)
			if (k != i && sym_eq->coef[k] && !scratch[sym_eq->sym[k]].determined)
				j = k;
		if (j < 0)
			continue;
		bpf_add_cost(env, 4, BPF_COST_XREG);
		factor = -sym_eq->coef[i] * def.coef[pos];
		scalar_scale(&bounds, &eqs->syms[sym_eq->sym[j]], sym_eq->coef[j]);
		/* no xreg gives the value of that sym. The sym of @def takes its place. */
		if (!sym_has_one_use(scratch, sym_eq->sym[j])) {
			sym_eq->sym[j] = def.sym[one_use];
			spare = false;
		}
		s = &eqs->syms[sym_eq->sym[j]];
		scalar_add_scaled(s, &bounds, &rest, factor * def.coef[one_use]);
		scalar_bounds_sync(s);
		sym_eq->coef[j] = 1;
		sym_eq->coef[i] = factor * def.coef[3 - pos - one_use];
		sym_eq->sym[i] = def.sym[3 - pos - one_use];
		sym_eq->off += factor * def.off;
		sym_eq->insn_idx = -1;
		/* a sym with one use is the last choice for the left side */
		swap(sym_eq->coef[j], sym_eq->coef[2]);
		swap(sym_eq->sym[j], sym_eq->sym[2]);
		one_use_sym = sym_eq->sym[2];
		if (!isolate_sym(sym_eq) ||
		    refine_same_sum(env, eqs, sym_eq, find_sym_pos(sym_eq, one_use_sym)))
			sym_eq->sym[0] = NO_SYM;
	}
	return true;
}

/* No xreg holds @sym, no jump tested it. An op made it of the syms of @sum: w1 += 1; w1 += 1; */
static bool only_op_is_left(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			    const struct bpf_sym_equation *sum, u32 sym)
{
	const struct sym_scratch *scratch = &env->eq_env->scratch[sym];
	const struct bpf_sym_equation *op = scratch->op;
	struct scalar bounds;

	return op && scratch->use_cnt == 2 && (!op->coef[1] || find_sym_pos(sum, op->sym[1]) < 3) &&
	       (!op->coef[2] || find_sym_pos(sum, op->sym[2]) < 3) &&
	       run_op(env, st, op, &bounds) && scalar_subsumes(&st->equations.syms[sym], &bounds);
}

static bool equation_is_useless(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				const struct bpf_sym_equation *sym_eq)
{
	const struct sym_scratch *scratch = env->eq_env->scratch;
	int i, sym_cnt = 0, one_use_cnt = 0;

	if (is_op(sym_eq))
		return sym_has_one_use(scratch, sym_eq->sym[0]) ||
		       (!sym_eq->coef[1] && !sym_eq->coef[2]);
	for (i = 0; i < 3; i++) {
		sym_cnt += sym_eq->coef[i] && !only_op_is_left(env, st, sym_eq, sym_eq->sym[i]);
		if (!sym_has_one_use(scratch, sym_eq->sym[i]))
			continue;
		one_use_cnt++;
		if ((sym_eq->coef[i] & 1) && scalar_is_unknown(&st->equations.syms[sym_eq->sym[i]]))
			return true;
	}
	return one_use_cnt >= sym_cnt - 1;
}

static void forget_useless_equations(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_equations *eqs = &st->equations;
	struct sym_scratch *scratch = env->eq_env->scratch;
	struct bpf_xreg_equation *xreg_eq, *next;
	struct bpf_sym_equation *sym_eq;
	bool more;
	int i;

	do {
		more = false;
		for_each_sym_equation(env, eqs, sym_eq) {
			if (sym_eq->sym[0] == NO_SYM || !equation_is_useless(env, st, sym_eq))
				continue;
			for (i = 0; i < 3; i++)
				more |= sym_eq->coef[i] && --scratch[sym_eq->sym[i]].use_cnt == 1;
			sym_eq->sym[0] = NO_SYM;
		}
	} while (more && !over_limit(env));
	forget_sym_equations(env, eqs, S32_MIN);
	next = eqs->xreg_equations;
	for_each_xreg_equation(env, eqs, xreg_eq) {
		if (xreg_eq->coef && !sym_has_one_use(scratch, xreg_eq->sym))
			*next++ = *xreg_eq;
		else if (xreg_eq->coef)
			scratch[xreg_eq->sym].use_cnt = 0;
	}
	eqs->xreg_equation_cnt = next - eqs->xreg_equations;
}

/* The sym that @sym_eq determines. 3: all are determined. -1: more than one is not. */
static int find_undetermined_sym(const struct sym_scratch *scratch,
				 const struct bpf_sym_equation *sym_eq)
{
	int i, pos = 3;

	for (i = 0; i < 3; i++) {
		if (!sym_eq->coef[i] || scratch[sym_eq->sym[i]].determined)
			continue;
		if (pos < 3 || (i && is_op(sym_eq)))
			return -1;
		pos = i;
	}
	return pos;
}

/* Only an op tells a sym of @sym_eq */
static bool leans_on_op(const struct sym_scratch *scratch, const struct bpf_sym_equation *sym_eq)
{
	int i;

	for (i = 0; i < 3; i++)
		if (sym_eq->coef[i] && scratch[sym_eq->sym[i]].by_op)
			return true;
	return is_op(sym_eq);
}

/* Delete what says nothing. Put the rest in the order that check_equations() needs. */
static void normalize_equations(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct sym_scratch *scratch = env->eq_env->scratch;
	struct bpf_equations *eqs = &st->equations;
	struct bpf_xreg_equation *xreg_eq;
	struct bpf_sym_equation *sym_eq, *done, *sweep_start, *end;
	bool substituted = false;
	struct expr expr;
	u32 i, cnt;
	int pos;

	if (eqs->normalized)
		return;
	for (i = 0; i < eqs->sym_cnt; i++) {
		expr = make_expr(0, 0, eqs->syms[i].var_off.value);
		if (tnum_is_const(eqs->syms[i].var_off))
			substituted |= substitute_sym(env, eqs, i, &expr, NULL);
	}
	/* see read_from_truncation() */
	for_each_sym_equation(env, eqs, sym_eq)
		if (is_op(sym_eq) && bits_read(env, sym_eq) < 32)
			op_skips_truncations(env, eqs, sym_eq);
again:
	if (over_limit(env))
		eqs->xreg_equation_cnt = eqs->sym_equation_cnt = 0;
	forget_sym_equations(env, eqs, S32_MIN);
	count_sym_uses(env, eqs);
	for_each_sum(env, eqs, sym_eq) {
		if (sym_eq->coef[2] || sym_eq->sym[0] == NO_SYM)
			continue;
		refine_syms_by_equation(env, st, sym_eq, 0);
		expr = rhs_expr(sym_eq, 0);
		/* sym0 = 2 * sym1, the only use of sym1: it shows only the low bits of sym0 */
		if (!is_plus_minus_one(expr.coef) && sym_has_one_use(scratch, sym_eq->sym[1]))
			continue;
		substitute_sym(env, eqs, sym_eq->sym[0], &expr, sym_eq);
		substituted = true;
	}
	if (substituted) {
		forget_sym_equations(env, eqs, S32_MIN);
		count_sym_uses(env, eqs);
		/* two sums can be the same now. What an insn made keeps its form. */
		for_each_sum(env, eqs, sym_eq) {
			pos = find_one_use_sym(scratch, sym_eq);
			if (pos >= 0 && sym_eq->insn_idx < 0 &&
			    refine_same_sum(env, eqs, sym_eq, pos))
				sym_eq->sym[0] = NO_SYM;
		}
		forget_sym_equations(env, eqs, S32_MIN);
		count_sym_uses(env, eqs);
		substituted = false;
	}
	forget_useless_equations(env, st);

	for_each_xreg_equation(env, eqs, xreg_eq)
		scratch[xreg_eq->sym].determined = true;
	/* The equations near the xregs go first. Cut a long chain: x += k; x += k; ... */
	done = eqs->sym_equations;
	end = eqs->sym_equations +
	      min(eqs->sym_equation_cnt, 2 * SUMS_PER_XREG * eqs->xreg_equation_cnt);
	do {
		bpf_add_cost(env, eqs->sym_equation_cnt - (done - eqs->sym_equations),
			     BPF_COST_COPY);
		sweep_start = done;
		for (sym_eq = done;
		     sym_eq < eqs->sym_equations + eqs->sym_equation_cnt && done < end; sym_eq++) {
			pos = find_undetermined_sym(scratch, sym_eq);
			/* sum += i & 1: go around the old sum, see eliminate_sym() */
			if (pos < 0 || (pos % 3 && sym_eq->insn_idx >= 0 &&
					!sym_has_one_use(scratch, sym_eq->sym[pos]) &&
					leans_on_op(scratch, sym_eq)))
				continue;
			if (sym_eq != done)
				swap(*sym_eq, *done);
			done++;
		}
		for (sym_eq = sweep_start; sym_eq < done; sym_eq++) {
			pos = find_undetermined_sym(scratch, sym_eq);
			if (pos == 3)
				continue;
			scratch[sym_eq->sym[pos]].by_op = leans_on_op(scratch, sym_eq);
			scratch[sym_eq->sym[pos]].determined = true;
		}
	} while (sweep_start < done && done < end && !over_limit(env));
	/* Nothing refines the operands of the other ops. The other sums need a sym with one use. */
	for (sym_eq = done; sym_eq < eqs->sym_equations + eqs->sym_equation_cnt; sym_eq++)
		for (i = 0; i < 3 && !is_op(sym_eq) && find_one_use_sym(scratch, sym_eq) < 0; i++)
			if (sym_eq->coef[i])
				scratch[sym_eq->sym[i]].new_symno = scratch[sym_eq->sym[i]].by_op;
	cnt = 0;
	for_each_sym_equation(env, eqs, sym_eq) {
		if (!is_op(sym_eq) || (sym_eq < done && !scratch[sym_eq->sym[0]].new_symno))
			continue;
		sym_eq->sym[0] = NO_SYM;
		cnt++;
	}
	if (cnt)
		goto again;
	/* the equations that are left lead through unknown syms. The last insn goes first. */
	for (cnt = 0; cnt < 2 && done < end; cnt++)
		for (sym_eq = eqs->sym_equations + eqs->sym_equation_cnt; sym_eq-- > done;)
			for (i = 0; i < 3 && (cnt || sym_eq->insn_idx >= 0); i++)
				if (sym_eq->coef[i] &&
				    !scratch[sym_eq->sym[i]].determined &&
				    eliminate_sym(env, eqs, sym_eq, i))
					goto again;
	if (done != eqs->sym_equations + eqs->sym_equation_cnt) {
		eqs->sym_equation_cnt = done - eqs->sym_equations;
		goto again;
	}

	eqs->normalized = true;
	for (i = 0, cnt = 0; i < eqs->sym_cnt; i++) {
		scratch[i].refined_sweep = 0;
		if (!scratch[i].use_cnt)
			continue;
		if (cnt != i)
			eqs->syms[cnt] = eqs->syms[i];
		scratch[i].new_symno = cnt++;
	}
	if (cnt == eqs->sym_cnt)
		return;
	eqs->sym_cnt = cnt;
	for_each_xreg_equation(env, eqs, xreg_eq)
		xreg_eq->sym = scratch[xreg_eq->sym].new_symno;
	for_each_sym_equation(env, eqs, sym_eq)
		for (i = 0; i < 3; i++)
			if (sym_eq->coef[i])
				sym_eq->sym[i] = scratch[sym_eq->sym[i]].new_symno;
}

/* Dead xregs are cleared */
void bpf_equations_clean(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	struct bpf_xreg_equation *xreg_eq, *next = st->equations.xreg_equations;
	struct bpf_equations *eqs = &st->equations;
	const struct scalar *s;

	if (!env->eq_env)
		return;
	if (st->speculative)
		eqs->xreg_equation_cnt = 0;
	for_each_xreg_equation(env, eqs, xreg_eq) {
		s = equation_xreg_bounds(env, st, xreg_eq);
		if (s && !tnum_is_const(s->var_off)) {
			*next++ = *xreg_eq;
			continue;
		}
		refine_sym_from_xreg(env, st, xreg_eq);
		env->eq_env->scratch[xreg_eq->sym].refined_sweep = 0;
	}
	eqs->normalized &= next == xreg_eq;
	eqs->xreg_equation_cnt = next - eqs->xreg_equations;
	if (!eqs->xreg_equation_cnt)
		eqs->sym_equation_cnt = eqs->sym_cnt = 0;
	normalize_equations(env, st);
	eqs->clean_sym_cnt = eqs->sym_cnt;
}

/* Subsume */

/* Translate @expr to the other state */
static bool match_expr(const struct sym_scratch *scratch, struct expr *expr)
{
	if (!expr->coef)
		return true;
	scratch += var_symno(expr->var);
	*expr = expr_scale(scratch->cur_expr, expr->coef, expr->off);
	return scratch->determined;
}

/* @sym of @old is @expr in @cur */
static bool match_sym(struct bpf_verifier_env *env, const struct bpf_equations *old,
		      const struct bpf_verifier_state *cur, u32 sym, const struct expr *expr)
{
	struct sym_scratch *scratch = &env->eq_env->scratch[sym];
	struct scalar bounds;
	struct expr diff;
	struct equation_pos pos = {};

	while (scratch->determined &&
	       bpf_find_next_diff(env, &cur->equations, &scratch->cur_expr, expr, &pos, &diff))
		if (!diff.coef && !diff.off)
			return true;
	if (scratch->determined)
		return false;
	bpf_eval_expr(env, cur, expr, &bounds);
	scratch->determined = scalar_subsumes(&old->syms[sym], &bounds);
	scratch->cur_expr = *expr;
	return scratch->determined;
}

/* @hint: after the equation of @cur that was found last. Most are in the same order. */
static bool check_sym_equation(struct bpf_verifier_env *env, const struct bpf_equations *old,
			       const struct bpf_verifier_state *cur,
			       const struct bpf_sym_equation *sym_eq, u32 *hint)
{
	const struct sym_scratch *scratch = env->eq_env->scratch;
	struct equation_pos pos = { .next = *hint };
	struct expr expr[2], diff;
	struct scalar bounds;
	int i, unmatched;

	if (is_op(sym_eq)) {
		expr[0] = rhs_expr(sym_eq, 0);
		expr[1] = rhs_expr(sym_eq, 1);
		return match_expr(scratch, &expr[0]) && match_expr(scratch, &expr[1]) &&
		       bpf_find_op(env, &cur->equations, sym_eq->insn_idx, expr, &diff) &&
		       match_sym(env, old, cur, sym_eq->sym[0], &diff);
	}
	/* -coef[unmatched] * sym[unmatched] = expr[0] - expr[1] */
	for (unmatched = 0; unmatched < 2 && scratch[sym_eq->sym[unmatched]].determined;
	     unmatched++)
		;
	for (i = 0; i < 2; i++) {
		expr[i] = sym_expr(sym_eq->coef[i + (i >= unmatched)] * (i ? -1 : 1),
				   sym_eq->sym[i + (i >= unmatched)], i ? 0 : sym_eq->off);
		if (!match_expr(scratch, &expr[i]))
			return false;
	}
	while (bpf_find_next_diff(env, &cur->equations, &expr[0], &expr[1], &pos, &diff)) {
		if (!sym_eq->coef[unmatched] ? !diff.coef && !diff.off :
		    bpf_expr_div_exact(&diff, 0, -sym_eq->coef[unmatched]) &&
		    match_sym(env, old, cur, sym_eq->sym[unmatched], &diff)) {
			*hint = pos.next;
			return true;
		}
	}
	/* no other equation uses it */
	if (!sym_has_one_use(scratch, sym_eq->sym[unmatched]) ||
	    !is_plus_minus_one(sym_eq->coef[unmatched]))
		return false;
	bpf_eval_diff(env, cur, &expr[sym_eq->coef[unmatched] > 0],
		      &expr[sym_eq->coef[unmatched] < 0], &bounds);
	return scalar_subsumes(&old->syms[sym_eq->sym[unmatched]], &bounds);
}

/*
 * Are there values for the syms of @old for which its equations hold in @cur?
 * @forget: it is @old. Mark the equations that do not hold, normalize_equations() deletes them.
 */
static bool check_equations(struct bpf_verifier_env *env, const struct bpf_equations *old,
			    const struct bpf_verifier_state *cur, struct bpf_equations *forget)
{
	struct bpf_xreg_equation *xreg_eq;
	struct bpf_sym_equation *sym_eq;
	bool is_ptr, ok = true;
	struct expr expr;
	u32 hint = 0;

	count_sym_uses(env, old);
	for_each_xreg_equation(env, old, xreg_eq) {
		if (bpf_xreg_expr(env, cur, xreg_eq->xreg, &expr, &is_ptr) &&
		    is_ptr == xreg_eq->is_ptr &&
		    bpf_expr_div_exact(&expr, xreg_eq->off, xreg_eq->coef) &&
		    match_sym(env, old, cur, xreg_eq->sym, &expr))
			continue;
		if (!forget)
			return false;
		xreg_eq->coef = 0;
		forget->normalized = ok = false;
	}
	for_each_sym_equation(env, old, sym_eq) {
		/* it depends on an equation that does not hold */
		if (!ok && find_undetermined_sym(env->eq_env->scratch, sym_eq) < 0)
			continue;
		if (check_sym_equation(env, old, cur, sym_eq, &hint))
			continue;
		if (!forget)
			return false;
		sym_eq->sym[0] = NO_SYM;
		forget->normalized = ok = false;
	}
	return ok;
}

bool bpf_equations_subsume(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
			   const struct bpf_verifier_state *cur)
{
	const struct bpf_xreg_equation *xreg_eq;
	const struct scalar *s;

	/* @old ends after the next jump. The equations that showed it can be gone. */
	if (old->equations.infeasible && !cur->equations.infeasible && env->bypass_spec_v1)
		return false;
	/* see loop_stack_safe() */
	for_each_xreg_equation(env, &old->equations, xreg_eq) {
		if ((u32)xreg_eq->xreg < BPF_XREG_TRIP)
			continue;
		s = equation_xreg_bounds(env, cur, xreg_eq);
		if (!s || !scalar_subsumes(equation_xreg_bounds(env, old, xreg_eq), s))
			return false;
	}
	return !old->equations.xreg_equation_cnt ||
	       check_equations(env, &old->equations, cur, NULL);
}

/* Join */

/*
 * Make the equations of @dst hold for @src too. Call it before the xregs are joined.
 * @leftover_loop: the states are at its header. @widen: @src came around it.
 */
void bpf_equations_pre_join(struct bpf_verifier_env *env, struct bpf_verifier_state *dst,
			    const struct bpf_verifier_state *src, struct bpf_loop *leftover_loop,
			    bool widen)
{
	const struct loop_stack_entry *top = bpf_top_loop(src->frame[src->curframe]);
	bool enters = leftover_loop && top &&
		      top->trip < bpf_top_loop(dst->frame[dst->curframe])->trip;
	struct bpf_equations *eqs;

	if (env->eq_env) {
		eqs = &env->eq_env->join_state.equations;
		/* what enters the loop can break the equations that keep the xregs small */
		if (enters && dst->equations.needs_refine)
			bpf_equations_refine_all(env, dst);
		normalize_equations(env, &env->eq_env->join_state);
		while (!check_equations(env, eqs, dst, eqs) || !check_equations(env, eqs, src, eqs))
			normalize_equations(env, &env->eq_env->join_state);
		eqs->needs_refine = widen || dst->equations.needs_refine ||
				    src->equations.needs_refine;
		swap(dst->equations, *eqs);
	}
}

/* The xregs of @dst are joined. Some of them are gone. */
void bpf_equations_post_join(struct bpf_verifier_env *env, struct bpf_verifier_state *dst,
			     const struct bpf_verifier_state *src)
{
	u32 cnt = dst->equations.xreg_equation_cnt;

	bpf_equations_clean(env, dst);
	while (cnt != dst->equations.xreg_equation_cnt &&
	       !check_equations(env, &dst->equations, src, &dst->equations))
		normalize_equations(env, dst);
	dst->equations.infeasible = false;
}

static void print_operand(struct bpf_verifier_log *log, const char *prefix, struct expr expr)
{
	if (expr.coef)
		bpf_log(log, "%s%lld*sym%u%+lld", prefix, expr.coef, var_symno(expr.var), expr.off);
	else
		bpf_log(log, "%s%lld", prefix, expr.off);
}

static void print_sym_equation(struct bpf_verifier_log *log, const struct bpf_sym_equation *sym_eq)
{
	bpf_log(log, " sym%u=", sym_eq->sym[0]);
	if (is_op(sym_eq)) {
		bpf_log(log, "insn%d", sym_eq->insn_idx);
		print_operand(log, "(", rhs_expr(sym_eq, 0));
		print_operand(log, ",", rhs_expr(sym_eq, 1));
		bpf_log(log, ")");
		return;
	}
	bpf_log(log, "%lld*sym%u", sym_eq->coef[1], sym_eq->sym[1]);
	if (sym_eq->coef[2])
		bpf_log(log, "%+lld*sym%u", sym_eq->coef[2], sym_eq->sym[2]);
	bpf_log(log, "%+lld", sym_eq->off);
}

void bpf_equations_print(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	const struct bpf_equations *eqs = &st->equations;
	struct bpf_verifier_log *log = &env->log;
	const struct bpf_xreg_equation *xreg_eq;
	const struct bpf_sym_equation *sym_eq;
	u32 i, xregno;

	for (xreg_eq = eqs->xreg_equations;
	     xreg_eq < eqs->xreg_equations + eqs->xreg_equation_cnt;
	     xreg_eq++) {
		xregno = xreg_eq->xreg;
		bpf_log(log,
			xregno < MAX_BPF_REG ? " %llu:r%d" : xregno < BPF_XREG_TRIP ? " %llu:fp%d" :
			" %llu:trip%d", xreg_eq->xreg >> 32, xregno < MAX_BPF_REG ? xregno :
			xregno < BPF_XREG_TRIP ? (MAX_BPF_EXT_REG - xregno - 1) * BPF_REG_SIZE :
			xregno - BPF_XREG_TRIP);
		bpf_log(log, "=%lld*sym%u%+lld", xreg_eq->coef, xreg_eq->sym, xreg_eq->off);
	}
	for (sym_eq = eqs->sym_equations;
	     sym_eq < eqs->sym_equations + eqs->sym_equation_cnt; sym_eq++)
		print_sym_equation(log, sym_eq);
	for (i = 0; i < eqs->sym_cnt; i++)
		bpf_log(log, " sym%u=[%lld,+%llu]", i, eqs->syms[i].r64.base,
			eqs->syms[i].r64.size);
}

int bpf_equation_env_init(struct bpf_verifier_env *env)
{
	if (!env->bpf_capable)
		return 0;
	env->eq_env = kvzalloc_obj(*env->eq_env, BPF_VERIFIER_GFP);
	return env->eq_env ? 0 : -ENOMEM;
}

void bpf_equation_env_free(struct bpf_verifier_env *env)
{
	if (!env->eq_env)
		return;
	kvfree(env->eq_env->scratch);
	kvfree(env->eq_env->use_links);
	kvfree(env->eq_env->phis);
	kvfree(env->eq_env->phi_index);
	bpf_equations_free(&env->eq_env->join_state.equations);
	kvfree(env->eq_env);
}
