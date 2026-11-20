// SPDX-License-Identifier: GPL-2.0-only
/*
 * The equations of a join and the thresholds of a trip index.
 *
 * A phi is a sym of the join. It has one value in each state:
 *
 *              trip   r1         r2             r3
 *  old state   0      0          p              0..9
 *  new state   1      4          p + 8          1..9
 *  join        sym0   4 * sym0   p + 8 * sym0   sym1 = sym0 + sym2, sym2 is 0..9
 */
#include <linux/bpf.h>
#include <linux/cnum.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/tnum.h>
#include "equation.h"

/* The values of a sym of the join in the two states */
struct join_phi {
	struct expr arg[2];
	u32 next_phi;	/* see phi_list() */
	bool in_sym_equation;
};

/* Only the range is known */
static const struct expr no_expr = { 1, 0, VAR_NONE };

struct equation_join {
	struct bpf_verifier_env *env;
	const struct bpf_verifier_state *st[2];
	struct bpf_equations *eqs;
	const struct bpf_loop *leftover_loop;
	bool widen;
	/* the sym that is 0 in the old state and 1 in the new state */
	u64 selector;
	/* by the sym of a state. 0: none, else the sym of the join + 1 */
	u32 *sym2phi[2], *phi_lists;
	/* after the equation that was found last in the two states and in the join */
	u32 hint[3];
	u32 sums;
};

enum iv_threshold_kind {
	THRESHOLD_EXIT_JUMP,	/* of the trip index, by a jump that leaves the loop */
	THRESHOLD_BODY_JUMP,	/* by another jump: the next trip can test its result */
	THRESHOLD_SYM,		/* of a number that moves with it */
	THRESHOLD_DIFF,		/* of the difference of two numbers */
};

struct bpf_iv_threshold {
	s64 value;
	enum iv_threshold_kind kind;
	/* the jump that gave it, and its index among the thresholds of that jump */
	u32 insn_idx, idx;
};

#define for_each_iv_threshold(env, loop, threshold, k)					\
	for (bpf_add_cost(env, (loop)->iv_threshold_cnt, BPF_COST_SCAN),		\
	     threshold = (loop)->iv_thresholds;						\
	     threshold < (loop)->iv_thresholds + (loop)->iv_threshold_cnt; threshold++)	\
		if (threshold->kind == (k))

static const struct expr *phi_args(const struct equation_join *j, u64 var)
{
	return j->env->eq_env->phis[var_symno(var)].arg;
}

static bool phi_has_exprs(const struct expr *arg)
{
	return !expr_equal(&arg[0], &no_expr) && !expr_equal(&arg[1], &no_expr);
}

/* The list of phis that are made of the vars in @arg. NULL if there can be only one. */
static u32 *phi_list(const struct equation_join *j, const struct expr *arg)
{
	int i = !arg[0].coef;

	if (!arg[i].coef)
		return j->phi_lists;
	return !var_is_sym(arg[i].var) ? NULL :
	       j->phi_lists + 1 + i * j->st[0]->equations.sym_cnt + var_symno(arg[i].var);
}

/*
 * The low 32 bits go around their own circle to the next threshold:
 *	int i = -5; do { ... } while (++i != 3);	i is 0xfffffffb..0xffffffff, 0..2
 */
static void widen_low32(struct equation_join *j, struct scalar *widened,
			const struct scalar *joined, const struct scalar *old,
			enum iv_threshold_kind kind)
{
	u32 start = joined->r32.base, end = start + joined->r32.size;
	u64 up = end == old->r32.base + old->r32.size ? 0 : U32_MAX;
	u64 down = start == old->r32.base ? 0 : U32_MAX;
	const struct bpf_iv_threshold *threshold;

	if (!up && !down)
		widened->var_off = tnum_with_subreg(widened->var_off, joined->var_off);
	for_each_iv_threshold(j->env, j->leftover_loop, threshold, kind) {
		up = min_t(u64, up, (u32)(threshold->value - end));
		down = min_t(u64, down, (u32)(start - threshold->value));
	}
	if (joined->r32.size + up + down < U32_MAX)
		cnum32_intersect_with(&widened->r32, (struct cnum32){ start - down,
								      joined->r32.size +
								      up + down });
}

static u64 new_phi(struct equation_join *j, const struct expr *arg, const struct scalar *bounds,
		   enum iv_threshold_kind kind)
{
	struct bpf_equation_env *eq_env = j->env->eq_env;
	struct scalar joined = bounds[0], widened;
	s64 min = S64_MIN, max = S64_MAX;
	const struct bpf_iv_threshold *threshold;
	bool is_ptr, grew_before, grows;
	u32 *list;
	u64 var;
	int i;

	bpf_add_cost(j->env, 1, BPF_COST_INSN);
	scalar_union(&joined, &bounds[1]);
	grows = j->leftover_loop && !scalar_equal(&joined, &bounds[0]);
	grew_before = arg[0].var != VAR_NONE &&
		      bpf_find_var_bounds(j->env, j->st[0], arg[0].var, &is_ptr)->grew_once;
	if (grows && j->widen && grew_before) {
		widened = joined;
		for_each_iv_threshold(j->env, j->leftover_loop, threshold, kind) {
			if (threshold->value >= cnum64_smax(joined.r64))
				max = min(max, threshold->value);
			if (threshold->value <= cnum64_smin(joined.r64))
				min = max(min, threshold->value);
		}
		if (kind == THRESHOLD_SYM) {
			scalar_widen(&widened, &bounds[0], min, max);
		} else {
			if (cnum64_smin(joined.r64) >= cnum64_smin(bounds[0].r64))
				min = cnum64_smin(joined.r64);
			if (cnum64_smax(joined.r64) <= cnum64_smax(bounds[0].r64))
				max = cnum64_smax(joined.r64);
			scalar_set_unknown(&widened);
			widened.r64 = cnum64_union(cnum64_from_srange(min, max), joined.r64);
		}
		widen_low32(j, &widened, &joined, &bounds[0], kind);
		/* the step changes only to a divisor. A number that can wrap has no step. */
		if (cnum64_smin(widened.r64) != S64_MIN && cnum64_smax(widened.r64) != S64_MAX) {
			widened.step = joined.step;
			widened.base = joined.base;
		}
		joined = widened;
	}
	if (!bpf_grow_array(j->env, &eq_env->phis, &eq_env->phi_cap,
			    j->eqs->sym_cnt + 1, sizeof(*eq_env->phis)))
		return VAR_NONE;
	var = bpf_new_sym(j->env, j->eqs, &joined);
	if (!var_is_sym(var))
		return var;
	j->eqs->syms[var_symno(var)].grew_once = grew_before || grows;
	for (i = 0; i < 2; i++) {
		eq_env->phis[var_symno(var)].arg[i] = arg[i];
		if (arg[i].coef == 1 && var_is_sym(arg[i].var) &&
		    !j->sym2phi[i][var_symno(arg[i].var)])
			j->sym2phi[i][var_symno(arg[i].var)] = var_symno(var) + 1;
	}
	eq_env->phis[var_symno(var)].next_phi = 0;
	eq_env->phis[var_symno(var)].in_sym_equation = false;
	list = phi_has_exprs(arg) ? phi_list(j, arg) : NULL;
	for (; list && *list; list = &eq_env->phis[*list - 1].next_phi)
		bpf_add_cost(j->env, 1, BPF_COST_SCAN);
	if (list)
		*list = var_symno(var) + 1;
	if (!arg[0].coef && !arg[1].coef)
		j->selector = var;
	return var;
}

/* The expr that is @expr[0] in the old state and @expr[1] in the new state */
static struct expr join_expr(struct equation_join *j, const struct expr *expr,
			     enum iv_threshold_kind kind)
{
	struct expr arg[2], res;
	struct scalar bounds[2];
	const struct expr *phi_arg;
	u32 symno, i, *list;

	if (!expr[0].coef && expr_equal(&expr[0], &expr[1]))
		return expr[0];
	/* the cpu can speculate past the test of one number that only goes with another one */
	if ((!expr[0].coef || !expr[1].coef) && !j->env->bypass_spec_v1)
		return no_expr;
	for (list = phi_list(j, expr); list && *list;
	     list = &j->env->eq_env->phis[symno].next_phi) {
		symno = *list - 1;
		phi_arg = phi_args(j, symno);
		bpf_add_cost(j->env, 1, BPF_COST_COPY);
		if (phi_arg[0].var != expr[0].var || phi_arg[1].var != expr[1].var)
			continue;
		bpf_add_cost(j->env, 1, BPF_COST_XREG);
		i = !phi_arg[0].coef;
		res = make_expr(0, 0, phi_arg[i].coef ? expr[i].coef : expr[1].off - expr[0].off);
		if (phi_arg[i].coef && !bpf_expr_div_exact(&res, 0, phi_arg[i].coef))
			continue;
		res = make_expr(res.off, VAR_SYM | symno, expr[0].off - res.off * phi_arg[0].off);
		arg[0] = expr_scale(phi_arg[0], res.coef, res.off);
		arg[1] = expr_scale(phi_arg[1], res.coef, res.off);
		if (expr_equal(&arg[0], &expr[0]) && expr_equal(&arg[1], &expr[1]))
			return res;
	}
	res.coef = expr[0].coef ?: expr[1].coef ?: expr[1].off - expr[0].off;
	res.off = expr[0].coef || !expr[1].coef ? expr[0].off : expr[1].off;
	arg[0] = expr[0];
	arg[1] = expr[1];
	if (!bpf_expr_div_exact(&arg[0], res.off, res.coef) ||
	    !bpf_expr_div_exact(&arg[1], res.off, res.coef)) {
		res = make_expr(1, VAR_NONE, 0);
		arg[0] = expr[0];
	}
	bpf_eval_expr(j->env, j->st[0], &arg[0], &bounds[0]);
	bpf_eval_expr(j->env, j->st[1], &arg[1], &bounds[1]);
	res.var = new_phi(j, arg, bounds, kind);
	return res;
}

static void join_xreg(struct equation_join *j, u64 xreg)
{
	struct expr expr[2];
	bool is_ptr[2];

	if (over_limit(j->env) || bpf_find_xreg_equation(j->eqs, xreg) ||
	    !bpf_xreg_expr(j->env, j->st[0], xreg, &expr[0], &is_ptr[0]) ||
	    !bpf_xreg_expr(j->env, j->st[1], xreg, &expr[1], &is_ptr[1]) || is_ptr[0] != is_ptr[1])
		return;
	expr[0] = join_expr(j, expr,
			    (u32)xreg < BPF_XREG_TRIP ? THRESHOLD_SYM : THRESHOLD_EXIT_JUMP);
	bpf_set_xreg_equation(j->env, j->eqs, xreg, &expr[0], is_ptr[0]);
}

static bool scalars_are_disjoint(const struct scalar *a, const struct scalar *b)
{
	return cnum64_is_empty(cnum64_intersect(a->r64, b->r64)) ||
	       cnum32_is_empty(cnum32_intersect(a->r32, b->r32));
}

/* The xregs that have no equation. @all: what a trip changes. */
static void join_other_xregs(struct equation_join *j, bool all)
{
	const struct scalar *a, *b;
	u32 fr, xregno, cnt;
	bool is_ptr;

	for (fr = 0; fr <= j->st[0]->curframe; fr++) {
		cnt = bpf_spi_to_xreg(bpf_stack_nr_slots(j->st[0]->frame[fr]));
		bpf_add_cost(j->env, cnt, BPF_COST_XREG);
		for (xregno = 0; xregno < cnt; xregno++) {
			a = bpf_find_var_bounds(j->env, j->st[0], bpf_xreg(fr, xregno), &is_ptr);
			b = a ? bpf_find_var_bounds(j->env, j->st[1], bpf_xreg(fr, xregno),
						    &is_ptr) : NULL;
			if (b && !scalar_equal(a, b) && (all || scalars_are_disjoint(a, b)))
				join_xreg(j, bpf_xreg(fr, xregno));
		}
	}
}

/* Most equations are in the same order in all tables */
static bool find_diff(struct equation_join *j, int i, const struct expr *a, const struct expr *b,
		      struct expr *diff)
{
	struct equation_pos pos = { .next = j->hint[i] };

	if (!bpf_find_next_diff(j->env, i < 2 ? &j->st[i]->equations : j->eqs, a, b, &pos, diff))
		return false;
	j->hint[i] = pos.next;
	return true;
}

static void join_add_sym_equation(struct equation_join *j, struct bpf_sym_equation sym_eq)
{
	int i;

	for (i = 0; i < 3; i++)
		if (sym_eq.coef[i] && sym_eq.sym[i] != NO_SYM)
			j->env->eq_env->phis[sym_eq.sym[i]].in_sym_equation = true;
	j->sums += bpf_add_sym_equation(j->env, j->eqs, sym_eq);
}

/* An equation for @a - @b. True if it needs no new sym. @needs_expr: a range is not enough. */
static bool join_diff(struct equation_join *j, struct expr a, struct expr b, bool needs_expr)
{
	struct join_phi *phis = j->env->eq_env->phis;
	u32 sym_cnt = j->eqs->sym_cnt;
	struct expr expr[2], x, y, res;
	struct scalar bounds[2];
	int i;

	if (!a.coef || !b.coef || a.var == b.var || over_limit(j->env))
		return true;
	if (phis[var_symno(a.var)].in_sym_equation && phis[var_symno(b.var)].in_sym_equation &&
	    find_diff(j, 2, &a, &b, &res))
		return true;
	if (!phi_has_exprs(phi_args(j, a.var)) || !phi_has_exprs(phi_args(j, b.var)))
		return false;
	for (i = 0; i < 2; i++) {
		x = expr_scale(phi_args(j, a.var)[i], a.coef, 0);
		y = expr_scale(phi_args(j, b.var)[i], b.coef, 0);
		if (find_diff(j, i, &x, &y, &expr[i]))
			continue;
		if (needs_expr || !j->env->bypass_spec_v1 || (i && expr_equal(&expr[0], &no_expr)))
			return false;
		bpf_eval_diff(j->env, j->st[i], &x, &y, &bounds[i]);
		expr[i] = no_expr;
	}
	i = expr_equal(&expr[0], &no_expr);
	if (!phi_has_exprs(expr))
		bpf_eval_expr(j->env, j->st[i], &expr[i], &bounds[i]);
	res = phi_has_exprs(expr) ? join_expr(j, expr, THRESHOLD_DIFF) :
				    make_expr(1, new_phi(j, expr, bounds, THRESHOLD_DIFF), 0);
	if (res.coef && !var_is_sym(res.var))
		return false;
	join_add_sym_equation(j, (struct bpf_sym_equation){
		{ a.coef, -b.coef, -res.coef },
		{ a.var, b.var, res.var },
		-1, -res.off });
	return sym_cnt == j->eqs->sym_cnt;
}

/* Translate @expr from state @input to the join */
static bool translate_expr(struct equation_join *j, int input, struct expr *expr)
{
	u32 symno;

	if (!expr->coef)
		return true;
	symno = j->sym2phi[input][var_symno(expr->var)];
	if (!symno--)
		return false;
	*expr = make_expr(expr->coef, VAR_SYM | symno,
			  expr->off - expr->coef * phi_args(j, symno)[input].off);
	return true;
}

static void join_op(struct equation_join *j, int input, const struct bpf_sym_equation *sym_eq)
{
	struct expr op[2], arg[2], res[2];
	int i, k;

	for (k = 0; k < 2; k++) {
		op[k] = rhs_expr(sym_eq, k);
		if (!translate_expr(j, input, &op[k]) ||
		    (op[k].coef && !phi_has_exprs(phi_args(j, op[k].var))))
			return;
	}
	if (bpf_find_op(j->env, j->eqs, sym_eq->insn_idx, op, res))
		return;
	for (i = 0; i < 2; i++) {
		for (k = 0; k < 2; k++)
			arg[k] = !op[k].coef ? op[k] :
				 expr_scale(phi_args(j, op[k].var)[i], op[k].coef, op[k].off);
		if (!bpf_find_op(j->env, &j->st[i]->equations, sym_eq->insn_idx, arg, &res[i]))
			return;
	}
	res[0] = join_expr(j, res, THRESHOLD_SYM);
	bpf_add_op(j->env, j->eqs, sym_eq->insn_idx, op, res);
}

/* The equations between the syms of state @input */
static void join_sym_equations(struct equation_join *j, int input)
{
	const struct bpf_sym_equation *sym_eq;
	struct expr a, b;
	int last;

	for_each_sym_equation(j->env, &j->st[input]->equations, sym_eq) {
		if (is_op(sym_eq))
			join_op(j, input, sym_eq);
		if (is_op(sym_eq) || j->sums >= SUMS_PER_XREG * j->eqs->xreg_equation_cnt)
			continue;
		for (last = 2; last >= (sym_eq->coef[2] ? 0 : 2); last--) {
			a = sym_expr(sym_eq->coef[!last], sym_eq->sym[!last], 0);
			b = sym_expr(-sym_eq->coef[2 - (last == 2)],
				     sym_eq->sym[2 - (last == 2)], 0);
			if (translate_expr(j, input, &a) && translate_expr(j, input, &b) &&
			    join_diff(j, a, b, false))
				break;
		}
	}
}

/* Two phis are one sym in state @input: i, or i + 1. The first @xreg_phi_cnt phis have xregs. */
static void join_keep_diffs(struct equation_join *j, int input, u32 xreg_phi_cnt)
{
	u32 symno, first_symno, cnt = j->eqs->sym_cnt, *sym2phi;
	struct expr arg;

	for (symno = 1; symno < cnt && !over_limit(j->env); symno++) {
		arg = phi_args(j, symno)[input];
		sym2phi = var_is_sym(arg.var) ? &j->sym2phi[input][var_symno(arg.var)] : NULL;
		first_symno = sym2phi ? *sym2phi - 1 : symno;
		if (first_symno >= symno)
			continue;
		join_diff(j, sym_expr(1, symno, 0), sym_expr(arg.coef, first_symno, 0), true);
		if (arg.coef != 1 || symno >= xreg_phi_cnt)
			continue;
		/* the equations of the sym can hold for this phi only */
		*sym2phi = symno + 1;
		join_sym_equations(j, input);
		*sym2phi = first_symno + 1;
	}
}

/* Find "@x = *@part + rest" in state @input. *@part is a constant in the other state. */
static bool find_sum_part(struct equation_join *j, int input, u64 x, struct expr *part)
{
	const struct bpf_sym_equation *sym_eq;
	int i, pos;

	for_each_sum(j->env, &j->st[input]->equations, sym_eq) {
		pos = find_sym_pos(sym_eq, var_symno(x));
		for (i = 0; i < 3 && pos < 3 && is_plus_minus_one(sym_eq->coef[pos]); i++) {
			if (i == pos || !sym_eq->coef[i])
				continue;
			*part = sym_expr(-sym_eq->coef[pos] * sym_eq->coef[i],
					 sym_eq->sym[i], 0);
			if (!translate_expr(j, input, part) || phi_args(j, part->var)[!input].coef)
				continue;
			part->off = 0;
			return true;
		}
	}
	return false;
}

/*
 * A number grows with two trip indexes. Each state shows one of them:
 *	old state  j = 0  x = 2 * k + d		join  m = 2 * k + 41 * j
 *	new state  k = 0  x = 41 * j + d	      x = m + d
 */
static void join_sum_parts(struct equation_join *j, u32 phi_cnt)
{
	struct expr part[2], arg[2], sum;
	u32 symno;

	for (symno = 0; symno < phi_cnt && !over_limit(j->env); symno++) {
		memcpy(arg, phi_args(j, symno), sizeof(arg));
		if (arg[0].coef != 1 || arg[1].coef != 1 ||
		    !var_is_sym(arg[0].var) || !var_is_sym(arg[1].var) ||
		    !find_sum_part(j, 0, arg[0].var, &part[0]) ||
		    !find_sum_part(j, 1, arg[1].var, &part[1]))
			continue;
		part[1].coef = -part[1].coef;
		join_diff(j, part[0], part[1], true);
		if (find_diff(j, 2, &part[0], &part[1], &sum))
			join_diff(j, sym_expr(1, symno, 0), sum, true);
	}
}

/*
 * The ends of the range of @var in the two states are on two lines. So a stored condition
 * gives the range:
 *	c = x == 0; ... if (c)
 */
static void join_bounds_by_selector(struct equation_join *j, u64 var, bool always)
{
	const struct expr *arg = phi_args(j, var);
	struct scalar a, b;
	s64 min_slope, max_slope;

	if (var == j->selector || !phi_has_exprs(arg))
		return;
	bpf_eval_expr(j->env, j->st[0], &arg[0], &a);
	bpf_eval_expr(j->env, j->st[1], &arg[1], &b);
	if (!always && !scalars_are_disjoint(&a, &b))
		return;
	min_slope = b.r64.base - a.r64.base;
	max_slope = min_slope + b.r64.size - a.r64.size;
	if (max(a.r64.size, b.r64.size) >= U32_MAX) {
		if (!always && max(a.r32.size, b.r32.size) == U32_MAX)
			return;
		min_slope = (s32)(b.r32.base - a.r32.base);
		max_slope = (s32)(min_slope + b.r32.size - a.r32.size);
	}
	if (min_slope)
		join_diff(j, make_expr(1, var, 0), make_expr(min_slope, j->selector, 0), false);
	if (max_slope && max_slope != min_slope)
		join_diff(j, make_expr(1, var, 0), make_expr(max_slope, j->selector, 0), false);
}

/* Where the trip index of @e in @dst can stop. 0: it is too early to know. */
u64 bpf_guess_trip_threshold(struct bpf_verifier_env *env, const struct bpf_verifier_state *dst,
			     const struct loop_stack_entry *e, u64 xreg)
{
	const struct bpf_iv_threshold *threshold;
	u64 value = S64_MAX;
	int kind;

	/* without an equation nothing limits it */
	if (!bpf_find_xreg_equation(&dst->equations, xreg))
		return value;
	if (!e->trip_index.grew_once)
		return 0;
	if (e->exit_threshold < value && e->exit_threshold >= cnum64_umax(e->trip_index.r64))
		return e->exit_threshold;
	for (kind = THRESHOLD_EXIT_JUMP; kind <= THRESHOLD_BODY_JUMP && value == S64_MAX; kind++)
		for_each_iv_threshold(env, e->loop, threshold, kind)
			if (threshold->value >= cnum64_umax(e->trip_index.r64))
				value = min_t(u64, value, threshold->value);
	return value;
}

/*
 * Guess the equations that hold for @dst and @src, see bpf_equations_pre_join().
 * The first join shows what a trip moves. The next walk finds the thresholds.
 *
 * It terminates. From the third join around a cycle, only the equations of @dst are kept.
 * An equation can only get weaker:
 *	two xregs with one sym -> a sum with a new sym -> a wider sym -> no equation
 * New equations come from constants, and a constant in @dst gets a range only once.
 */
void bpf_guess_equations(struct bpf_verifier_env *env, const struct bpf_verifier_state *dst,
			 const struct bpf_verifier_state *src, struct bpf_loop *leftover_loop,
			 bool widen)
{
	struct bpf_equation_env *eq_env = env->eq_env;
	struct equation_join j = { env, { dst, src }, &eq_env->join_state.equations,
				   leftover_loop, widen, .selector = VAR_NONE };
	const struct loop_stack_entry *top = bpf_top_loop(dst->frame[dst->curframe]);
	const struct bpf_xreg_equation *xreg_eq;
	u32 i, sym_cnt;
	bool selector_is_trip, both_inputs;
	int fr;

	j.eqs->xreg_equation_cnt = j.eqs->sym_equation_cnt = j.eqs->sym_cnt = 0;
	sym_cnt = dst->equations.sym_cnt + src->equations.sym_cnt;
	if (!bpf_grow_array(env, &eq_env->phi_index, &eq_env->phi_index_cap,
			    2 * sym_cnt + 1, sizeof(u32)))
		return;
	memset(eq_env->phi_index, 0, (2 * sym_cnt + 1) * sizeof(u32));
	j.sym2phi[0] = eq_env->phi_index;
	j.sym2phi[1] = eq_env->phi_index + dst->equations.sym_cnt;
	j.phi_lists = eq_env->phi_index + sym_cnt;
	eq_env->equation_added = true;
	for (fr = dst->curframe; fr >= 0; fr--)
		for (i = dst->frame[fr]->loop_stack_cnt; i--;)
			join_xreg(&j, bpf_xreg(fr, BPF_XREG_TRIP + i));
	selector_is_trip = j.selector != VAR_NONE;
	for (i = 0; i < 2; i++)
		for_each_xreg_equation(env, &j.st[i]->equations, xreg_eq)
			join_xreg(&j, xreg_eq->xreg);
	join_other_xregs(&j, selector_is_trip);
	both_inputs = !widen || selector_is_trip ||
		      (top && top->trip_index.grew_once && !top->trip_widened);
	for (i = 0, sym_cnt = j.eqs->sym_cnt; i <= both_inputs; i++) {
		join_keep_diffs(&j, i, sym_cnt);
		join_sym_equations(&j, i);
	}
	/* the equations made phis too: i, and i before it was truncated to 32 bits */
	if (leftover_loop)
		join_keep_diffs(&j, 0, 0);
	if (leftover_loop && !widen)
		join_sum_parts(&j, sym_cnt);
	for (i = 0, sym_cnt = j.eqs->sym_cnt; j.selector != VAR_NONE && i < sym_cnt; i++)
		join_bounds_by_selector(&j, VAR_SYM | i, selector_is_trip);
}

/*
 * Which xregs move with the trip index in @dst? Some do not in the equations of the @join:
 *	i = (i + 1) & 63;
 */
void bpf_note_linear_xregs(struct bpf_verifier_env *env, const struct bpf_verifier_state *dst,
			   const struct bpf_equations *join)
{
	const struct bpf_func_state *f = dst->frame[dst->curframe];
	u64 trip_xreg = bpf_xreg(dst->curframe, BPF_XREG_TRIP + f->loop_stack_cnt - 1);
	const struct bpf_xreg_equation *old_trip =
		bpf_find_xreg_equation(&dst->equations, trip_xreg), *xreg_eq, *new;
	const struct bpf_xreg_equation *new_trip = bpf_find_xreg_equation(join, trip_xreg);

	if (!f->loop_stack_cnt || !old_trip || !new_trip)
		return;
	for_each_xreg_equation(env, &dst->equations, xreg_eq) {
		if (xreg_eq->sym != old_trip->sym || xreg_eq->xreg >> 32 != dst->curframe ||
		    (u32)xreg_eq->xreg >= BPF_XREG_TRIP)
			continue;
		new = bpf_find_xreg_equation(join, xreg_eq->xreg);
		if (!new || new->sym != new_trip->sym)
			__set_bit((u32)xreg_eq->xreg, loop->nonlinear_xregs);
		else if (!__test_and_set_bit((u32)xreg_eq->xreg, loop->linear_xregs))
			env->new_linear_xreg = true;
	}
}

/* Thresholds */

/*
 * A jump gives thresholds in many states. Keep the last one in the direction of @step.
 * No @step: @value is for the syms of the current state only.
 */
static void add_iv_threshold(struct bpf_verifier_env *env, struct bpf_loop *loop, s64 value,
			     s64 step, enum iv_threshold_kind kind, u32 idx)
{
	struct bpf_iv_threshold *threshold;

	for_each_iv_threshold(env, loop, threshold, kind)
		if (threshold->insn_idx == env->insn_idx && threshold->idx == idx)
			break;
	if (threshold < loop->iv_thresholds + loop->iv_threshold_cnt) {
		if (value == threshold->value || (step && (step > 0) == (value < threshold->value)))
			return;
		threshold->value = value;
	} else if (bpf_grow_array(env, &loop->iv_thresholds, &loop->iv_threshold_cap,
				  loop->iv_threshold_cnt + 1, sizeof(*threshold))) {
		loop->iv_thresholds[loop->iv_threshold_cnt++] =
			(struct bpf_iv_threshold){ value, kind, env->insn_idx, idx };
	}
	if (env->log.level & BPF_LOG_LEVEL2)
		bpf_log(&env->log, "loop at %d: %s has threshold %lld\n", loop->header,
			kind <= THRESHOLD_BODY_JUMP ? "the trip index" : "a number", value);
}

/* Write @expr as a function of @trip_var. It starts from the far end of what is added. */
static bool match_iv(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		     struct expr *expr, u64 trip_var, bool *low32, bool *start_is_range)
{
	const struct bpf_sym_equation *sym_eq, *ext;
	struct scalar bounds;
	struct expr rest;
	u32 n, i, k;

	for (n = 0;
	     expr->coef && expr->var != trip_var && n < st->equations.sym_equation_cnt; n++) {
		if (!var_is_sym(expr->var) || over_limit(env))
			return false;
		ext = NULL;
		for_each_sum(env, &st->equations, sym_eq) {
			i = find_sym_pos(sym_eq, var_symno(expr->var));
			if (i == 3)
				continue;
			k = find_sym_pos(sym_eq, var_symno(trip_var));
			if (!i && !(u8)sym_eq->coef[2])
				ext = sym_eq;
			if (k == 3 || !is_plus_minus_one(sym_eq->coef[i]))
				continue;
			rest = sym_expr(-expr->coef * sym_eq->coef[i] * sym_eq->coef[3 - i - k],
					sym_eq->sym[3 - i - k],
					expr->off - expr->coef * sym_eq->coef[i] * sym_eq->off);
			bpf_eval_expr(env, st, &rest, &bounds);
			*expr = make_expr(-expr->coef * sym_eq->coef[i] * sym_eq->coef[k],
					  trip_var, bounds.r64.base);
			if (bounds.r64.size > U32_MAX && bounds.r32.size == U32_MAX)
				return false;
			*start_is_range = bounds.r64.size;
			*low32 |= bounds.r64.size >= U32_MAX;
			if (*low32)
				expr->off = bounds.r32.base +
					    (expr->coef < 0 ? bounds.r32.size : 0);
			else if (expr->coef < 0)
				expr->off += bounds.r64.size;
			return expr->coef;
		}
		if (!ext)
			return false;
		*expr = expr_scale(rhs_expr(ext, 0), expr->coef, expr->off);
	}
	return expr->coef && expr->var == trip_var;
}

/*
 * "*@x @op @bound" holds in the trips that continue. In how many, if each adds @step to it?
 * *@x becomes the end of the range in which they continue.
 */
static u64 compute_trip_count(s64 step, u64 *x, u8 op, bool jmp32, struct scalar bound)
{
	struct cnum64 arc;
	struct scalar body_range;
	u64 left;

	if (op == BPF_JNE && jmp32)
		scalar_set_const(&bound, bound.r32.base + (step > 0 ? bound.r32.size : 0));
	else if (op == BPF_JNE)
		scalar_set_const(&bound, bound.r64.base + (step > 0 ? bound.r64.size : 0));
	scalar_set_unknown(&body_range);
	scalars_refine_cond_op(&body_range, &bound, op, jmp32);
	arc = jmp32 ? (struct cnum64){ body_range.r32.base, body_range.r32.size } : body_range.r64;
	left = jmp32 ? (u32)(*x - arc.base) : *x - arc.base;
	if (left > arc.size)
		return 0;
	*x = arc.base + (step > 0 ? arc.size : 0);
	*x = !jmp32 ? *x : op == bpf_signed_opcode(op) && op != BPF_JNE ? (s32)*x : (u32)*x;
	return min(div64_u64(step > 0 ? arc.size - left : left, abs64(step)), U64_MAX - 1) + 1;
}

static bool insn_is_in_loop(struct bpf_verifier_env *env, const struct bpf_loop *loop, int idx)
{
	int h = bpf_loop_at_index(env, idx);

	return h == loop->header || bpf_is_nested_loop(env, h, loop->header);
}

/* The jump stays in the loop if operand 0 or 1, or their difference, is "op" the bound */
static u8 loop_cond_opcode(const struct bpf_insn *insn, bool taken, int i)
{
	u8 op = taken ? BPF_OP(insn->code) : bpf_rev_opcode(BPF_OP(insn->code));

	return !i ? op : i == 1 ? bpf_flip_opcode(op) : bpf_signed_opcode(op);
}

/* The difference starts from @x, but not further out than @bound[1] - @bound[0] can be */
static s64 clamp_diff_start(const struct scalar *bound, s64 x, s64 step)
{
	s64 a = step < 0 ? cnum64_smax(bound[1].r64) : cnum64_smin(bound[1].r64);
	s64 b = step < 0 ? cnum64_smin(bound[0].r64) : cnum64_smax(bound[0].r64);

	if (check_sub_overflow(a, b, &a))
		return x;
	return step < 0 ? min(x, a) : max(x, a);
}

/* The jump at env->insn_idx tests a number that moves with the trip index. Find thresholds. */
void bpf_collect_iv_thresholds(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[env->insn_idx];
	const struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
	const struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *f = st->frame[st->curframe];
	bool is_ptr, is_iv[3], low32[3], start_is_range[3] = {}, stays_in_loop[2], is_body_jump;
	struct loop_stack_entry *e = bpf_top_loop(f);
	struct expr trip, step, expr[3];
	struct scalar bound[3];
	struct equation_pos pos = {};
	bool tests_carry = false;
	u32 i, n;
	u64 start, x, cnt;
	u8 op;

	if (!env->eq_env || !e || e->loop->kind != BPF_LOOP_JUMPS ||
	    (env->path_sensitive ? !aux->iv_operand : !st->equations.xreg_equation_cnt ||
				   (e->trip_widened &&
				    aux->thresholds_epoch == e->loop->leftover_epoch)))
		return;
	expr[1] = make_expr(0, 0, insn->imm);
	if (!bpf_xreg_expr(env, st, bpf_reg_to_xreg(st, insn->dst_reg), &expr[0], &is_ptr) ||
	    (BPF_SRC(insn->code) == BPF_X &&
	     !bpf_xreg_expr(env, st, bpf_reg_to_xreg(st, insn->src_reg), &expr[1], &is_ptr)))
		return;
	bpf_eval_expr(env, st, &expr[1], &bound[0]);
	bpf_eval_expr(env, st, &expr[0], &bound[1]);
	scalar_set_const(&bound[2], 0);
	stays_in_loop[0] = insn_is_in_loop(env, e->loop, env->insn_idx + 1);
	stays_in_loop[1] = insn_is_in_loop(env, e->loop, env->insn_idx + insn->off + 1);
	is_body_jump = stays_in_loop[0] && stays_in_loop[1];
	low32[0] = low32[1] = low32[2] = BPF_CLASS(insn->code) == BPF_JMP32;
	x = bpf_xreg(st->curframe, BPF_XREG_TRIP + f->loop_stack_cnt - 1);
	if (!bpf_xreg_expr(env, st, x, &trip, &is_ptr) || !var_is_sym(trip.var))
		return;
	if (expr[0].coef && expr[1].coef &&
	    bpf_find_next_diff(env, &st->equations, &expr[0], &expr[1], &pos, &expr[2])) {
		/* it gets to 0 */
		add_iv_threshold(env, e->loop, expr[0].off - expr[1].off, 0, THRESHOLD_DIFF, 0);
		add_iv_threshold(env, e->loop, expr[1].off - expr[0].off, 0, THRESHOLD_DIFF, 1);
		add_iv_threshold(env, e->loop, -expr[2].coef * expr[2].off, 0, THRESHOLD_DIFF, 2);
	} else {
		expr[2].coef = 0;
	}
	for (i = 0; i < 3; i++) {
		is_iv[i] = match_iv(env, st, &expr[i], trip.var, &low32[i], &start_is_range[i]);
		/* the step in one trip */
		step = make_expr(0, 0, expr[i].coef);
		is_iv[i] = is_iv[i] && bpf_expr_div_exact(&step, 0, trip.coef);
		expr[i].coef = step.off;
	}
	/* they do not get closer */
	if (is_iv[0] && is_iv[1] && !start_is_range[0] && !start_is_range[1] &&
	    expr[0].coef == expr[1].coef) {
		/* but 'x != (u32)x' is 'x > U32_MAX', see refine_carry(). Operand i is x. */
		i = cnum64_umax(bound[1].r64) <= U32_MAX;
		if ((insn->code != (BPF_JMP | BPF_JNE | BPF_X) &&
		     insn->code != (BPF_JMP | BPF_JEQ | BPF_X)) ||
		    expr[0].off == expr[1].off || (u32)(expr[0].off - expr[1].off) ||
		    cnum64_umax(bound[i].r64) > U32_MAX)
			return;
		scalar_set_const(&bound[i], U32_MAX);
		is_iv[!i] = is_iv[2] = low32[i] = false;
		tests_carry = true;
	}
	start = e->trip_index.r64.base;
	for (n = is_iv[0] && is_iv[1] && is_iv[2] ? 4 : 0; n < 6; n++) {
		i = n / 2;
		if (!is_iv[i] || !stays_in_loop[n & 1] || (is_body_jump && start_is_range[i]))
			continue;
		aux->thresholds_epoch = e->loop->leftover_epoch;
		/* note_trips_left() takes the other operand as the bound */
		if (i < 2 && !tests_carry)
			aux->iv_operand = i + 1;
		x = expr[i].coef * (start - trip.off) + expr[i].off;
		if (i == 2 && start_is_range[i])
			x = clamp_diff_start(bound, low32[i] ? (s32)x : x, expr[i].coef);
		op = loop_cond_opcode(insn, n & 1, i);
		if (tests_carry)
			op = op == BPF_JNE ? BPF_JGT : BPF_JLE;
		cnt = compute_trip_count(expr[i].coef, &x, op, low32[i], bound[i]);
		/* its start is not known, so the trip index does not give its end */
		if (cnt && start_is_range[i] && i < 2) {
			add_iv_threshold(env, e->loop, x, expr[i].coef, THRESHOLD_SYM, 2 * n);
			add_iv_threshold(env, e->loop, x + expr[i].coef, expr[i].coef,
					 THRESHOLD_SYM, 2 * n + 1);
		}
		if (!cnt || cnt > BPF_MAX_TRIPS)
			continue;
		add_iv_threshold(env, e->loop, start + cnt, 1, is_body_jump, 2 * n);
		if (is_body_jump)
			add_iv_threshold(env, e->loop, start + cnt + 1, 1, is_body_jump, 2 * n + 1);
		else
			e->exit_threshold = min(e->exit_threshold, start + cnt);
	}
}
