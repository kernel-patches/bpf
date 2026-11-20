/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BPF_EQUATION_H
#define __BPF_EQUATION_H

#include <linux/bpf_verifier.h>

/* A var is an xreg, see bpf_xreg(), or a sym */
#define VAR_SYM		BIT_ULL(63)
#define VAR_NONE	U64_MAX
#define NO_SYM		U32_MAX

/* For each xreg a state keeps twice that many sums and ops in total, see normalize_equations() */
#define SUMS_PER_XREG	2

/* coef * var + off. A constant has no var and coef == 0. */
struct expr {
	s64 coef;
	u64 off;
	u64 var;
};

/* xreg = coef * sym + off. The table is sorted by xreg. */
struct bpf_xreg_equation {
	u64 xreg;
	s64 coef;
	u64 off;
	u32 sym;
	bool is_ptr;		/* the number is the offset of a pointer */
};

/*
 * A sum: 0 = coef[0] * sym[0] + coef[1] * sym[1] + coef[2] * sym[2] + off, coef[0] is -1.
 * An op: sym[0] is what @insn_idx makes of the operands, see rhs_expr(). coef[0] is 1.
 */
struct bpf_sym_equation {
	s64 coef[3];
	u32 sym[3];
	s32 insn_idx;		/* that made the equation, -1 for a sum of a join */
	u64 off, off_src;
};

/* See bpf_find_next_diff() */
struct equation_pos {
	u32 next, seen_cnt;
};

/* Scratch data of a function about a sym */
struct sym_scratch {
	u32 use_cnt;		/* equations that use it */
	/* propagate_bounds(): the sweep that has to look at its equations */
	u32 refined_sweep;
	/* propagate_bounds(): not of this sym. The queue of refined syms. */
	u32 queued_sym;
	u32 first_use;		/* see link_sym_equations() */
	u32 new_symno;
	bool determined, by_op;
	bool forgotten, in_data_deps;	/* bpf_equations_join_forgets() */
	const struct bpf_sym_equation *op;	/* that makes it */
	struct expr cur_expr;	/* check_equations(): its value in the other state */
};

struct bpf_equation_env {
	struct sym_scratch *scratch;
	u32 *use_links;
	u32 scratch_cap, use_link_cap, refined_cnt;
	/* the insn that is checked and its operands */
	s32 insn_idx;
	struct expr operand_expr[2];
	struct scalar operand_bounds[2];
	bool has_expr[2], is_ptr[2], equation_added, divided;
	/* the arguments of a call */
	struct expr arg_expr[BPF_REG_5 + 1];
	u8 has_arg_expr;
	u64 fill_xreg;
	u32 fill_bits;
	/* the operand of a jump and its bounds, see refine_from_reg() */
	struct expr jump_expr;
	struct scalar jump_bounds;
	/* equation_join.c */
	struct bpf_verifier_state join_state;	/* it has equations and no frames */
	struct join_phi *phis;
	u32 *phi_index;
	u32 phi_cap, phi_index_cap;
};

#define for_each_sym_equation(env, eqs, pos)						\
	for (bpf_add_cost(env, (eqs)->sym_equation_cnt, BPF_COST_COPY),			\
	     pos = (eqs)->sym_equations;						\
	     pos < (eqs)->sym_equations + (eqs)->sym_equation_cnt; pos++)

#define for_each_sum(env, eqs, pos) \
	for_each_sym_equation(env, eqs, pos) \
		if (!is_op(pos))

#define for_each_xreg_equation(env, eqs, pos)						\
	for (bpf_add_cost(env, (eqs)->xreg_equation_cnt, BPF_COST_COPY),		\
	     pos = (eqs)->xreg_equations;						\
	     pos < (eqs)->xreg_equations + (eqs)->xreg_equation_cnt; pos++)

/* The pass is over its budget. It finds no more equations, a scan in a loop does not start. */
static inline bool over_limit(struct bpf_verifier_env *env)
{
	return env->over_limit || bpf_check_limits(env);
}

static inline bool var_is_sym(u64 var)
{
	return var != VAR_NONE && (var & VAR_SYM);
}

static inline u32 var_symno(u64 var)
{
	return var;
}

static inline u64 abs64(s64 x)
{
	return x < 0 ? -(u64)x : x;
}

static inline bool is_plus_minus_one(s64 coef)
{
	return coef == 1 || coef == -1;
}

static inline struct expr make_expr(s64 coef, u64 var, u64 off)
{
	return (struct expr){ coef, off, coef ? var : VAR_NONE };
}

static inline struct expr sym_expr(s64 coef, u32 sym, u64 off)
{
	return make_expr(coef, VAR_SYM | sym, off);
}

static inline struct expr expr_scale(struct expr expr, s64 coef, u64 off)
{
	return make_expr(expr.coef * coef, expr.var, expr.off * coef + off);
}

static inline bool expr_equal(const struct expr *a, const struct expr *b)
{
	return a->coef == b->coef && a->off == b->off && a->var == b->var;
}

/* Operand @i on the right side */
static inline struct expr rhs_expr(const struct bpf_sym_equation *sym_eq, int i)
{
	return sym_expr(sym_eq->coef[i + 1], sym_eq->sym[i + 1], i ? sym_eq->off_src : sym_eq->off);
}

static inline bool is_op(const struct bpf_sym_equation *sym_eq)
{
	return sym_eq->coef[0] == 1;
}

/* The position of @sym in @sym_eq. 3 if it is not there. */
static inline int find_sym_pos(const struct bpf_sym_equation *sym_eq, u32 sym)
{
	return sym_eq->sym[0] == sym ? 0 : sym_eq->sym[1] == sym ? 1 :
	       sym_eq->sym[2] == sym ? 2 : 3;
}

/* equation.c */
u64 bpf_new_sym(struct bpf_verifier_env *env, struct bpf_equations *eqs,
		const struct scalar *bounds);
bool bpf_add_sym_equation(struct bpf_verifier_env *env, struct bpf_equations *eqs,
			  struct bpf_sym_equation sym_eq);
bool bpf_add_op(struct bpf_verifier_env *env, struct bpf_equations *eqs, s32 insn,
		const struct expr *op, const struct expr *res);
bool bpf_find_op(struct bpf_verifier_env *env, const struct bpf_equations *eqs, s32 insn,
		 const struct expr *op, struct expr *res);
struct bpf_xreg_equation *bpf_find_xreg_equation(const struct bpf_equations *eqs, u64 xreg);
void bpf_set_xreg_equation(struct bpf_verifier_env *env, struct bpf_equations *eqs, u64 xreg,
			   const struct expr *expr, bool is_ptr);
u64 bpf_reg_to_xreg(const struct bpf_verifier_state *st, u32 regno);
struct scalar *bpf_find_var_bounds(struct bpf_verifier_env *env,
				   const struct bpf_verifier_state *st, u64 var, bool *is_ptr);
bool bpf_xreg_expr(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, u64 xreg,
		   struct expr *expr, bool *is_ptr);
void bpf_eval_expr(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		   const struct expr *expr, struct scalar *bounds);
bool bpf_expr_div_exact(struct expr *expr, u64 off, s64 coef);
bool bpf_find_next_diff(struct bpf_verifier_env *env, const struct bpf_equations *eqs,
			const struct expr *a, const struct expr *b, struct equation_pos *pos,
			struct expr *diff);
void bpf_eval_diff(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		   const struct expr *a, const struct expr *b, struct scalar *bounds);

/* equation_join.c */
void bpf_guess_equations(struct bpf_verifier_env *env, const struct bpf_verifier_state *dst,
			 const struct bpf_verifier_state *src, struct bpf_loop *leftover_loop,
			 bool widen);
void bpf_note_linear_xregs(struct bpf_verifier_env *env, const struct bpf_verifier_state *dst,
			   const struct bpf_equations *join);
u64 bpf_guess_trip_threshold(struct bpf_verifier_env *env, const struct bpf_verifier_state *dst,
			     const struct loop_stack_entry *e, u64 xreg);

#endif
