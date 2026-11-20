/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BPF_EQUATION_H
#define __BPF_EQUATION_H

#include <linux/bpf_verifier.h>

/* A var is an xreg, see bpf_xreg(), or a sym */
#define VAR_SYM		BIT_ULL(63)
#define VAR_NONE	U64_MAX
#define NO_SYM		U32_MAX

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
	s32 insn_idx;		/* that made the equation, -1 for a sum of a join or a clean-up */
	u64 off, off_src;
};

/* See bpf_find_next_diff() */
struct equation_pos {
	u32 next, seen_cnt;
};

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

bool bpf_expr_div_exact(struct expr *expr, u64 off, s64 coef);
bool bpf_find_next_diff(struct bpf_verifier_env *env, const struct bpf_equations *eqs,
			const struct expr *a, const struct expr *b, struct equation_pos *pos,
			struct expr *diff);
#endif
