// SPDX-License-Identifier: GPL-2.0-only
/*
 * Help for the path-sensitive run, see run_path_sensitive(). If the error of a pass is real,
 * the next passes get a small budget and the log gets a path to the error. The run reproduces
 * the error with no joins. The path on which the check fails again is the failing path.
 *
 *	entry --> ... --> state --+--> 2 hops --> unproven insn		goes first
 *	                          +--> 9 hops --> unproven insn
 *	                          +--> no path				is dropped
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/slab.h>

#include "precision.h"

#define NO_PATH	(U32_MAX / 2)

static bool shorter(u32 *hops, u32 via)
{
	if (via + 1 >= *hops)
		return false;
	*hops = via + 1;
	return true;
}

/* @to follows @from in one function */
static bool shorter_via(struct bpf_precision *prec, u32 from, u32 to)
{
	return shorter(&prec->hops_to_err[from], prec->hops_to_err[to]) |
	       shorter(&prec->hops_to_exit[from], prec->hops_to_exit[to]);
}

/*
 * For each insn, the number of edges to
 * - an unproven insn, in its function or in a function that it calls,
 * - the exit of its function.
 * The first unproven insn is nearer than the other ones.
 */
static int compute_hops(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub = env->subprog_info;
	u32 len = env->prog->len, taken = NO_PATH, i, k, n, s;
	struct bpf_precision *prec = env->precision;
	struct bpf_insn_aux_data *aux;
	struct bpf_iarray *succ;
	bool changed = true;
	int t, err = 0;

	for (i = 0; i < len; i++) {
		prec->hops_to_err[i] = !test_bit(i, prec->err_insns) ? NO_PATH :
				       i == prec->first_unproven_insn ? 0 : len;
		prec->hops_to_exit[i] = env->prog->insnsi[i].code == (BPF_JMP | BPF_EXIT) ?
					0 : NO_PATH;
	}
	while (changed && !err) {
		changed = false;
		/* callees first */
		for (k = 0; k < env->subprog_cnt; k++) {
			s = env->subprog_topo_order[k];
			for (i = sub[s].postorder_start; i < sub[s + 1].postorder_start; i++) {
				n = env->cfg.insn_postorder[i];
				aux = &env->insn_aux_data[n];
				succ = bpf_insn_successors(env, n);
				iarray_for_each(t, succ)
					changed |= shorter_via(prec, n, t);
				/* see check_loop_guard() and check_recursion_guard() */
				if (aux->guard_place)
					changed |= shorter_via(prec, n, aux->guard_to);
				if ((aux->guard_place || (sub[s].cycle && n == sub[s].start)) &&
				    sub[s].bail_insn >= 0)
					changed |= shorter_via(prec, n, sub[s].bail_insn);
				if (!bpf_calls_function(env, n))
					continue;
				t = bpf_insn_callee(env, n);
				changed |= shorter(&prec->hops_to_err[n],
						   t > 0 ? prec->hops_to_err[sub[t].start] : taken);
			}
			if (sub[s].addr_taken)
				changed |= shorter(&taken, prec->hops_to_err[sub[s].start]);
		}
		err = bpf_add_cost_and_check(env, len, BPF_COST_XREG);
	}
	return err;
}

bool bpf_failing_path_may_end_at(struct bpf_verifier_env *env, u32 idx)
{
	return idx < env->prog->len && test_bit(idx, env->precision->err_insns);
}

/* The number of edges from @st to an unproven insn. U32_MAX if there is no path. */
u32 bpf_failing_path_hops(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	const struct bpf_precision *prec = env->precision;
	u32 idx = st->insn_idx, fr = st->curframe;
	u64 hops = prec->hops_to_err[idx], out = 0;

	for (; fr; fr--) {
		out += prec->hops_to_exit[idx];
		idx = st->frame[fr]->callsite + !st->frame[fr]->in_callback_fn;
		hops = min(hops, out + prec->hops_to_err[idx]);
	}
	return hops < NO_PATH ? hops : U32_MAX;
}

static u64 hash_value(const struct bpf_reg_state *reg, u64 hash)
{
	return bpf_hash64(reg, offsetof(struct bpf_reg_state, grew_once), hash);
}

/* The join_key, the values of the deps, and which of them have one sym */
static u64 hash_state(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	unsigned long all[XREG_WORDS], control_deps[XREG_WORDS];
	u64 hash = bpf_hash_join_key(env, st);
	const struct bpf_reg_state *reg;
	const struct bpf_func_state *f;
	struct bpf_reg_state tmp;
	u32 fr, xregno, i, bits;

	for (fr = 0; fr <= st->curframe; fr++) {
		f = st->frame[fr];
		bpf_frame_mask(env, env->precision->control_deps, st, fr, control_deps);
		bits = bpf_frame_mask(env, env->precision->type_apart, st, fr, all);
		bitmap_or(all, all, control_deps, bits);
		bpf_add_cost(env, 2 * bitmap_weight(all, bits), BPF_COST_XREG);
		hash += bpf_equations_hash(env, st, fr, all, bits);
		for_each_set_bit(xregno, all, bits) {
			for (i = 0; xregno == XREG_STACK_ARGS && i < f->out_stack_arg_cnt; i++)
				hash = hash_value(&f->stack_arg_regs[i], hash);
			reg = bpf_xreg_value(env, f, xregno, &tmp);
			if (reg)
				hash = hash_value(reg, hash + xregno);
			i = bpf_xreg_to_spi(xregno);
			if (i < bpf_stack_nr_slots(f))
				hash = bpf_hash64(bpf_stack_slot(f, i)->slot_type,
						  BPF_REG_SIZE, hash);
		}
	}
	return hash;
}

static bool add_to_set(u64 *set, u32 bits, u64 hash)
{
	u32 i;

	for (i = hash & (BIT(bits) - 1); set[i]; i = (i + 1) & (BIT(bits) - 1))
		if (set[i] == hash)
			return false;
	set[i] = hash;
	return true;
}

/* Returns 1 if a path was at this insn with the same hash_state(). A collision drops a path. */
int bpf_failing_path_was_here(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	struct bpf_precision *prec = env->precision;
	u32 size = BIT(prec->seen_bits), i;
	u64 *set;

	if (2 * prec->seen_cnt + 2 > size) {
		set = kvcalloc(2 * size, sizeof(*set), BPF_VERIFIER_GFP);
		if (!set)
			return -ENOMEM;
		for (i = 0; prec->seen && i < size; i++)
			if (prec->seen[i])
				add_to_set(set, prec->seen_bits + 1, prec->seen[i]);
		env->mem += size * sizeof(*set);
		kvfree(prec->seen);
		prec->seen = set;
		prec->seen_bits++;
	}
	if (!add_to_set(prec->seen, prec->seen_bits, hash_state(env, st) | 1))
		return 1;
	prec->seen_cnt++;
	return 0;
}

/* The insn at @idx selects what runs next, and a path can get to it more than once */
static bool selects_path_again(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];

	if (env->insn_aux_data[idx].calls_callback)
		return true;
	if (idx < env->subprog_info[1].start && bpf_loop_at_index(env, idx) < 0)
		return false;
	return bpf_insn_is_cond_jump(insn->code) || insn_is_gotox(insn) ||
	       (bpf_calls_function(env, idx) && !bpf_pseudo_call(insn));
}

/*
 * A path came around a loop from @old to @new. Do the jumps that it can get to again see the
 * same values? Then it can take the same edges again.
 * @iv_jump_idx: ignore the jump that tests the iv. -1 if there is none.
 * @iv_xregs: each trip adds a constant to these xregs. Are all other loop-carried xregs the
 * same too, and not computed from these?
 */
int bpf_jumps_see_same(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
		       const struct bpf_verifier_state *new, int iv_jump_idx,
		       const unsigned long *iv_xregs)
{
	const struct bpf_insn_aux_data *aux = &env->insn_aux_data[old->insn_idx];
	struct bpf_precision *prec = env->precision;
	unsigned long *masks = iv_jump_idx < 0 ? prec->loop_control_deps : prec->new_data_deps;
	u32 *made_for = iv_jump_idx < 0 ? &prec->loop_control_deps_for : &prec->new_data_deps_for;
	DECLARE_BITMAP(loop_carried, MAX_BPF_XREG) = {};
	u32 key = 2 * iv_jump_idx + !iv_xregs, i;
	struct state_cmp cmp;
	int err;

	if (iv_xregs) {
		loop_carried[0] = aux->live_regs_before & XREG_REGS;
		bpf_add_slots(loop_carried, aux->live_stack_before, MAX_BPF_XREG);
		bitmap_andnot(loop_carried, loop_carried, iv_xregs, MAX_BPF_XREG);
	}
	if (*made_for == key) {
		bpf_compare_states(env, old, new, masks, NULL, &cmp);
		/* masks that were made for other @iv_xregs can miss an xreg */
		if (cmp.all || bitmap_subset(loop_carried, prec->loop_carried, MAX_BPF_XREG))
			return !cmp.all;
	}
	for (i = 0; i < env->prog->len; i++)
		__assign_bit(i, prec->control_seeds,
			     i != iv_jump_idx && selects_path_again(env, i));
	if (iv_xregs) {
		bitmap_copy(prec->loop_carried, loop_carried, MAX_BPF_XREG);
		prec->loop_carried_at = old->insn_idx;
	}
	err = bpf_compute_deps(env, masks, prec->control_seeds);
	prec->loop_carried_at = U32_MAX;
	if (err)
		return err;
	*made_for = key;
	bpf_compare_states(env, old, new, masks, NULL, &cmp);
	return !cmp.all;
}

/* The masks or the budget are new */
bool bpf_failing_path_is_due(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	return prec->failing_path_due || prec->partitioned_by == BIT(PARTITION_ADD_DEPS);
}

/* @repeat: start like the last run */
int bpf_failing_path_prepare(struct bpf_verifier_env *env, bool repeat)
{
	struct bpf_precision *prec = env->precision;

	prec->failing_path_due = false;
	if (prec->seen)
		memset(prec->seen, 0, sizeof(*prec->seen) << prec->seen_bits);
	prec->seen_cnt = prec->new_data_deps_for = 0;
	return repeat ? 0 : compute_hops(env);
}
