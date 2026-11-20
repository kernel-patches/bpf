// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/slab.h>

#include "precision.h"

/* The insn at @idx is unproven because it reads a value from another unproven insn */
void bpf_note_reads_from_unproven(struct bpf_verifier_env *env, u32 idx)
{
	__set_bit(idx, env->precision->this_pass.bad_read_insns);
	__set_bit(idx, env->precision->err_insns);
}

/* The access at @idx is unproven because of its address, whatever it loads or stores */
static bool bad_address(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, u32 idx)
{
	const struct bpf_func_state *f = st->frame[st->curframe];
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	u8 class = BPF_CLASS(insn->code);
	const struct bpf_reg_state *base;

	if (insn->src_reg >= MAX_BPF_REG || insn->dst_reg >= MAX_BPF_REG ||
	    (class != BPF_LDX && class != BPF_ST &&
	     (class != BPF_STX || f->regs[insn->src_reg].type != SCALAR_VALUE)))
		return false;
	base = &f->regs[class == BPF_LDX ? insn->src_reg : insn->dst_reg];
	if (base->type != PTR_TO_STACK)
		return !tnum_is_const(base->var_off);
	return reg_smin(base) < -(s64)env->stack_limit - insn->off ||
	       reg_smax(base) > -insn->off - bpf_size_to_bytes(BPF_SIZE(insn->code));
}

/* The insn at @idx is unproven in @st */
void bpf_note_unproven_insn(struct bpf_verifier_env *env,
			    const struct bpf_verifier_state *st, u32 idx)
{
	struct bpf_subprog_info *sub = bpf_find_containing_subprog(env, idx);
	struct bpf_precision *prec = env->precision;
	const struct loop_stack_entry *e;
	u32 i, fr;

	if (!sub)
		return;
	for (fr = 0; fr <= st->curframe && st->frame[fr]; fr++) {
		e = st->frame[fr]->loop_stack;
		for (i = 0; i < st->frame[fr]->loop_stack_cnt; i++, e++)
			e->loop->this_pass.has_unproven |= (e->peeled || e->loop->disjoint_apart) &&
							   !(st->suspect_loops &
							     ~e->loop->suspect_bit);
	}
	for (i = st->curframe; i > 0 && st->frame[i]; i--)
		__set_bit(st->frame[i]->callsite, prec->this_pass.call_insns);
	/* the state does not know who called */
	__set_bit(st->frame[0] ? st->frame[0]->subprogno : sub - env->subprog_info,
		  prec->this_pass.unproven_funcs);
	/* peeling comes first: it helps only for the suspect loops of this state */
	if (!__test_and_set_bit(idx, prec->this_pass.unproven_insns)) {
		prec->last_unproven_left -= test_bit(idx, prec->last_unproven_insns);
		prec->this_pass.suspect_loops |= st->suspect_loops;
		if (idx == env->err_insn)
			prec->this_pass.first_suspect_loops |= st->suspect_loops;
	}
	if (!st->frame[0] || !bad_address(env, st, idx))
		__set_bit(idx, prec->bad_value_insns);
	if (!st->holds_too_much)
		__set_bit(idx, prec->err_insns);
	for (i = BPF_REG_0; st->frame[0] && i < BPF_REG_FP; i++)
		if ((env->insn_aux_data[idx].use_regs & BIT(i)) &&
		    !test_bit(idx, prec->bad_read_insns_done) &&
		    st->frame[st->curframe]->regs[i].type == NOT_INIT)
			__set_bit(idx, prec->this_pass.bad_read_insns);
}

/* The state that set the fixup is gone. The leftover of a loop possibly made it up. */
static void suspect_loops_of_insn(struct bpf_verifier_env *env, u32 idx)
{
	env->precision->this_pass.suspect_loops |= env->insn_aux_data[idx].suspect_loops;
	if (!env->err)
		env->precision->this_pass.first_suspect_loops |=
			env->insn_aux_data[idx].suspect_loops;
}

/* The current insn has a fixup that does not fit the current state */
void bpf_note_fixups_differ(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[env->insn_idx];

	suspect_loops_of_insn(env, env->insn_idx);
	if (aux->speculative_first && !env->cur_state->speculative)
		aux->non_speculative_first = env->precision->new_nospec = env->imprecise = true;
}

bool bpf_insn_is_unproven(struct bpf_verifier_env *env)
{
	return !env->path_sensitive &&
	       test_bit(env->insn_idx, env->precision->this_pass.unproven_insns);
}

static void note_unproven_after_pass(struct bpf_verifier_env *env, u32 idx)
{
	static const struct bpf_verifier_state no_state;

	bpf_note_unproven_insn(env, &no_state, idx);
	/* no check failed, so the failing path cannot end here */
	__clear_bit(idx, env->precision->err_insns);
	suspect_loops_of_insn(env, idx);
}

/* check_after_pass() found an error. Which insns caused it? */
void bpf_find_unproven_after_pass(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insn = env->prog->insnsi;
	u32 i;

	for (i = 0; i < env->subprog_cnt; i++)
		note_unproven_after_pass(env, env->subprog_info[i].deepest_insn);
	for (i = 0; i < env->prog->len; i++, insn++, aux++) {
		if (aux->pessimized) {
			note_unproven_after_pass(env, i);
		} else if (aux->seen && (bpf_calls_function(env, i) || is_stack_arg_st(insn) ||
					 is_stack_arg_stx(insn))) {
			__set_bit(i, env->precision->this_pass.call_insns);
			suspect_loops_of_insn(env, i);
		}
	}
}

/*
 * All unproven insns of the last pass are unproven again, so the pass can stop. It continues if
 * it added to linear_xregs: later trips can show that the xreg is not linear.
 */
bool bpf_same_insns_unproven(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	return env->for_log || (prec->last_unproven_left == 1 && !env->new_linear_xreg &&
				test_bit(env->insn_idx, prec->last_unproven_insns) &&
				!test_bit(env->insn_idx, prec->this_pass.unproven_insns));
}
