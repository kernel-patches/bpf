// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file implements a test oracle for the verifier. When the oracle is enabled, the verifier
 * saves information on variables at regular points throughout the program. This information is
 * then compared at runtime with the concrete values to ensure that the verifier's information is
 * correct.
 */

#include <linux/bpf_verifier.h>

static void convert_oracle_state(struct bpf_verifier_state *istate, struct bpf_oracle_state *ostate)
{
	struct bpf_func_state *frame = istate->frame[istate->curframe];
	struct bpf_reg_oracle_state *oreg;
	struct bpf_reg_state *ireg;
	int i;

	/* No need to check R10 with the oracle. */
	for (i = 0; i < MAX_BPF_REG - 1; i++) {
		ireg = &frame->regs[i];
		oreg = &ostate->regs[i];

		oreg->scalar = ireg->type == SCALAR_VALUE;
		oreg->ptr_not_null = reg_not_null(ireg);

		oreg->var_off = ireg->var_off;
		oreg->smin_value = ireg->smin_value;
		oreg->smax_value = ireg->smax_value;
		oreg->umin_value = ireg->umin_value;
		oreg->umax_value = ireg->umax_value;
		oreg->s32_min_value = ireg->s32_min_value;
		oreg->s32_max_value = ireg->s32_max_value;
		oreg->u32_min_value = ireg->u32_min_value;
		oreg->u32_max_value = ireg->u32_max_value;
	}
}

int save_state_in_oracle(struct bpf_verifier_env *env, int insn_idx)
{
	struct bpf_verifier_state *cur = env->cur_state;
	struct bpf_insn_aux_data *aux = cur_aux(env);
	struct bpf_oracle_state_list *new_sl;

	if (env->subprog_cnt > 1)
		/* Skip the oracle if subprogs are used. */
		return 0;

	if (!aux->oracle_states) {
		aux->oracle_states = kmalloc(sizeof(*aux->oracle_states), GFP_KERNEL_ACCOUNT);
		if (!aux->oracle_states)
			return -ENOMEM;

		INIT_LIST_HEAD(aux->oracle_states);
	}

	new_sl = kzalloc(sizeof(*new_sl), GFP_KERNEL_ACCOUNT);
	if (!new_sl)
		return -ENOMEM;
	convert_oracle_state(cur, &new_sl->state);
	list_add(&new_sl->node, aux->oracle_states);

	return 0;
}
