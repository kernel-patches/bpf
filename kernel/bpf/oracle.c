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

static struct bpf_map *create_inner_oracle_map(size_t size)
{
	struct bpf_map *map;
	int err;

	union bpf_attr map_attr = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(struct bpf_oracle_state),
		.max_entries = size,
		.map_flags = BPF_F_INNER_MAP | BPF_F_RDONLY,
		.map_name = "oracle_inner",
	};
	map = array_map_ops.map_alloc(&map_attr);
	if (IS_ERR(map))
		return map;

	map->ops = &array_map_ops;
	map->map_type = BPF_MAP_TYPE_ARRAY;

	err = bpf_obj_name_cpy(map->name, map_attr.map_name,
			       sizeof(map_attr.map_name));
	if (err < 0)
		goto free_map;

	mutex_init(&map->freeze_mutex);
	spin_lock_init(&map->owner_lock);

	err = security_bpf_map_create(map, &map_attr, NULL, false);
	if (err)
		goto free_map_sec;

	err = bpf_map_alloc_id(map);
	if (err)
		goto free_map_sec;

	bpf_map_save_memcg(map);

	return map;

free_map_sec:
	security_bpf_map_free(map);
free_map:
	bpf_map_free(map);
	return ERR_PTR(err);
}

struct bpf_prog *patch_oracle_check_insn(struct bpf_verifier_env *env, struct bpf_insn *insn,
					 int i, int *cnt)
{
	struct bpf_insn ld_addrs[2] = {
		BPF_LD_IMM64_RAW(0, BPF_PSEUDO_MAP_ORACLE, 0),
	};
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[i];
	struct list_head *head = aux->oracle_states;
	struct bpf_insn *insn_buf = env->insn_buf;
	struct bpf_prog *new_prog = env->prog;
	int num_oracle_states, err;
	struct bpf_map *inner_map;

	if (env->subprog_cnt > 1)
		/* Skip the oracle if subprogs are used. */
		goto noop;

	num_oracle_states = list_count_nodes(head);
	if (!num_oracle_states)
		goto noop;

	inner_map = create_inner_oracle_map(num_oracle_states);
	if (IS_ERR(inner_map))
		return (void *)inner_map;

	ld_addrs[0].imm = (u32)(u64)inner_map;
	ld_addrs[1].imm = ((u64)inner_map) >> 32;
	insn_buf[0] = ld_addrs[0];
	insn_buf[1] = ld_addrs[1];
	insn_buf[2] = *insn;
	*cnt = 3;

	new_prog = bpf_patch_insn_data(env, i, insn_buf, *cnt);
	if (!new_prog)
		return ERR_PTR(-ENOMEM);

	/* Attach oracle inner map to new LDIMM64 instruction. */
	aux = &env->insn_aux_data[i];
	aux->oracle_inner_map = inner_map;

	err = __add_used_map(env, inner_map);
	if (err < 0)
		return ERR_PTR(err);

	return new_prog;

noop:
	*cnt = 1;
	return new_prog;
}
