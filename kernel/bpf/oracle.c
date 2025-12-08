// SPDX-License-Identifier: GPL-2.0-only
/*
 * This file implements a test oracle for the verifier. When the oracle is enabled, the verifier
 * saves information on variables at regular points throughout the program. This information is
 * then compared at runtime with the concrete values to ensure that the verifier's information is
 * correct.
 */

#include <linux/bpf_verifier.h>

#define REGS_FMT_BUF_LEN 221

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

static int populate_oracle_inner_map(struct list_head *head, struct bpf_map *inner_map)
{
	struct bpf_oracle_state_list *sl;
	struct list_head *pos, *tmp;
	int i = 0;

	list_for_each_safe(pos, tmp, head) {
		sl = container_of(pos, struct bpf_oracle_state_list, node);
		inner_map->ops->map_update_elem(inner_map, &i, &sl->state, 0);
		i++;
	}

	return 0;
}

static void free_oracle_states(struct list_head *oracle_states)
{
	struct bpf_oracle_state_list *sl;
	struct list_head *pos, *tmp;

	list_for_each_safe(pos, tmp, oracle_states) {
		sl = container_of(pos, struct bpf_oracle_state_list, node);
		kfree(sl);
	}
	kvfree(oracle_states);
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

	populate_oracle_inner_map(head, inner_map);
	free_oracle_states(aux->oracle_states);
	aux->oracle_states = NULL;

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

static int populate_oracle_map(struct bpf_verifier_env *env, struct bpf_map *oracle_map)
{
	struct bpf_insn_aux_data *aux;
	int i, err;

	/* Oracle checks are always before pruning points, so they cannot be the last
	 * instruction.
	 */
	for (i = 0; i < env->prog->len - 1; i++) {
		aux = &env->insn_aux_data[i];
		if (!aux->oracle_inner_map || !aux->oracle_inner_map->max_entries)
			continue;

		bpf_map_inc(aux->oracle_inner_map);

		rcu_read_lock();
		err = htab_map_update_elem_in_place(oracle_map, &i, &aux->oracle_inner_map,
						    BPF_NOEXIST, false, false);
		rcu_read_unlock();
		if (err) {
			bpf_map_put(aux->oracle_inner_map);
			return err;
		}
	}

	return 0;
}

static struct bpf_map *alloc_oracle_inner_map_meta(void)
{
	struct bpf_array *inner_array_meta;
	struct bpf_map *inner_map_meta;

	inner_map_meta = kzalloc(sizeof(*inner_map_meta), GFP_USER);
	if (!inner_map_meta)
		return ERR_PTR(-ENOMEM);

	inner_map_meta->map_type = BPF_MAP_TYPE_ARRAY;
	inner_map_meta->key_size = sizeof(__u32);
	inner_map_meta->value_size = sizeof(struct bpf_oracle_state);
	inner_map_meta->map_flags = BPF_F_INNER_MAP;
	inner_map_meta->max_entries = 1;

	inner_map_meta->ops = &array_map_ops;

	inner_array_meta = container_of(inner_map_meta, struct bpf_array, map);
	inner_array_meta->index_mask = 0;
	inner_array_meta->elem_size = round_up(inner_map_meta->value_size, 8);
	inner_map_meta->bypass_spec_v1 = true;

	return inner_map_meta;
}

static struct bpf_map *create_oracle_map(struct bpf_verifier_env *env)
{
	struct bpf_map *map = NULL, *inner_map;
	int err;

	union bpf_attr map_attr = {
		.map_type = BPF_MAP_TYPE_HASH_OF_MAPS,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = env->num_prune_points,
		.map_flags = BPF_F_RDONLY,
		.map_name = "oracle_map",
	};
	/* We don't want to use htab_of_maps_map_ops here because it expects map_attr.inner_map_fd
	 * to be set to the fd of inner_map_meta, which we don't have. Instead we can allocate and
	 * set inner_map_meta ourselves.
	 */
	map = htab_map_ops.map_alloc(&map_attr);
	if (IS_ERR(map))
		return map;

	map->ops = &htab_of_maps_map_ops;
	map->map_type = BPF_MAP_TYPE_HASH_OF_MAPS;

	inner_map = alloc_oracle_inner_map_meta();
	if (IS_ERR(inner_map)) {
		err = PTR_ERR(inner_map);
		goto free_map;
	}
	map->inner_map_meta = inner_map;

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

int create_and_populate_oracle_map(struct bpf_verifier_env *env)
{
	struct bpf_map *oracle_map;
	int err;

	if (env->num_prune_points == 0 || env->subprog_cnt > 1)
		return 0;

	oracle_map = create_oracle_map(env);
	if (IS_ERR(oracle_map))
		return PTR_ERR(oracle_map);

	err = __add_used_map(env, oracle_map);
	if (err < 0)
		return err;

	return populate_oracle_map(env, oracle_map);
}

static bool oracle_test_reg(struct bpf_reg_oracle_state *exp, u64 reg)
{
	if (exp->scalar) {
		if (reg < exp->umin_value || reg > exp->umax_value ||
		    (s64)reg < exp->smin_value || (s64)reg > exp->smax_value ||
		    (u32)reg < exp->u32_min_value || (u32)reg > exp->u32_max_value ||
		    (s32)reg < exp->s32_min_value || (s32)reg > exp->s32_max_value ||
		    !tnum_match(exp->var_off, reg))
			return true;
	} else if (exp->ptr_not_null && !reg) {
		return true;
	}
	return false;
}

static bool oracle_test_state(struct bpf_oracle_state *state, u64 *regs, u32 *non_match_regs)
{
	int i;

	for (i = 0; i < MAX_BPF_REG - 1; i++) {
		if (oracle_test_reg(&state->regs[i], regs[i])) {
			*non_match_regs |= 1 << i;
			return true;
		}
	}

	return false;
}

static void format_non_match_regs(u32 non_match_regs, u64 *regs, char *buf)
{
	int i, delta = 0;

	for (i = 0; i < MAX_BPF_REG - 1; i++) {
		if (non_match_regs & (1 << i)) {
			delta += snprintf(buf + delta, REGS_FMT_BUF_LEN - delta, "r%d=%#llx ",
					  i, regs[i]);
		}
	}
}

void oracle_test(struct bpf_map *oracle_states, u64 *regs)
{
	struct bpf_oracle_state *state;
	u32 non_match_regs = 0;
	char regs_fmt[REGS_FMT_BUF_LEN];
	bool expected = false;
	int i;

	for (i = 0; i < oracle_states->max_entries; i++) {
		state = oracle_states->ops->map_lookup_elem(oracle_states, &i);
		if (!oracle_test_state(state, regs, &non_match_regs)) {
			expected = true;
			break;
		}
	}
	if (!expected) {
		format_non_match_regs(non_match_regs, regs, regs_fmt);
		BPF_WARN_ONCE(1, "oracle caught invalid states in oracle_map[id:%d]: %s\n",
			      oracle_states->id, regs_fmt);
	}
}
