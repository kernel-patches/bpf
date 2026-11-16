// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/hash.h>
#include <linux/sort.h>

#include "diagnostics.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

#define BPF_MAX_GOTOX_EDGES	BPF_COMPLEXITY_LIMIT_INSNS

/* non-recursive DFS pseudo code
 * 1  procedure DFS-iterative(G,v):
 * 2      label v as discovered
 * 3      let S be a stack
 * 4      S.push(v)
 * 5      while S is not empty
 * 6            t <- S.peek()
 * 7            if t is what we're looking for:
 * 8                return t
 * 9            for all edges e in G.adjacentEdges(t) do
 * 10               if edge e is already labelled
 * 11                   continue with the next edge
 * 12               w <- G.adjacentVertex(t,e)
 * 13               if vertex w is not discovered and not explored
 * 14                   label e as tree-edge
 * 15                   label w as discovered
 * 16                   S.push(w)
 * 17                   continue at 5
 * 18               else if vertex w is discovered
 * 19                   label e as back-edge
 * 20               else
 * 21                   // vertex w is explored
 * 22                   label e as forward- or cross-edge
 * 23           label t as explored
 * 24           S.pop()
 *
 * convention:
 * 0x10 - discovered
 * 0x11 - discovered and fall-through edge labelled
 * 0x12 - discovered and fall-through and branch edges labelled
 * 0x20 - explored
 */

enum {
	DISCOVERED = 0x10,
	EXPLORED = 0x20,
	FALLTHROUGH = 1,
	BRANCH = 2,
};

enum {
	DONE_EXPLORING = 0,
	KEEP_EXPLORING = 1,
};

/* t, w, e - match pseudo-code above:
 * t - index of current instruction
 * w - next instruction
 * e - edge
 */
static int push_insn(int t, int w, int e, struct bpf_verifier_env *env)
{
	int *insn_stack = env->cfg.insn_stack;
	int *insn_state = env->cfg.insn_state;

	if (e == FALLTHROUGH && insn_state[t] >= (DISCOVERED | FALLTHROUGH))
		return DONE_EXPLORING;

	if (e == BRANCH && insn_state[t] >= (DISCOVERED | BRANCH))
		return DONE_EXPLORING;

	if (w < 0 || w >= env->prog->len) {
		verbose_linfo(env, t, "%d: ", t);
		verbose(env, "jump out of range from insn %d to %d\n", t, w);
		bpf_diag_program_structure(
			env, t, "jump out of range", "Keep branch targets inside the program.",
			"Instruction %d jumps to instruction %d, but the program only contains instructions 0 through %d.",
			t, w, env->prog->len - 1);
		return -EINVAL;
	}

	if (e == BRANCH)
		mark_jump_target(env, w);

	if (insn_state[w] == 0) {
		/* tree-edge */
		insn_state[t] = DISCOVERED | e;
		insn_state[w] = DISCOVERED;
		if (env->cfg.cur_stack >= env->prog->len)
			return -E2BIG;
		insn_stack[env->cfg.cur_stack++] = w;
		return KEEP_EXPLORING;
	} else if ((insn_state[w] & 0xF0) == DISCOVERED) {
		if (env->bpf_capable)
			return DONE_EXPLORING;
		verbose_linfo(env, t, "%d: ", t);
		verbose_linfo(env, w, "%d: ", w);
		verbose(env, "back-edge from insn %d to %d\n", t, w);
		bpf_diag_program_structure(
			env, t, "back-edge is not allowed",
			"Load with privileges that allow this back-edge, or rewrite the control flow so it does not branch backward.",
			"Instruction %d branches back to instruction %d. This program is being rejected without the privilege needed for this back-edge.",
			t, w);
		return -EINVAL;
	} else if (insn_state[w] == EXPLORED) {
		/* forward- or cross-edge */
		insn_state[t] = DISCOVERED | e;
	} else {
		verifier_bug(env, "insn state internal bug");
		return -EFAULT;
	}
	return DONE_EXPLORING;
}

static int visit_func_call_insn(int t, struct bpf_insn *insns,
				struct bpf_verifier_env *env,
				bool visit_callee)
{
	int ret, insn_sz;

	insn_sz = bpf_is_ldimm64(&insns[t]) ? 2 : 1;
	ret = push_insn(t, t + insn_sz, FALLTHROUGH, env);
	if (ret)
		return ret;

	return visit_callee ? push_insn(t, t + insns[t].imm + 1, BRANCH, env) : 0;
}

struct bpf_iarray *bpf_iarray_realloc(struct bpf_iarray *old, size_t n_elem)
{
	size_t new_size = sizeof(struct bpf_iarray) + n_elem * sizeof(old->items[0]);
	struct bpf_iarray *new;

	new = kvrealloc(old, new_size, BPF_VERIFIER_GFP);
	if (!new) {
		/* this is what callers always want, so simplify the call site */
		kvfree(old);
		return NULL;
	}

	new->cnt = n_elem;
	return new;
}

static struct bpf_index_slot *index_slot(const struct bpf_index *index, u64 key)
{
	u32 i = hash_64(key, index->bits);

	while (index->slots[i].next_val && index->slots[i].key != key)
		i = (i + 1) & (BIT(index->bits) - 1);
	return &index->slots[i];
}

/* Returns the value of 'key', -1 if there is none */
int bpf_index_find(const struct bpf_index *index, u64 key)
{
	return index->cnt ? index_slot(index, key)->next_val - 1 : -1;
}

/* 'key' is new. At most a half of the slots is taken. */
int bpf_index_add(struct bpf_index *index, u64 key, u32 val)
{
	struct bpf_index old = *index;
	u32 i;

	if (2 * old.cnt >= BIT(old.bits) - 1) {
		index->slots = kvcalloc(BIT(old.bits + 2), sizeof(*old.slots), BPF_VERIFIER_GFP);
		if (!index->slots) {
			index->slots = old.slots;
			return -ENOMEM;
		}
		index->bits += 2;
		for (i = 0; old.cnt && i < BIT(old.bits); i++)
			if (old.slots[i].next_val)
				*index_slot(index, old.slots[i].key) = old.slots[i];
		kvfree(old.slots);
	}
	*index_slot(index, key) = (struct bpf_index_slot){ key, val + 1 };
	index->cnt++;
	return 0;
}

int bpf_call_graph_init(struct bpf_call_graph *cg, u32 cnt)
{
	*cg = (struct bpf_call_graph){ .cnt = cnt };
	/* the last 4 parts are for bpf_call_graph_sort() */
	cg->first = kvcalloc(8 * (size_t)cnt + 1, sizeof(u32), BPF_VERIFIER_GFP);
	cg->marks = kvcalloc(cnt, sizeof(u16), BPF_VERIFIER_GFP);
	if (!cg->first || !cg->marks)
		return -ENOMEM;
	cg->postorder = cg->first + cnt + 1;
	cg->order = cg->postorder + cnt;
	cg->cycle = cg->order + cnt;
	return 0;
}

void bpf_call_graph_free(struct bpf_call_graph *cg)
{
	kvfree(cg->first);
	kvfree(cg->callee);
	kvfree(cg->marks);
}

/* Callers come in increasing order */
int bpf_call_graph_add(struct bpf_call_graph *cg, u32 caller, u32 callee)
{
	if (WARN_ON_ONCE(callee >= cg->cnt))
		return -EFAULT;
	if (!bpf_table_next(cg->callee, cg->edge_cnt))
		return -ENOMEM;
	while (cg->next <= caller)
		cg->first[cg->next++] = cg->edge_cnt;
	cg->callee[cg->edge_cnt++] = callee;
	return 0;
}

/*
 * Tarjan's algorithm. Calls of the nodes that have a mark in 'skip' do not count.
 *
 *   main -> f1 -> f2 -> f3      postorder:  f3 f2 f1 main
 *           ^     |             order:      f3 f2 f1 main    callees first, a cycle in a row
 *           +-----+             cycle:      0  1  1  3       where the cycle starts in 'order'
 */
void bpf_call_graph_sort(struct bpf_call_graph *cg, u16 skip)
{
	u32 cnt = cg->cnt, *low = cg->cycle + cnt, *edge = low + cnt, *path = edge + cnt;
	u32 *open = path + cnt, depth = 0, top = 0, num = 0, done = 0, post = 0, i, s, j;

	while (cg->next <= cnt)
		cg->first[cg->next++] = cg->edge_cnt;
	/* low: 0 - not visited, U32_MAX - is in 'order' */
	memset(low, 0, cnt * sizeof(*low));
	for (i = 0; i < cnt; i++) {
		if (!low[i])
			path[depth++] = i;
		while (depth) {
			s = path[depth - 1];
			if (!low[s]) {
				/* until the node is in 'order': its number */
				low[s] = cg->cycle[s] = ++num;
				edge[s] = cg->first[s];
				open[top++] = s;
			}
			if (edge[s] < cg->first[s + 1]) {
				j = cg->callee[edge[s]];
				if (cg->marks[j] & skip) {
					edge[s]++;
				} else if (!low[j]) {
					path[depth++] = j;
				} else {
					low[s] = min(low[s], low[j]);
					edge[s]++;
				}
				continue;
			}
			depth--;
			cg->postorder[post++] = s;
			if (low[s] != cg->cycle[s])
				continue;
			for (j = done; low[s] != U32_MAX; done++) {
				cg->order[done] = open[--top];
				cg->cycle[open[top]] = j;
				low[open[top]] = U32_MAX;
			}
		}
	}
}

bool bpf_call_graph_recursive(const struct bpf_call_graph *cg, u32 s)
{
	u32 j;

	bpf_for_each_callee(cg, s, j)
		if (cg->cycle[j] == cg->cycle[s])
			return true;
	return false;
}

/* What a node has of 'mask', all nodes that it gets to have */
void bpf_call_graph_mark_callees(struct bpf_call_graph *cg, u16 mask)
{
	u32 start, end, i, j;
	u16 m;

	for (end = cg->cnt; end; end = start) {
		start = cg->cycle[cg->order[end - 1]];
		for (i = start, m = 0; i < end; i++)
			m |= cg->marks[cg->order[i]] & mask;
		for (i = start; i < end; i++)
			bpf_for_each_callee(cg, cg->order[i], j)
				cg->marks[j] |= m;
	}
}

/* What a node has of 'mask', all nodes that get to it have. 'skip' is that of the sort. */
void bpf_call_graph_mark_callers(struct bpf_call_graph *cg, u16 mask, u16 skip)
{
	u32 start, end, j;
	u16 m;

	for (start = 0; start < cg->cnt; start = end) {
		for (end = start, m = 0; end < cg->cnt && cg->cycle[cg->order[end]] == start; end++)
			bpf_for_each_callee(cg, cg->order[end], j)
				if (!(cg->marks[j] & skip))
					m |= cg->marks[j] & mask;
		for (j = start; j < end; j++)
			cg->marks[cg->order[j]] |= m;
	}
}

static int copy_insn_array(struct bpf_map *map, u32 start, u32 end, u32 *items)
{
	struct bpf_insn_array_value *value;
	u32 i;

	for (i = start; i <= end; i++) {
		value = map->ops->map_lookup_elem(map, &i);
		/*
		 * map_lookup_elem of an array map will never return an error,
		 * but not checking it makes some static analysers to worry
		 */
		if (IS_ERR(value))
			return PTR_ERR(value);
		else if (!value)
			return -EINVAL;
		items[i - start] = value->xlated_off;
	}
	return 0;
}

static int cmp_ptr_to_u32(const void *a, const void *b)
{
	return *(u32 *)a - *(u32 *)b;
}

static int sort_insn_array_uniq(u32 *items, int cnt)
{
	int unique = 1;
	int i;

	sort(items, cnt, sizeof(items[0]), cmp_ptr_to_u32, NULL);

	for (i = 1; i < cnt; i++)
		if (items[i] != items[unique - 1])
			items[unique++] = items[i];

	return unique;
}

/*
 * sort_unique({map[start], ..., map[end]}) into off
 */
int bpf_copy_insn_array_uniq(struct bpf_map *map, u32 start, u32 end, u32 *off)
{
	u32 n = end - start + 1;
	int err;

	err = copy_insn_array(map, start, end, off);
	if (err)
		return err;

	return sort_insn_array_uniq(off, n);
}

/*
 * Copy all unique offsets from the map
 */
static struct bpf_iarray *jt_from_map(struct bpf_map *map)
{
	struct bpf_iarray *jt;
	int err;
	int n;

	jt = bpf_iarray_realloc(NULL, map->max_entries);
	if (!jt)
		return ERR_PTR(-ENOMEM);

	n = bpf_copy_insn_array_uniq(map, 0, map->max_entries - 1, jt->items);
	if (n < 0) {
		err = n;
		goto err_free;
	}
	if (n == 0) {
		err = -EINVAL;
		goto err_free;
	}
	jt->cnt = n;
	return jt;

err_free:
	kvfree(jt);
	return ERR_PTR(err);
}

/*
 * Collect the jump table of every subprogram that has one, as the combined
 * table of all maps whose targets land inside that subprogram. All gotox
 * instructions of a subprogram share the same table, so this is done in a
 * single pass over the maps rather than once per gotox.
 */
static int __compute_subprog_jts(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog;
	struct bpf_iarray *jt, *jt_cur;
	struct bpf_map *map;
	u32 old_cnt;
	int i;

	for (i = 0; i < env->insn_array_map_cnt; i++) {
		/*
		 * TODO (when needed): collect only jump tables, not static keys
		 * or maps for indirect calls
		 */
		map = env->insn_array_maps[i];

		jt_cur = jt_from_map(map);
		if (IS_ERR(jt_cur))
			return PTR_ERR(jt_cur);

		subprog = bpf_find_containing_subprog(env, jt_cur->items[0]);
		if (verifier_bug_if(!subprog, env, "no subprog contains insn %u of an insn array map",
				    jt_cur->items[0])) {
			kvfree(jt_cur);
			return -EFAULT;
		}
		if (jt_cur->items[jt_cur->cnt - 1] >= (subprog + 1)->start) {
			verbose(env, "jump table of subprog starting at %u spans multiple subprogs, map id=%d\n",
				subprog->start, map->id);
			bpf_diag_program_structure(
				env, subprog->start, "jump table spans subprograms",
				"Keep every entry of a jump table inside one subprogram.",
				"The jump table in map id %d for the subprogram that starts at instruction %u reaches past its end at instruction %u.",
				map->id, subprog->start, (subprog + 1)->start);
			kvfree(jt_cur);
			return -EINVAL;
		}

		old_cnt = subprog->jt ? subprog->jt->cnt : 0;
		jt = bpf_iarray_realloc(subprog->jt, roundup_pow_of_two(old_cnt + jt_cur->cnt));
		if (!jt) {
			subprog->jt = NULL;
			kvfree(jt_cur);
			return -ENOMEM;
		}
		memcpy(jt->items + old_cnt, jt_cur->items, jt_cur->cnt << 2);
		jt->cnt = old_cnt + jt_cur->cnt;
		subprog->jt = jt;

		kvfree(jt_cur);
	}

	for (i = 0; i < env->subprog_cnt; i++) {
		jt = env->subprog_info[i].jt;
		if (jt)
			jt->cnt = sort_insn_array_uniq(jt->items, jt->cnt);
	}

	env->cfg.subprog_jts_ready = true;
	return 0;
}

/* Leave nothing behind on failure. */
static int compute_subprog_jts(struct bpf_verifier_env *env)
{
	int err;

	err = __compute_subprog_jts(env);
	if (err)
		bpf_free_subprog_jts(env);
	return err;
}

void bpf_free_subprog_jts(struct bpf_verifier_env *env)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(env->subprog_info); i++) {
		kvfree(env->subprog_info[i].jt);
		env->subprog_info[i].jt = NULL;
	}
	env->cfg.subprog_jts_ready = false;
}

static struct bpf_iarray *
subprog_jt(int t, struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *subprog;
	int subprog_start, err;

	if (!env->cfg.subprog_jts_ready) {
		err = compute_subprog_jts(env);
		if (err)
			return ERR_PTR(err);
	}

	subprog = bpf_find_containing_subprog(env, t);
	if (verifier_bug_if(!subprog, env, "no subprog contains insn %d", t))
		return ERR_PTR(-EFAULT);
	subprog_start = subprog->start;

	if (!subprog->jt) {
		verbose(env, "no jump tables found for subprog starting at %u\n", subprog_start);
		bpf_diag_program_structure(
			env, t, "missing jump table",
			"Make sure subprograms containing gotox instructions are accompanied by jump tables referencing these subprograms.",
			"No jump table was found for the subprogram that starts at instruction %u.",
			subprog_start);
		return ERR_PTR(-EINVAL);
	}

	return subprog->jt;
}

/* "conditional jump with N edges" */
static int visit_gotox_insn(int t, struct bpf_verifier_env *env)
{
	int *insn_stack = env->cfg.insn_stack;
	int *insn_state = env->cfg.insn_state;
	bool keep_exploring = false;
	struct bpf_iarray *jt;
	int i, w;

	/*
	 * The first visit pushes every target that still needs exploring, and
	 * those are all done by the time this insn is revisited, so there is
	 * nothing left to walk the jump table for.
	 */
	if (insn_state[t] & BRANCH)
		return DONE_EXPLORING;

	jt = subprog_jt(t, env);
	if (IS_ERR(jt))
		return PTR_ERR(jt);

	insn_state[t] |= BRANCH;

	if (check_add_overflow(env->cfg.gotox_edges, jt->cnt,
			       &env->cfg.gotox_edges) ||
	    env->cfg.gotox_edges > BPF_MAX_GOTOX_EDGES) {
		verbose(env, "number of indirect jump edges in the program exceeds %u\n",
			BPF_MAX_GOTOX_EDGES);
		bpf_diag_program_structure(
			env, t, "too many indirect jump edges",
			"Reduce the number of indirect jumps, or the number of distinct targets they can reach.",
			"The program has more than %u indirect jump edges in total, counted over every gotox instruction.",
			BPF_MAX_GOTOX_EDGES);
		return -E2BIG;
	}

	for (i = 0; i < jt->cnt; i++) {
		w = jt->items[i];
		if (verifier_bug_if(w < 0 || w >= env->prog->len, env,
				    "indirect jump from insn %d to %d out of range", t, w))
			return -EFAULT;

		mark_jump_target(env, w);

		/* EXPLORED || DISCOVERED */
		if (insn_state[w])
			continue;

		if (env->cfg.cur_stack >= env->prog->len)
			return -E2BIG;

		insn_stack[env->cfg.cur_stack++] = w;
		insn_state[w] |= DISCOVERED;
		keep_exploring = true;
	}

	return keep_exploring ? KEEP_EXPLORING : DONE_EXPLORING;
}

enum {
	CHANGES_PKT_DATA = BIT(0),
	MIGHT_SLEEP	 = BIT(1),
	MIGHT_THROW	 = BIT(2),
};

/*
 * A subprog does what its callees do. The load of the address of a function counts as a call.
 * So does the load of the address of a map with pointers to functions:
 *
 *   f1: r1 = map ll  --+
 *                      +--> node of the map --> all functions in the map
 *   f2: r1 = map ll  --+
 */
static int merge_callee_effects(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *si = env->subprog_info;
	struct bpf_insn *insn = env->prog->insnsi;
	u32 cnt = env->subprog_cnt, n, s, t;
	struct bpf_call_graph cg;
	struct bpf_func_ptr *ptr;
	int err;

	err = bpf_call_graph_init(&cg, cnt + env->used_map_cnt);
	for (s = 0; s < cnt && !err; s++) {
		cg.marks[s] = (si[s].changes_pkt_data ? CHANGES_PKT_DATA : 0) |
			      (si[s].might_sleep ? MIGHT_SLEEP : 0) |
			      (si[s].might_throw ? MIGHT_THROW : 0);
		for (t = si[s].start; t < si[s + 1].start && !err; t++) {
			if (bpf_pseudo_call(&insn[t]) || bpf_pseudo_func(&insn[t]))
				err = bpf_call_graph_add(&cg, s, bpf_find_subprog(env,
							 t + insn[t].imm + 1));
			else if (bpf_is_ldimm64(&insn[t]) && insn[t].src_reg &&
				 insn[t].src_reg != BPF_PSEUDO_BTF_ID)
				err = bpf_call_graph_add(&cg, s,
							 cnt + env->insn_aux_data[t].map_index);
		}
	}
	for (s = 0; s < env->used_map_cnt; s++) {
		ptr = bpf_map_func_ptrs(env, env->used_maps[s], &n);
		for (; n-- && !err; ptr++)
			err = bpf_must_abort() ? -EINTR :
			      bpf_call_graph_add(&cg, cnt + s,
						 bpf_find_subprog(env, ptr->xlated_off));
	}
	if (err)
		goto out;
	bpf_call_graph_sort(&cg, 0);
	bpf_call_graph_mark_callers(&cg, U16_MAX, 0);
	for (s = 0; s < cnt; s++) {
		si[s].changes_pkt_data = cg.marks[s] & CHANGES_PKT_DATA;
		si[s].might_sleep = cg.marks[s] & MIGHT_SLEEP;
		si[s].might_throw = cg.marks[s] & MIGHT_THROW;
	}
out:
	bpf_call_graph_free(&cg);
	return err;
}

/* Visits the instruction at index t and returns one of the following:
 *  < 0 - an error occurred
 *  DONE_EXPLORING - the instruction was fully explored
 *  KEEP_EXPLORING - there is still work to be done before it is fully explored
 */
static int visit_insn(int t, struct bpf_verifier_env *env)
{
	struct bpf_insn *insns = env->prog->insnsi, *insn = &insns[t];
	struct bpf_subprog_info *sub;
	int ret, off, insn_sz;

	if (bpf_pseudo_func(insn))
		return visit_func_call_insn(t, insns, env, true);

	/* All non-branch instructions have a single fall-through edge. */
	if (BPF_CLASS(insn->code) != BPF_JMP &&
	    BPF_CLASS(insn->code) != BPF_JMP32) {
		insn_sz = bpf_is_ldimm64(insn) ? 2 : 1;
		return push_insn(t, t + insn_sz, FALLTHROUGH, env);
	}

	switch (BPF_OP(insn->code)) {
	case BPF_EXIT:
		return DONE_EXPLORING;

	case BPF_CALL:
		/* For functions that invoke callbacks it is not known how many times
		 * callback would be called. Verifier models callback calling functions
		 * by repeatedly visiting callback bodies and returning to origin call
		 * instruction.
		 */
		if (bpf_is_sync_callback_calling_insn(insn))
			mark_calls_callback(env, t);
		sub = bpf_find_containing_subprog(env, t);
		if (bpf_helper_call(insn)) {
			const struct bpf_func_proto *fp;

			ret = bpf_get_helper_proto(env, insn->imm, &fp);
			/* If called in a non-sleepable context program will be
			 * rejected anyway, so we should end up with precise
			 * sleepable marks on subprogs, except for dead code
			 * elimination.
			 */
			if (ret == 0 && fp->might_sleep)
				sub->might_sleep = true;
			/* nobody knows yet whether the dynptr is that of an skb */
			if (bpf_helper_changes_pkt_data(insn->imm) ||
			    insn->imm == BPF_FUNC_dynptr_write)
				sub->changes_pkt_data = true;
		} else if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL) {
			struct bpf_call_arg_meta meta;

			ret = bpf_fetch_kfunc_arg_meta(env, insn->imm, insn->off, &meta);
			/* Same as helpers, if called in a non-sleepable context
			 * program will be rejected anyway, so we should end up
			 * with precise sleepable marks on subprogs, except for
			 * dead code elimination.
			 */
			if (ret == 0 && bpf_is_kfunc_sleepable(&meta))
				sub->might_sleep = true;
			if (ret == 0 && bpf_is_kfunc_pkt_changing(&meta))
				sub->changes_pkt_data = true;
			if (ret == 0 && bpf_is_throw_kfunc(insn))
				sub->might_throw = true;
		}
		return visit_func_call_insn(t, insns, env, insn->src_reg == BPF_PSEUDO_CALL);

	case BPF_JA:
		if (BPF_SRC(insn->code) == BPF_X)
			return visit_gotox_insn(t, env);

		if (BPF_CLASS(insn->code) == BPF_JMP)
			off = insn->off;
		else
			off = insn->imm;

		/* unconditional jump with single edge */
		ret = push_insn(t, t + off + 1, FALLTHROUGH, env);
		if (ret)
			return ret;

		mark_jump_target(env, t + off + 1);

		return ret;

	default:
		/* conditional jump with two edges */
		ret = push_insn(t, t + 1, FALLTHROUGH, env);
		if (ret)
			return ret;

		return push_insn(t, t + insn->off + 1, BRANCH, env);
	}
}

/* non-recursive depth-first-search to detect loops in BPF program
 * loop == back-edge in directed graph
 */
int bpf_check_cfg(struct bpf_verifier_env *env)
{
	int insn_cnt = env->prog->len;
	int *insn_stack, *insn_state;
	int i, root, ret = 0;
	u32 ptr = 0;

	insn_state = env->cfg.insn_state = kvzalloc_objs(int, insn_cnt,
							 BPF_VERIFIER_GFP);
	if (!insn_state)
		return -ENOMEM;

	insn_stack = env->cfg.insn_stack = kvzalloc_objs(int, insn_cnt,
							 BPF_VERIFIER_GFP);
	if (!insn_stack) {
		kvfree(insn_state);
		return -ENOMEM;
	}

	root = 0; /* 0 is the first instruction */
walk_cfg:
	insn_state[root] = DISCOVERED;
	insn_stack[0] = root;
	env->cfg.cur_stack = 1;

	while (env->cfg.cur_stack > 0) {
		int t = insn_stack[env->cfg.cur_stack - 1];

		ret = bpf_must_abort() ? -EINTR : visit_insn(t, env);
		switch (ret) {
		case DONE_EXPLORING:
			insn_state[t] = EXPLORED;
			env->cfg.cur_stack--;
			break;
		case KEEP_EXPLORING:
			break;
		default:
			if (ret > 0) {
				verifier_bug(env, "visit_insn internal bug");
				ret = -EFAULT;
			}
			goto err_free;
		}
	}

	if (env->cfg.cur_stack < 0) {
		verifier_bug(env, "pop stack internal bug");
		ret = -EFAULT;
		goto err_free;
	}

	root = env->subprog_info[env->exception_callback_subprog].start;
	if (insn_state[root] != EXPLORED)
		goto walk_cfg;

	/* callx can call what the maps point to */
	while (ptr < env->func_ptr_cnt) {
		root = env->func_ptrs[ptr++].xlated_off;
		mark_jump_target(env, root);
		if (insn_state[root] != EXPLORED)
			goto walk_cfg;
	}

	for (i = 0; i < insn_cnt; i++) {
		struct bpf_insn *insn = &env->prog->insnsi[i];

		if (insn_state[i] != EXPLORED) {
			verbose(env, "unreachable insn %d\n", i);
			bpf_diag_program_structure(
				env, i, "unreachable instruction",
				"Remove the unreachable instruction or add valid control flow that reaches it.",
				"Instruction %d is not reachable from the program entry point.", i);
			ret = -EINVAL;
			goto err_free;
		}
		if (bpf_is_ldimm64(insn)) {
			if (insn_state[i + 1] != 0) {
				verbose(env, "jump into the middle of ldimm64 insn %d\n", i);
				bpf_diag_program_structure(
					env, i, "jump into ldimm64 immediate",
					"Target the first instruction of the ldimm64 pair, or restructure the jump target.",
					"Control flow reaches the second half of the ldimm64 instruction pair that starts at instruction %d.",
					i);
				ret = -EINVAL;
				goto err_free;
			}
			i++; /* skip second half of ldimm64 */
		}
	}
	/* cfg looks good */
	ret = merge_callee_effects(env);
	env->prog->aux->changes_pkt_data = env->subprog_info[0].changes_pkt_data;
	env->prog->aux->might_sleep = env->subprog_info[0].might_sleep;

err_free:
	kvfree(insn_state);
	kvfree(insn_stack);
	env->cfg.insn_state = env->cfg.insn_stack = NULL;
	return ret;
}

struct dfs_state {
	u32 traversed:1;
	u32 next_succ:31;
};

/*
 * For each subprogram 'i' fill array env->cfg.insn_subprogram sub-range
 * [env->subprog_info[i].postorder_start, env->subprog_info[i+1].postorder_start)
 * with indices of 'i' instructions in postorder.
 */
int bpf_compute_postorder(struct bpf_verifier_env *env)
{
	int *stack = NULL, *postorder = NULL, *postorder_nums = NULL;
	int subprog_idx, stack_sz, cur, s, cur_postorder, start;
	struct dfs_state *state = NULL;
	struct bpf_iarray *succ = NULL;

	postorder_nums = kvzalloc_objs(int, env->prog->len, BPF_VERIFIER_GFP);
	postorder = kvzalloc_objs(int, env->prog->len, BPF_VERIFIER_GFP);
	stack = kvzalloc_objs(int, env->prog->len, BPF_VERIFIER_GFP);
	state = kvzalloc_objs(struct dfs_state, env->prog->len, BPF_VERIFIER_GFP);
	if (!postorder_nums || !postorder || !stack || !state) {
		kvfree(postorder_nums);
		kvfree(postorder);
		kvfree(stack);
		kvfree(state);
		return -ENOMEM;
	}
	cur_postorder = 0;
	for (subprog_idx = 0; subprog_idx < env->subprog_cnt; subprog_idx++) {
		start = env->subprog_info[subprog_idx].start;
		env->subprog_info[subprog_idx].postorder_start = cur_postorder;
		stack[0] = start;
		stack_sz = 1;
		state[start].traversed = true;
		do {
			cur = stack[stack_sz - 1];
			succ = bpf_insn_successors(env, cur);
			if (state[cur].next_succ == succ->cnt) {
				postorder_nums[cur] = cur_postorder;
				postorder[cur_postorder] = cur;
				cur_postorder++;
				stack_sz--;
				continue;
			}
			s = succ->items[state[cur].next_succ];
			if (!state[s].traversed) {
				state[s].traversed = true;
				state[s].next_succ = 0;
				stack[stack_sz] = s;
				stack_sz++;
				continue;
			}
			state[cur].next_succ++;
		} while (stack_sz);
	}
	env->subprog_info[subprog_idx].postorder_start = cur_postorder;
	env->cfg.postorder_nums = postorder_nums;
	env->cfg.insn_postorder = postorder;
	env->cfg.cur_postorder = cur_postorder;
	kvfree(stack);
	kvfree(state);
	return 0;
}
