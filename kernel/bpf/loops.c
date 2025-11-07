// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/slab.h>
#include <linux/bpf_verifier.h>

struct dfs_state {
	u32 traversed:1;
	u32 next_succ:31;
};

struct loops_dfs {
	struct dfs_state *state;
	int *dfs_pos;
	int *stack;
};

static void mark_irreducible(struct bpf_verifier_env *env, int h)
{
	env->insn_aux_data[h].loop->irreducible = true;
}

static int mark_header(struct bpf_verifier_env *env, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;

	if (!aux[h].loop) {
		aux[h].loop = kvzalloc_obj(struct bpf_loop, GFP_KERNEL_ACCOUNT);
		if (!aux[h].loop)
			return -ENOMEM;
	}
	return 0;
}

static int assign_header(struct bpf_verifier_env *env, struct loops_dfs *dfs, int n, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int *dfs_pos = dfs->dfs_pos;
	int err, nh;

	err = mark_header(env, h);
	if (err)
		return err;

	/* Don't encode self-loops, otherwise can't reflect loops nesting structure. */
	if (n == h)
		return 0;

	/* Make sure that loop headers up the chain are sorted by dfs_pos. */
	while (aux[n].loop_header != -1) {
		nh = aux[n].loop_header;
		if (nh == h)
			return 0;
		if (dfs_pos[nh] < dfs_pos[h]) {
			aux[n].loop_header = h;
			n = h;
			h = nh;
		} else {
			n = nh;
		}
	}
	aux[n].loop_header = h;
	return 0;
}

/*
 * As described in "A New Algorithm for Identifying Loops in Decompilation" by Wei et al,
 * adapted to be non-recursive.
 */
static int compute_loops_in_subprog(struct bpf_verifier_env *env, struct loops_dfs *dfs,
				    int subprog_idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct dfs_state *state = dfs->state;
	int start = env->subprog_info[subprog_idx].start;
	int *dfs_pos = dfs->dfs_pos;
	int *stack = dfs->stack;
	int i, s, h, err, cur, stack_sz;
	struct bpf_iarray *succ;

	stack[0] = start;
	state[start].traversed = true;
	state[start].next_succ = 0;
	dfs_pos[start] = 1;
	stack_sz = 1;
	i = 0;
	do {
		/*
		 * The algorithm should be very fast in practice,
		 * guard against pathological inputs, just in case.
		 */
		if (i++ == 1024) {
			i = 0;
			if (signal_pending(current))
				return -EAGAIN;
			cond_resched();
		}

		cur = stack[stack_sz - 1];
		succ = bpf_insn_successors(env, cur);
		if (state[cur].next_succ == succ->cnt) {
			dfs_pos[cur] = 0;
			stack_sz--;
			continue;
		}
		s = succ->items[state[cur].next_succ];
		if (!state[s].traversed) {
			/* Case A:  start -> ... -> cur -> s [unxplored] */
			state[s].traversed = true;
			state[s].next_succ = 0;
			stack[stack_sz] = s;
			dfs_pos[s] = stack_sz + 1;
			stack_sz++;
			continue;
		}
		/* 's' is fully explored at this point */
		if (dfs_pos[s]) {
			/*
			 * start -> ... -> s -> cur --.
			 *                 ^          |
			 *                 '----------'
			 * Case B: 's' is in the current DFS path.
			 */
			err = assign_header(env, dfs, cur, s);
			if (err)
				return err;
		} else if (aux[s].loop_header == -1) {
			/*
			 * start -> ... -> ... -> s -> ... -> end
			 *           |            ^
			 *           '---> cur ---'
			 * Case C: 's' is explored, not in the current DFS path,
			 * and not a part of any loop.
			 */
		} else if (dfs_pos[aux[s].loop_header]) {
			/*
			 *                 .----------------------.
			 *                 v                      |
			 * start -> ... -> h -> ... -> ... -> s --'
			 *                       |            ^
			 *	                 '---> cur ---'
			 * Case D: 's' is explored, not in current DFS path,
			 * but it's innermost loop header is.
			 */
			err = assign_header(env, dfs, cur, aux[s].loop_header);
			if (err)
				return err;
		} else {
			/* case E */
			h = aux[s].loop_header;
			mark_irreducible(env, h);
			/* can also mark 's' as reentry, but no need for now */
			while (aux[h].loop_header != -1) {
				h = aux[h].loop_header;
				if (dfs_pos[h]) {
					err = assign_header(env, dfs, cur, h);
					if (err)
						return err;
					break;
				}
				mark_irreducible(env, h);
			}
		}
		state[cur].next_succ++;
	} while (stack_sz);

	return 0;
}

int bpf_compute_loops(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, err = 0, len = env->prog->len;
	struct loops_dfs dfs = {};

	dfs.dfs_pos = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	dfs.state = kvcalloc(len, sizeof(struct dfs_state), GFP_KERNEL_ACCOUNT);
	dfs.stack = kvcalloc(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	if (!dfs.dfs_pos || !dfs.state || !dfs.stack) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < len; i++)
		aux[i].loop_header = -1;
	for (i = 0; i < env->subprog_cnt; i++) {
		err = compute_loops_in_subprog(env, &dfs, i);
		if (err)
			goto out;
	}

out:
	kvfree(dfs.dfs_pos);
	kvfree(dfs.stack);
	kvfree(dfs.state);
	return err;
}
