// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/slab.h>
#include <linux/bpf_verifier.h>

static bool is_cfg_jump(struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code);
	u8 opcode = BPF_OP(insn->code);

	switch (class) {
	case BPF_JMP:
	case BPF_JMP32:
		return opcode != BPF_CALL;
	default:
		return false;
	}
}

static struct bpf_iarray **compute_predecessors(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_iarray *succ, *preds, **result;
	struct bpf_prog *prog = env->prog;
	u32 *num_preds, i, s, len = prog->len;
	struct bpf_insn *insn;
	size_t sz;
	void *tmp;

	num_preds = kvzalloc_objs(u32, prog->len, BPF_VERIFIER_GFP);
	if (!num_preds)
		return NULL;

	/*
	 * 'result' layout:
	 *  - array of pointers (struct bpf_iarray *)[len]
	 *  - struct bpf_iarray one after another
	 */
	sz = size_mul(len, sizeof(*result) + sizeof(**result));
	for (i = 0; i < len; i++) {
		insn = env->prog->insnsi + i;
		succ = bpf_insn_successors(env, i);
		sz = size_add(sz, array_size(succ->cnt, sizeof(*succ->items)));
		iarray_for_each(s, succ) {
			num_preds[s]++;
		}
		if (bpf_is_ldimm64(insn))
			i++;
	}

	result = kvzalloc(sz, BPF_VERIFIER_GFP);
	if (!result) {
		kvfree(num_preds);
		return NULL;
	}

	tmp = (void *)&result[len];
	for (i = 0; i < len; i++) {
		result[i] = tmp;
		tmp += struct_size(result[i], items, num_preds[i]);
	}

	for (i = 0; i < len; i++) {
		insn = env->prog->insnsi + i;
		succ = bpf_insn_successors(env, i);
		iarray_for_each(s, succ) {
			preds = result[s];
			preds->items[preds->cnt++] = i;
		}
		if (succ->cnt > 1 ||
		    (succ->cnt == 1 && num_preds[succ->items[0]] > 1) ||
		    is_cfg_jump(insn))
			aux[i].bb_end = true;
		if (bpf_is_ldimm64(insn))
			i++;
	}

	kvfree(num_preds);
	return result;
}

static int idoms_intersect(struct bpf_verifier_env *env, int a, int b)
{
	int *postorder_nums = env->cfg.postorder_nums;
	int *idoms = env->idoms;

	while (a != b) {
		while (postorder_nums[a] < postorder_nums[b]) {
			a = idoms[a];
		}
		while (postorder_nums[b] < postorder_nums[a]) {
			b = idoms[b];
		}
	}
	return a;
}

/* An insn. The nodes are in the order of a depth-first walk, node 0 is none. */
struct idom_node {
	u32 insn;
	u32 parent;	/* in the walk */
	u32 semi;	/* semidominator */
	u32 idom;
	u32 up;		/* a parent, or a parent of it, once the node is done */
	u32 min;	/* the node with the lowest 'semi' on the way to 'up' */
	u32 bucket;	/* list of the nodes whose 'semi' this node is */
	u32 next;	/* in that list. Before that the next successor for the walk */
};

/* The node with the lowest 'semi' on the way up from node 'id'. Makes the way short. */
static u32 idom_eval(struct idom_node *nodes, u32 *path, u32 id)
{
	struct idom_node *node, *up;
	u32 cnt = 0, cur;

	for (cur = id; nodes[nodes[cur].up].up; cur = nodes[cur].up)
		path[cnt++] = cur;
	while (cnt--) {
		node = &nodes[path[cnt]];
		up = &nodes[node->up];
		if (nodes[up->min].semi < nodes[node->min].semi)
			node->min = up->min;
		node->up = up->up;
	}
	return nodes[id].min;
}

/*
 * See "A Fast Algorithm for Finding Dominators in a Flowgraph" by Lengauer and Tarjan.
 *
 *   1 -> 2 -> 3 -> 4      walk:          parent[4] = 3
 *   |              ^      from the end:  semi[4] = 1
 *   +-> 5 ---------+      from the top:  idom[4] = 1
 */
int bpf_compute_idoms(struct bpf_verifier_env *env)
{
	u32 len = env->prog->len, cnt = 0, i, insn, id, cur, best, *num, *path;
	struct bpf_iarray **preds, *succ;
	struct idom_node *nodes, *node;
	int err = -ENOMEM;

	preds = compute_predecessors(env);
	env->idoms = kvmalloc_objs(*env->idoms, len, BPF_VERIFIER_GFP);
	nodes = kvzalloc_objs(*nodes, len + 1, BPF_VERIFIER_GFP);
	/* insn -> node */
	num = kvzalloc_objs(*num, 2 * (size_t)len, BPF_VERIFIER_GFP);
	path = num + len;
	if (!preds || !env->idoms || !nodes || !num)
		goto out;
	memset(env->idoms, 0xff, len * sizeof(*env->idoms));

	err = -EINTR;
	for (i = 0; i < env->subprog_cnt; i++) {
		insn = env->subprog_info[i].start;
		for (cur = 0;; insn = succ->items[nodes[cur].next++]) {
			if (!num[insn]) {
				num[insn] = ++cnt;
				nodes[cnt] = (struct idom_node){ insn, cur, cnt, .min = cnt };
				cur = cnt;
			}
			if (bpf_must_abort())
				goto out;
			/* go back to a node that has a successor left */
			for (; cur; cur = nodes[cur].parent) {
				succ = bpf_insn_successors(env, nodes[cur].insn);
				if (nodes[cur].next < succ->cnt)
					break;
			}
			if (!cur)
				break;
		}
	}

	for (id = cnt; id; id--) {
		node = &nodes[id];
		if (!node->parent)
			continue;
		iarray_for_each(insn, preds[node->insn]) {
			if (bpf_must_abort())
				goto out;
			if (!num[insn])
				continue;
			best = idom_eval(nodes, path, num[insn]);
			node->semi = min(node->semi, nodes[best].semi);
		}
		node->next = nodes[node->semi].bucket;
		nodes[node->semi].bucket = id;
		node->up = node->parent;
		for (cur = nodes[node->parent].bucket; cur; cur = nodes[cur].next) {
			best = idom_eval(nodes, path, cur);
			nodes[cur].idom = nodes[best].semi < nodes[cur].semi ? best : node->parent;
		}
		nodes[node->parent].bucket = 0;
	}

	for (id = 1; id <= cnt; id++) {
		node = &nodes[id];
		if (!node->parent)
			continue;
		if (node->idom != node->semi)
			node->idom = nodes[node->idom].idom;
		env->idoms[node->insn] = nodes[node->idom].insn;
	}
	err = 0;
out:
	kvfree(preds);
	kvfree(nodes);
	kvfree(num);
	return err;
}

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

static void add_backedge(struct bpf_verifier_env *env, int from, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop = aux[h].loop;
	int cnt = loop->backedges_cnt;

	if (cnt == MAX_BACKEDGES) {
		loop->backedges_overflow = true;
		return;
	}
	loop->backedges[cnt].from = from;
	loop->backedges_cnt++;
}

static int mark_as_header(struct bpf_verifier_env *env, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;

	if (!aux[h].loop) {
		aux[h].loop = kvzalloc_obj(struct bpf_loop, BPF_VERIFIER_GFP);
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

	err = mark_as_header(env, h);
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

int bpf_loop_at_index(struct bpf_verifier_env *env, u32 idx)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;

	return aux[idx].loop ? idx : aux[idx].loop_header;
}

/*
 * The backedge->from and its latch can reside in an inner loop of @h, e.g.:
 *
 *  1:  r7 += 1;
 *  2:  r6 += 1;
 *      if r7 == 2 goto 1b;
 *      if r6 < 2 goto 2b;
 *
 * For now, let's assume that latches are unknown for such cases.
 * (GCC/LLVM handle this by inserting artificial cfg nodes).
 */
static int find_latch(struct bpf_verifier_env *env, int h, int n)
{
	if (bpf_loop_at_index(env, n) != h || idoms_intersect(env, n, h) != h)
		return -1;
	for (; n >= 0 && !bpf_insn_leaves_loop(env, h, n); n = n == h ? -1 : env->idoms[n])
		bpf_add_cost(env, 1, BPF_COST_SCAN);
	return n;
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
	int s, h, err, cur, stack_sz;
	struct bpf_iarray *succ;

	stack[0] = start;
	state[start].traversed = true;
	state[start].next_succ = 0;
	dfs_pos[start] = 1;
	stack_sz = 1;
	do {
		if (bpf_must_abort())
			return -EINTR;

		cur = stack[stack_sz - 1];
		succ = bpf_insn_successors(env, cur);
		if (state[cur].next_succ == succ->cnt) {
			dfs_pos[cur] = 0;
			stack_sz--;
			continue;
		}
		s = succ->items[state[cur].next_succ];
		if (!state[s].traversed) {
			/* Case A:  start -> ... -> cur -> s [unexplored] */
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
			add_backedge(env, cur, s);
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
			 * but its innermost loop header is.
			 */
			err = assign_header(env, dfs, cur, aux[s].loop_header);
			if (err)
				return err;
		} else {
			/*
			 * case E: 's' is explored, not in current DFS path,
			 * its innermost loop header is not in current DFS path,
			 * hence 's' is another entry into the same loop.
			 */
			h = aux[s].loop_header;
			mark_irreducible(env, h);
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

bool bpf_is_nested_loop(struct bpf_verifier_env *env, int inner_header, int outer_header)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int idx;

	for (idx = inner_header; idx >= 0; idx = aux[idx].loop_header)
		if (aux[idx].loop_header == outer_header)
			return true;

	return false;
}

/* Whether @n is a conditional jump in the loop @h itself that leaves @h */
bool bpf_insn_leaves_loop(struct bpf_verifier_env *env, int h, int n)
{
	struct bpf_insn *insn = &env->prog->insnsi[n];
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);
	int t, f;

	if (bpf_loop_at_index(env, n) != h)
		return false;
	if ((class != BPF_JMP && class != BPF_JMP32) || op == BPF_JA || op == BPF_CALL ||
	    op == BPF_EXIT || op == BPF_JCOND)
		return false;
	t = bpf_loop_at_index(env, n + insn->off + 1);
	f = bpf_loop_at_index(env, n + 1);
	return (t != h && !bpf_is_nested_loop(env, t, h)) ||
	       (f != h && !bpf_is_nested_loop(env, f, h));
}

int bpf_compute_loops(struct bpf_verifier_env *env)
{
	int i, j, s, t, iloop, sloop, err = 0, len = env->prog->len;
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_verifier_log *log = &env->log;
	struct bpf_backedge *backedge;
	struct loops_dfs dfs = {};
	struct bpf_iarray *succ;
	struct bpf_loop *loop;

	dfs.dfs_pos = kvzalloc_objs(int, len, BPF_VERIFIER_GFP);
	dfs.state = kvzalloc_objs(struct dfs_state, len, BPF_VERIFIER_GFP);
	dfs.stack = kvzalloc_objs(int, len, BPF_VERIFIER_GFP);
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
	for (i = 0; i < len; i++) {
		loop = aux[i].loop;
		if (!loop)
			continue;
		loop->exit_to = -1;
		for (j = 0; j < loop->backedges_cnt; j++) {
			loop->backedges[j].latch = find_latch(env, i, loop->backedges[j].from);
		}
	}
	/* find exits */
	for (i = 0; i < len; i++) {
		iloop = aux[i].loop ? i : aux[i].loop_header;
		if (iloop < 0)
			continue;
		succ = bpf_insn_successors(env, i);
		iarray_for_each(s, succ) {
			sloop = bpf_loop_at_index(env, s);
			for (t = iloop; t >= 0 && t != sloop && !bpf_is_nested_loop(env, sloop, t);
			     t = aux[t].loop_header)
				if (aux[t].loop->exit_to < 0)
					aux[t].loop->exit_to = s;
		}
		if (bpf_is_ldimm64(env->prog->insnsi + i))
			i++;
	}

	if (env->log.level & BPF_LOG_LEVEL2) {
		for (i = 0; i < len; i++) {
			loop = aux[i].loop;
			if (!loop)
				continue;
			bpf_log(log, "loop at %d", i);
			if (aux[i].loop_header >= 0)
				bpf_log(log, ", nested in %d", aux[i].loop_header);
			if (loop->irreducible)
				bpf_log(log, ", irreducible");
			bpf_log(log, "\n");
			for (j = 0; j < loop->backedges_cnt; j++) {
				backedge = &loop->backedges[j];
				bpf_log(log, "  backedge from %d", backedge->from);
				if (backedge->latch >= 0)
					bpf_log(log, ", latch at %d", backedge->latch);
				bpf_log(log, "\n");
			}
			if (loop->exit_to >= 0)
				bpf_log(log, "  first exit to %d\n", loop->exit_to);
		}
	}

out:
	kvfree(dfs.dfs_pos);
	kvfree(dfs.stack);
	kvfree(dfs.state);
	return err;
}
