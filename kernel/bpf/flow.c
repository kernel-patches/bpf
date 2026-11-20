// SPDX-License-Identifier: GPL-2.0-only
/*
 * The main pass of the verifier. It is a fixpoint over the control flow graph.
 *
 *              +---------+   next    +-------------------+
 *        +---->| pending |---------->| check basic block |
 *        |     +---------+           +---------+---------+
 *        | new                                 v
 *        |                           +-------------------+   subsumed
 *        +---------------------------|    join point     |------------> prune
 *          joined, or kept apart     +-------------------+
 *
 * A state that arrives is compared with the states that have the same join_key, see
 * flow_prune_or_join(). The order of pending states completes a loop before the code that
 * follows it, see flow_compute_order(). The check of a function ends when nothing is pending.
 *
 * Loops. The peeled trips are kept apart. The leftover stands for all later trips. A state
 * that comes back to the header of the leftover is joined and widened.
 *
 * Functions. A static function can get only numbers and pointers that are not to the stack.
 * Then it is verified on its own: once for each instance, not for each chain of calls.
 * The call waits, see bpf_flow_call().
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/interval_tree_generic.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

#include "diagnostics.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

enum flow_kind {
	FLOW_AT,		/* before the insn */
	FLOW_AGAIN,		/* the same, it meets no state */
	FLOW_LEFTOVER,		/* about to start the leftover of the loop */
	FLOW_PEELED,		/* started an earlier peeled trip, see flow_prune_peeled() */
	FLOW_FUNC_ENTRY,	/* starts an instance */
	FLOW_JOINED_CALLS,	/* the same, for all numbers, see flow_may_add_instance() */
	FLOW_FUNC_EXIT,		/* came out of an instance */
};

struct flow_state {
	struct bpf_verifier_state st;
	struct rb_node tree_node;	/* see flow_find() */
	u64 hash, first, last, subtree_last;
	/* in a list of its instance, or in waiting_calls of @callee */
	struct list_head node;
	struct flow_instance *started_instance;	/* FLOW_FUNC_ENTRY */
	struct flow_instance *callee;	/* of a call */
	struct rb_node rb;		/* pending states */
	int prev_insn_idx;
	u64 log_pos, diag_pos;		/* the logs have the path up to there */
	u32 seq;
	u32 join_key_id;		/* states with one id have the same join_key */
	enum flow_kind kind;
	bool pending;
	bool late_exit_reaches;		/* a late exit state can get to it */
	bool from_apart;		/* it comes from a state that was not alone */
	/* it is kept until the states leave this loop, see flow_loop_is_left() */
	u8 kept_frameno, kept_depth;
	/* the order of pending states, see flow_set_pending() */
	u64 priority;
	u8 order_len;
	u32 order[MAX_CALL_FRAMES];
};

#define FLOW_FIRST(s)	((s)->first)
#define FLOW_LAST(s)	((s)->last)
INTERVAL_TREE_DEFINE(struct flow_state, tree_node, u64, subtree_last, FLOW_FIRST, FLOW_LAST, static,
		     flow_tree)

/* Instances that can wait for each other, see flow_find_ended() */
struct flow_group {
	u32 busy_cnt;			/* pending states, and open calls to other groups */
	struct flow_instance *instances;
};

/* One check of a function: its entry state, its exit states and the calls that get them */
struct flow_instance {
	u32 id;
	u64 priority;			/* 0 until a call waits for it, see flow_set_pending() */
	struct flow_state *entry_state;	/* NULL after the start: it does not change any more */
	u32 pending_cnt;		/* states */
	/* calls from this instance that can get more exit states, and those that call itself */
	u32 open_call_cnt, self_call_cnt;
	struct flow_group *group;
	struct flow_instance *next_in_group;
	u64 *cost;			/* of its function, see flow_may_add_instance() */
	bool in_peeled_trip;		/* a call of it, or of a caller, is in a peeled trip */
	bool replaced;			/* no new call finds it, see flow_grow_instance() */
	bool ended;			/* see flow_end_instance() */
	struct flow_instance *next;
	struct list_head waiting_calls;	/* calls of this instance */
	struct list_head exit_states;	/* these go to @waiting_calls */
	struct list_head done;		/* see flow_keep() */
};

#define INSTANCE_BYTES	(sizeof(struct flow_instance) + 2 * sizeof(void *))

struct flow_kept {
	struct list_head node;
	struct bpf_flow *flow;
	struct bpf_header_state header_state;
};

struct bpf_flow {
	/* computed once */
	u32 *pos;			/* position of the insn in the order */
	s32 *insn_after;		/* the next insn in the order, or -1 */
	u32 *rank;			/* callers go first */
	unsigned long *bb_starts;	/* insn starts a basic block */
	unsigned long *join_points;	/* more than one edge leads to the insn */
	struct bpf_loop call_loop;	/* from the exit of a function to its next call */
	u32 start_cnt;			/* of passes and of path-sensitive runs */

	/* of the pass */
	u64 *cost;			/* per function */
	u64 budget, charged_cost;
	u64 apart_cost;			/* of states that are not alone, see bpf_flow_next() */
	u32 budget_func_cnt;

	/* of the check */
	struct rb_root_cached state_tree;
	u32 *nr_states;				/* per insn */
	struct rb_root_cached pending;
	struct flow_group *groups;		/* bpf_subprog_info.cycle is the index */
	struct flow_instance **instances;	/* bpf_verifier_state.instance_id is the index */
	u32 instance_cnt, instance_cap;
	struct flow_instance *last_instance;	/* of the last pending state */
	bool last_is_apart;			/* it adds to @apart_cost */
	u64 priority_gen;
	struct list_head unused;		/* struct flow_kept */
	u32 seq;
	u32 live_states;
};

/*
 * The order. Reverse post order is a topological order of the graph without
 * back edges, but it may put what follows a loop between the insns of
 * the loop. Keep the insns of a loop together, the head first: in the list of
 * its parent the loop takes the place of the insn of it that comes first.
 *
 * Every cycle has a back edge of the depth first search in it and
 * bpf_compute_loops() makes the target of such edge a loop head. So every edge
 * that goes backwards in the order is in a loop whose head is at or before its
 * target, loops that are not reducible included.
 */
static int flow_compute_order(struct bpf_verifier_env *env, struct bpf_flow *flow)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int len = env->prog->len, i, s, n, h, top, depth, prev = -1;
	int *next, *head, *tail, *stack;
	unsigned long *linked;
	u32 pos = 0;
	int err = -ENOMEM;

	/* lists of members are indexed by loop head, len is the function */
	next = kvmalloc_array(len, sizeof(int), BPF_VERIFIER_GFP);
	head = kvmalloc_array(len + 1, sizeof(int), BPF_VERIFIER_GFP);
	tail = kvmalloc_array(len + 1, sizeof(int), BPF_VERIFIER_GFP);
	stack = kvmalloc_array(len + 1, sizeof(int), BPF_VERIFIER_GFP);
	linked = kvcalloc(BITS_TO_LONGS(len), sizeof(long), BPF_VERIFIER_GFP);
	if (!next || !head || !tail || !stack || !linked)
		goto out;

	for (i = 0; i <= len; i++)
		head[i] = tail[i] = -1;

	for (s = 0; s < env->subprog_cnt; s++) {
		int first = env->subprog_info[s].postorder_start;
		int last = env->subprog_info[s + 1].postorder_start - 1;

		head[len] = tail[len] = -1;
		for (i = last; i >= first; i--) {
			n = env->cfg.insn_postorder[i];
			/* n, then the heads of the loops around it that are not in a list yet */
			depth = 0;
			for (h = n; h >= 0 && !test_bit(h, linked); h = aux[h].loop_header)
				stack[depth++] = h;
			while (depth) {
				h = stack[--depth];
				top = aux[h].loop_header >= 0 ? aux[h].loop_header : len;
				__set_bit(h, linked);
				next[h] = -1;
				if (tail[top] < 0)
					head[top] = h;
				else
					next[tail[top]] = h;
				tail[top] = h;
			}
		}

		depth = 0;
		n = head[len];
		while (n >= 0 || depth) {
			if (n < 0) {
				n = next[stack[--depth]];
				continue;
			}
			flow->pos[n] = pos++;
			flow->insn_after[n] = -1;
			if (prev >= 0)
				flow->insn_after[prev] = n;
			prev = n;
			if (aux[n].loop && head[n] >= 0) {
				stack[depth++] = n;
				n = head[n];
			} else {
				n = next[n];
			}
		}
	}
	err = 0;
out:
	kvfree(next);
	kvfree(head);
	kvfree(tail);
	kvfree(stack);
	kvfree(linked);
	return err;
}

int bpf_flow_insn_after(struct bpf_verifier_env *env, int idx)
{
	return env->flow->insn_after[idx];
}

/* Does the insn at @idx stop the loop @h? */
static bool flow_is_bound(struct bpf_verifier_env *env, int h, int idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	int t;

	/* Once it is out of budget it's a jump. It has to leave the loop. */
	if (bpf_is_may_goto_insn(insn)) {
		t = bpf_loop_at_index(env, idx + insn->off + 1);
		return t != h && !bpf_is_nested_loop(env, t, h);
	}
	if (!bpf_insn_is_iter_next(env, insn))
		return false;
	/* unless the main pass finds that it doesn't, see iter_stops_loops() */
	t = env->insn_aux_data[idx].not_stopped;
	return t < 0 || bpf_is_nested_loop(env, h, t);
}

/*
 * What stops a loop at run time is may_goto that leaves it, or bpf_iter_*_next() of
 * an iterator that is older than the loop, that every trip goes through. A loop without
 * it gets may_goto unless the number of its trips turns out to be known.
 *
 * The place for it is in front of a conditional jump that leaves the loop, with
 * the same target. The registers and the stack are what they are when
 * the program leaves the loop there. One such jump that every trip goes
 * through is enough. Otherwise every back edge needs one.
 */
static void flow_set_guard(struct bpf_verifier_env *env, int h, int n)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int t = n + env->prog->insnsi[n].off + 1;
	int i = bpf_loop_at_index(env, t);

	if (i == h || bpf_is_nested_loop(env, i, h))
		t = n + 1;
	aux[n].guard_place = true;
	aux[n].guard_to = t;
	aux[h].loop->has_guards = true;
}

static void flow_place_guards(struct bpf_verifier_env *env, int h)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop = aux[h].loop;
	int i, n, o, t;

	if (loop->backedges_overflow)
		goto header;

	/*
	 * The head of a loop with more than one entry doesn't dominate what is in the loop.
	 * Then an insn that dominates a back edge can be passed once, on the way in, and
	 * never again. Every trip goes through the jump that is the back edge, and
	 * through the head.
	 */
	if (loop->irreducible) {
		for (i = 0; i < loop->backedges_cnt; i++)
			if (loop->backedges[i].latch != loop->backedges[i].from)
				goto header;
		for (i = 0; i < loop->backedges_cnt; i++)
			flow_set_guard(env, h, loop->backedges[i].from);
		return;
	}

	for (n = bpf_loop_spine_end(env, loop); n >= 0; n = n == h ? -1 : env->idoms[n])
		if (bpf_insn_leaves_loop(env, h, n))
			return flow_set_guard(env, h, n);

	for (i = 0; i < loop->backedges_cnt; i++)
		if (loop->backedges[i].latch < 0)
			goto header;
	for (i = 0; i < loop->backedges_cnt; i++)
		flow_set_guard(env, h, loop->backedges[i].latch);
	return;

header:
	/*
	 * In front of a jump may_goto goes where the jump goes. From the head to where the loop
	 * is left is not an edge of the program: it skips what is in the loop. If that is what
	 * stops a loop around this one, bpf_iter_*_next() or i++, and the exit leads back to
	 * the head of that loop, the program goes round and round from may_goto to may_goto.
	 * So leave all loops.
	 *
	 * What is derived from the graph in the direction of the edges has to know about this
	 * one, see bpf_head_guard_target().
	 */
	for (o = h; aux[o].loop_header >= 0; o = aux[o].loop_header)
		;
	/* a loop that has no exit can only be stopped together with the program */
	t = aux[o].loop->exit_to;
	if (t < 0)
		return;
	aux[h].guard_place = true;
	aux[h].guard_at_header = true;
	aux[h].guard_to = t;
	loop->has_guards = true;
}

/* Does every trip of the loop @h go through an insn that stops it? */
static bool flow_loop_is_bounded(struct bpf_verifier_env *env, int h)
{
	struct bpf_loop *loop = env->insn_aux_data[h].loop;
	int i, n;

	/* see flow_place_guards() about loops with more than one entry */
	if (loop->backedges_overflow || loop->irreducible)
		return false;
	for (i = 0; i < loop->backedges_cnt; i++) {
		for (n = loop->backedges[i].from; n >= 0 && n != h; n = env->idoms[n]) {
			bpf_add_cost(env, 1, BPF_COST_SCAN);
			if (flow_is_bound(env, h, n))
				break;
		}
		if (n < 0 || !flow_is_bound(env, h, n))
			return false;
	}
	return true;
}

/*
 * The main pass got to bpf_iter_*_next() at @insn_idx in a state in which it doesn't stop
 * the loop @h around it. What is assumed about the loops stays as it is until the pass
 * is over, so that all states are treated alike.
 */
void bpf_flow_next_is_no_bound(struct bpf_verifier_env *env, int insn_idx, int h)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[insn_idx];

	if (aux->not_stopped >= 0 && !bpf_is_nested_loop(env, h, aux->not_stopped))
		return;
	aux->not_stopped = h;
	env->restart = true;
}

/*
 * True if a loop was taken for bounded in the pass and is not. The pass is done again then.
 * A loop that has something else that stops it, like the outer one of two nested
 * bpf_for(), is not affected. Every time at least one loop is found out for good.
 */
bool bpf_flow_loops_lost_bound(struct bpf_verifier_env *env)
{
	struct bpf_loop *loop;
	int h;

	for (h = 0; h < env->prog->len; h++) {
		loop = env->insn_aux_data[h].loop;
		if (loop && loop->rt_bounded && !flow_loop_is_bounded(env, h))
			return true;
	}
	return false;
}

/*
 * A state goes around @loop without a trip count, so the loop gets may_goto. At run time
 * may_goto is there for all states. This includes states with a trip count, and states that
 * got to the end of the loop in a peeled trip. A loop before this one can use up the budget
 * of may_goto. So if a state did not take the edges of may_goto, the pass restarts.
 */
int bpf_flow_needs_guard(struct bpf_verifier_env *env, struct bpf_loop *loop)
{
	if (loop->rt_bounded)
		return 0;
	loop->no_first_trips_guess = true;
	if (!loop->has_guards) {
		verbose(env, "loop at insn %d never exits\n", loop->header);
		return -EINVAL;
	}
	if (!loop->this_pass.needs_guard && (env->log.level & BPF_LOG_LEVEL2))
		verbose(env, "loop at %d has no trip count\n", loop->header);
	loop->this_pass.needs_guard = loop->guarded = true;
	env->guards_late |= loop->this_pass.no_guard_edges;
	return 0;
}

/* This pass peels more trips. What the last pass found about @loop can be wrong. */
static void flow_forget_loop(struct bpf_verifier_env *env, struct bpf_loop *loop)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, n = loop->nr_insns;

	loop->changed = loop->guarded = false;
	bpf_add_cost(env, n, BPF_COST_SCAN);
	for (i = loop->header; n--; i = bpf_flow_insn_after(env, i)) {
		if (bpf_loop_at_index(env, i) != loop->header)
			continue;
		aux[i].guard_no_unwind = aux[i].guard_unset_reg = false;
		aux[i].not_stopped = -1;
	}
	loop->rt_bounded = flow_loop_is_bounded(env, loop->header);
}

/* A pass starts. It verifies the main prog and the global functions. */
void bpf_flow_new_pass(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_flow *flow = env->flow;
	int i;

	memset(flow->cost, 0, env->subprog_cnt * sizeof(*flow->cost));
	flow->budget = bpf_precision_budget(env);
	flow->budget_func_cnt = 0;
	flow->apart_cost = 0;
	flow->start_cnt++;
	for (i = 0; i < env->prog->len; i++, aux++) {
		if (aux->callback_loop)
			aux->callback_loop->this_pass = (struct bpf_loop_per_pass){};
		if (aux->recursion_loop)
			aux->recursion_loop->this_pass = (struct bpf_loop_per_pass){};
		if (!aux->loop)
			continue;
		/* pass 0 is over */
		if (flow->start_cnt == 2)
			aux->loop->guarded = aux->loop->this_pass.needs_guard;
		aux->loop->this_pass = (struct bpf_loop_per_pass){};
		if (aux->loop->changed && !env->path_sensitive)
			flow_forget_loop(env, aux->loop);
		if (aux->loop->rt_bounded)
			aux->loop->rt_bounded = flow_loop_is_bounded(env, i);
	}
}

/* The pass has no error. A loop needs may_goto only if a state had no trip count. */
void bpf_flow_drop_guards(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int i, h;

	for (i = 0; i < env->prog->len; i++) {
		h = bpf_loop_at_index(env, i);
		if (h >= 0)
			aux[i].loop_guard &= aux[h].loop->this_pass.needs_guard;
	}
}

/*
 * Which loops have something that stops them at run time, and where may_goto goes in the others.
 * Returns 1 if a place is at the head of a loop.
 */
int bpf_flow_place_guards(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int len = env->prog->len, h, i, ret = 0, err = 0;
	struct bpf_loop *loop;

	for (i = 0; i < len; i++) {
		aux[i].not_stopped = -1;
		for (h = bpf_loop_at_index(env, i); h >= 0; h = aux[h].loop_header)
			aux[h].loop->nr_insns++;
	}

	for (h = 0; h < len; h++) {
		loop = aux[h].loop;
		if (!loop)
			continue;
		err = bpf_add_cost_and_check(env, (u64)loop->nr_insns * loop->backedges_cnt,
					     BPF_COST_COPY);
		if (err)
			break;
		loop->rt_bounded = flow_loop_is_bounded(env, h);
		/* also when it's bounded: the main pass may find that it's not */
		flow_place_guards(env, h);
		/* pass 0 does not know the trip count before it ends */
		loop->guarded = loop->has_guards && !bpf_prog_is_offloaded(env->prog->aux);
		if (aux[h].guard_at_header)
			ret = 1;
	}
	return err ?: ret;
}

static bool flow_may_load_pkt_end(struct bpf_verifier_env *env, const struct bpf_insn *insn)
{
	struct bpf_insn_access_aux info = { .reg_type = SCALAR_VALUE };
	bool tstamp = env->prog->tstamp_type_access, valid;

	valid = env->subprog_cnt > 1 && insn->src_reg != BPF_REG_FP && env->ops->is_valid_access &&
		env->ops->is_valid_access(insn->off, bpf_size_to_bytes(BPF_SIZE(insn->code)),
					  BPF_READ, env->prog, &info);
	/* it notes what the prog reads, and this is a question */
	env->prog->tstamp_type_access = tstamp;
	return valid && info.reg_type == PTR_TO_PACKET_END;
}

int bpf_check_limits(struct bpf_verifier_env *env)
{
	env->aborted |= bpf_must_abort();
	if (env->aborted)
		return -EINTR;
	if (env->no_mem)
		return -ENOMEM;
	if (env->cost <= min(env->max_cost, env->pass_max_cost) && env->mem <= env->max_mem &&
	    !env->over_limit)
		return 0;
	verbose(env, "BPF program is too complex: cost %llu of %llu, memory %llu of %llu\n",
		env->cost, min(env->max_cost, env->pass_max_cost), env->mem, env->max_mem);
	env->over_limit = true;
	return -E2BIG;
}

static struct bpf_loop *flow_new_call_loop(struct bpf_verifier_env *env, enum bpf_loop_kind kind,
					   int header, int func)
{
	struct bpf_loop *loop = kvzalloc_obj(*loop, BPF_VERIFIER_GFP);

	env->mem += sizeof(*loop);
	if (!loop)
		return NULL;
	loop->kind = kind;
	loop->header = header;
	/* the helper stops, the function checks the stack, see check_recursion_guard() */
	loop->rt_bounded = true;
	loop->nr_insns = func < 0 ? 1 :
			 env->subprog_info[func + 1].start - env->subprog_info[func].start;
	return loop;
}

int bpf_flow_prepare(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_subprog_info *sub = env->subprog_info;
	struct bpf_insn *insns = env->prog->insnsi;
	int len = env->prog->len, i, s, err = 0;
	struct bpf_iarray *succ;
	struct bpf_flow *flow;
	unsigned long *pred;

	flow = kzalloc_obj(*flow, BPF_VERIFIER_GFP);
	if (!flow)
		return -ENOMEM;
	env->flow = flow;
	INIT_LIST_HEAD(&flow->unused);
	flow->state_tree = flow->pending = RB_ROOT_CACHED;
	flow->call_loop.kind = BPF_LOOP_RECURSION;

	flow->pos = kvcalloc(2 * len, sizeof(u32), BPF_VERIFIER_GFP);
	flow->rank = kvcalloc(env->subprog_cnt + 1, sizeof(u32), BPF_VERIFIER_GFP);
	flow->cost = kvcalloc(env->subprog_cnt, sizeof(u64), BPF_VERIFIER_GFP);
	flow->groups = kvcalloc(env->subprog_cnt, sizeof(*flow->groups), BPF_VERIFIER_GFP);
	flow->bb_starts = kvcalloc(BITS_TO_LONGS(len), sizeof(long), BPF_VERIFIER_GFP);
	flow->join_points = kvcalloc(BITS_TO_LONGS(len), sizeof(long), BPF_VERIFIER_GFP);
	flow->nr_states = kvcalloc(len, sizeof(u32), BPF_VERIFIER_GFP);
	pred = kvcalloc(BITS_TO_LONGS(len), sizeof(long), BPF_VERIFIER_GFP);
	if (!flow->pos || !flow->rank || !flow->cost || !flow->bb_starts || !flow->join_points ||
	    !flow->nr_states || !flow->groups || !pred) {
		kvfree(pred);
		return -ENOMEM;
	}

	flow->insn_after = flow->pos + len;
	/* subprog_topo_order[] has callees first */
	for (i = 0; i < env->subprog_cnt; i++)
		flow->rank[env->subprog_topo_order[i]] = env->subprog_cnt - i;

	for (i = 0; i < len; i++) {
		succ = bpf_insn_successors(env, i);
		iarray_for_each(s, succ) {
			if (__test_and_set_bit(s, pred))
				__set_bit(s, flow->join_points);
			if (aux[i].bb_end)
				__set_bit(s, flow->bb_starts);
		}
		if (bpf_is_throw_kfunc(&insns[i]) && i + 1 < len)
			__set_bit(i + 1, flow->bb_starts);
		/* where the callees come back to */
		if ((bpf_pseudo_call(&insns[i]) || bpf_is_callx(&insns[i])) && i + 1 < len)
			__set_bit(i + 1, flow->join_points);
		if (aux[i].calls_callback) {
			aux[i].callback_loop = flow_new_call_loop(env, BPF_LOOP_CALLBACK, i,
								  bpf_insn_callee(env, i));
			err = aux[i].callback_loop ? err : -ENOMEM;
		}
		if (aux[i].calls_callback || aux[i].loop)
			__set_bit(i, flow->join_points);
		if (bpf_is_ldimm64(&insns[i]))
			i++;
		/* a guess: the base register can point to something else than ctx */
		if (BPF_CLASS(insns[i].code) == BPF_LDX && flow_may_load_pkt_end(env, &insns[i]))
			bpf_find_containing_subprog(env, i)->loads_pkt_end = true;
	}
	for (s = 0; s < env->subprog_cnt; s++, sub++) {
		i = sub->start;
		__set_bit(i, flow->join_points);
		if (!sub->cycle || err)
			continue;
		if (sub->cycle != s) {
			aux[env->subprog_info[sub->cycle].start].recursion_loop->nr_insns +=
				sub[1].start - i;
			continue;
		}
		aux[i].recursion_loop = flow_new_call_loop(env, BPF_LOOP_RECURSION, i, s);
		err = aux[i].recursion_loop ? 0 : -ENOMEM;
	}
	bitmap_or(flow->bb_starts, flow->bb_starts, flow->join_points, len);
	kvfree(pred);
	return err ?: flow_compute_order(env, flow);
}

static struct flow_state *flow_new_state(struct bpf_verifier_env *env, int prev_insn_idx)
{
	struct flow_state *s = kzalloc_obj(*s, BPF_VERIFIER_GFP);
	struct bpf_flow *flow = env->flow;

	if (!s)
		return NULL;
	RB_CLEAR_NODE(&s->tree_node);
	INIT_LIST_HEAD(&s->node);
	s->prev_insn_idx = prev_insn_idx;
	s->seq = ++flow->seq;
	s->from_apart = flow->last_is_apart;
	s->log_pos = env->log.end_pos;
	s->diag_pos = bpf_diag_event_log_save(env);
	bpf_add_cost(env, 1, BPF_COST_STATE);
	env->total_states++;
	flow->live_states++;
	env->peak_states = max(env->peak_states, flow->live_states);
	return s;
}

static struct flow_instance *flow_state_instance(struct bpf_flow *flow, const struct flow_state *s)
{
	return s->started_instance ?: flow->instances[s->st.instance_id];
}

static void flow_clear_pending(struct bpf_flow *flow, struct flow_state *s)
{
	if (!s->pending)
		return;
	rb_erase_cached(&s->rb, &flow->pending);
	flow_state_instance(flow, s)->pending_cnt--;
	flow_state_instance(flow, s)->group->busy_cnt--;
	s->pending = false;
}

static void flow_unlink(struct bpf_verifier_env *env, struct flow_state *s)
{
	struct flow_instance *instance;

	flow_clear_pending(env->flow, s);
	if (s->callee || !RB_EMPTY_NODE(&s->tree_node))
		env->flow->nr_states[s->st.insn_idx]--;
	if (s->callee) {
		instance = flow_state_instance(env->flow, s);
		instance->open_call_cnt--;
		instance->self_call_cnt -= instance == s->callee;
		instance->group->busy_cnt -= instance->group != s->callee->group;
		s->callee = NULL;
	}
	if (!RB_EMPTY_NODE(&s->tree_node))
		flow_tree_remove(s, &env->flow->state_tree);
	RB_CLEAR_NODE(&s->tree_node);
	list_del_init(&s->node);
}

static void flow_free_state(struct bpf_verifier_env *env, struct flow_state *s)
{
	flow_unlink(env, s);
	bpf_free_verifier_state(env, &s->st, false);
	kfree(s);
	env->flow->live_states--;
}

static void flow_free_list(struct bpf_verifier_env *env, struct list_head *list)
{
	struct flow_state *s, *sn;

	list_for_each_entry_safe(s, sn, list, node)
		flow_free_state(env, s);
}

static void flow_free_unused(struct bpf_verifier_env *env)
{
	struct flow_kept *k;

	while ((k = list_first_entry_or_null(&env->flow->unused, struct flow_kept, node))) {
		list_del(&k->node);
		bpf_free_verifier_state(env, &k->header_state.st, false);
		kfree(k);
	}
}

/* What a check leaves behind. */
void bpf_flow_reset(struct bpf_verifier_env *env)
{
	struct bpf_flow *flow = env->flow;
	struct rb_node *n;
	int i;

	if (!flow)
		return;
	while ((n = rb_first_cached(&flow->state_tree)))
		flow_free_state(env, rb_entry(n, struct flow_state, tree_node));
	for (i = 0; i < flow->instance_cnt; i++)
		flow_free_list(env, &flow->instances[i]->waiting_calls);
	for (i = 0; i < flow->instance_cnt; i++) {
		flow->instances[i]->group->instances = NULL;
		kfree(flow->instances[i]);
	}
	flow_free_unused(env);
	env->mem -= flow->instance_cnt * INSTANCE_BYTES;
	flow->instance_cnt = 0;
	flow->last_instance = NULL;
	flow->last_is_apart = false;
}

void bpf_flow_free(struct bpf_verifier_env *env)
{
	struct bpf_flow *flow = env->flow;

	if (!flow)
		return;
	bpf_flow_reset(env);
	kvfree(flow->pos);
	kvfree(flow->rank);
	kvfree(flow->cost);
	kvfree(flow->groups);
	kvfree(flow->bb_starts);
	kvfree(flow->join_points);
	kvfree(flow->nr_states);
	kvfree(flow->instances);
	kfree(flow);
	env->flow = NULL;
}

bool bpf_flow_is_bb_start(struct bpf_verifier_env *env, int insn_idx)
{
	return test_bit(insn_idx, env->flow->bb_starts);
}

/* The paths that continue from the current state share a copy of it */
int bpf_flow_save_header_state(struct bpf_verifier_env *env, struct loop_stack_entry *entry)
{
	struct flow_kept *k = kzalloc_obj(*k, BPF_VERIFIER_GFP);

	if (!k)
		return -ENOMEM;
	bpf_flow_put_header_state(entry);
	entry->header_state = NULL;
	k->flow = env->flow;
	k->header_state.refcnt = 1;
	if (bpf_copy_verifier_state(env, &k->header_state.st, env->cur_state)) {
		list_add(&k->node, &k->flow->unused);
		return -ENOMEM;
	}
	entry->header_state = &k->header_state;
	return 0;
}

void bpf_flow_put_header_state(struct loop_stack_entry *entry)
{
	struct flow_kept *k;

	if (!entry->header_state || --entry->header_state->refcnt)
		return;
	k = container_of(entry->header_state, struct flow_kept, header_state);
	list_add(&k->node, &k->flow->unused);
}

/* A peeled trip is complete before the next one starts. The leftover is last. */
static int flow_cmp_trips(const struct bpf_func_state *fa, const struct bpf_func_state *fb)
{
	const struct loop_stack_entry *ea = fa->loop_stack, *eb = fb->loop_stack;
	u32 i, ta, tb;

	for (i = 0; i < fa->loop_stack_cnt && i < fb->loop_stack_cnt; i++, ea++, eb++) {
		if (ea->loop != eb->loop)
			break;
		ta = ea->peeled ? ea->trip : U32_MAX;
		tb = eb->peeled ? eb->trip : U32_MAX;
		if (ta != tb)
			return ta < tb ? -1 : 1;
	}
	return 0;
}

static bool flow_less(struct rb_node *na, const struct rb_node *nb)
{
	const struct flow_state *a = rb_entry(na, struct flow_state, rb);
	const struct flow_state *b = rb_entry(nb, struct flow_state, rb);
	int cmp;
	u32 i;

	if (a->priority != b->priority)
		return a->priority < b->priority;
	for (i = 0; i < a->order_len && i < b->order_len; i++) {
		cmp = flow_cmp_trips(a->st.frame[i], b->st.frame[i]);
		if (cmp)
			return cmp < 0;
		if (a->order[i] != b->order[i])
			return a->order[i] < b->order[i];
	}
	if (a->order_len != b->order_len)
		return a->order_len < b->order_len;
	/* a speculative state gets a barrier if the fixups of the others do not fit */
	if (a->st.speculative != b->st.speculative)
		return b->st.speculative;
	return a->seq < b->seq;
}

/*
 * The order of pending states:
 * 1. An instance that a call waits for. The call has no exit state to continue. It waits at
 *    its position in the order. The code after the call waits too.
 * 2. Callers. So the calls of a function get to it before it is checked.
 * 3. The trip, then the position, in each frame. A callee in the frames of its callers is
 *    complete before the code after the call.
 * 4. Exit states. They go to the calls when the instance is complete.
 *
 * A path-sensitive run goes depth first, to the state that is nearer to an unproven insn.
 */
static void flow_set_pending(struct bpf_verifier_env *env, struct flow_state *s)
{
	const struct bpf_verifier_state *st = &s->st;
	struct bpf_flow *flow = env->flow;
	struct flow_instance *instance = flow_state_instance(flow, s);
	u32 i;

	s->priority = instance->priority ?:
		      BIT_ULL(63) | (u64)flow->rank[st->frame[0]->subprogno] << 32 | ~instance->id;
	for (i = 0; i < st->curframe; i++)
		s->order[i] = flow->pos[st->frame[i + 1]->callsite];
	s->order[i] = s->kind == FLOW_FUNC_EXIT ? U32_MAX : flow->pos[st->insn_idx];
	s->order_len = i + 1;
	if (env->path_sensitive) {
		s->priority = (u64)~env->insn_processed << 32 | (env->fallthrough_first ?
			      st->insn_idx != s->prev_insn_idx + 1 :
			      bpf_failing_path_hops(env, st));
		s->order_len = 0;
	}
	s->pending = true;
	instance->pending_cnt++;
	instance->group->busy_cnt++;
	rb_add_cached(&s->rb, &flow->pending, flow_less);
}

/*
 * States meet only if they have the same hash. The tree sorts them by a half of the hash,
 * then by the range of one xreg of data_deps. Two ranges with a gap stay apart, but not where
 * states come around a loop. Two constants, such as 0 and 3, can miss their join.
 * Returns the first state near @s.
 */
static struct flow_state *flow_find(struct bpf_verifier_env *env, struct flow_state *s)
{
	const struct bpf_insn_aux_data *aux = &env->insn_aux_data[s->st.insn_idx];
	struct loop_stack_entry *e = bpf_top_loop(s->st.frame[0]);
	u32 first = 0, last = U32_MAX;
	u64 hash;

	hash = bpf_hash_apart_xregs(env, &s->st, bpf_hash_join_key(env, &s->st) + s->kind,
				    s->kind == FLOW_PEELED);
	/* the arguments are joined, else calls do not share an instance */
	if (s->kind != FLOW_FUNC_ENTRY && s->kind != FLOW_JOINED_CALLS)
		hash = bpf_hash_live_types(env, &s->st, hash, env->flow->apart_cost);
	if (s->kind == FLOW_FUNC_ENTRY && (!e || e->peeled))
		hash = bpf_hash_args(env, &s->st, hash);
	if (s->kind == FLOW_AT ? !aux->loop && !aux->callback_loop :
	    s->kind == FLOW_FUNC_EXIT && !e)
		bpf_range_of_data_dep(env, &s->st, &first, &last);
	bpf_add_cost(env, bpf_xreg_cnt(&s->st), BPF_COST_COPY);
	s->join_key_id = ++env->flow->seq;
	s->hash = hash;
	s->first = hash << 32 | first;
	s->last = hash << 32 | last;
	return flow_tree_iter_first(&env->flow->state_tree, s->first, s->last);
}

#define flow_for_each_near(env, s, t, tn)						\
	for (t = flow_find(env, s);							\
	     t && (tn = flow_tree_iter_next(t, (s)->first, (s)->last), true); t = tn)

/*
 * The loop that @st came around or entered, if @st is at a header. One insn can be the header
 * of a jump loop and of the calls of a callback.
 */
static struct loop_stack_entry *flow_header_entry(const struct bpf_verifier_state *st)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	struct loop_stack_entry *e = NULL;
	u32 i = frame->loop_stack_cnt;

	while (i-- && frame->loop_stack[i].loop->header == st->insn_idx && !(e && e->trip) &&
	       frame->loop_stack[i].loop->kind != BPF_LOOP_RECURSION)
		e = &frame->loop_stack[i];
	return e;
}

/* If more than one state starts a peeled trip, paths of other lengths can come to one state */
static bool flow_keep_peeled(struct bpf_verifier_env *env, struct loop_stack_entry *e)
{
	bool more = e->loop->this_pass.last_peeled_trip == e->trip;

	e->loop->this_pass.last_peeled_trip = e->trip;
	if (!more && !bpf_trip_is_saved(e))
		return false;
	e->entry_id = ++env->loop_entry_cnt;
	return true;
}

/*
 * @s is the next pending state. Can a state with the same join_key arrive later?
 * - In the leftover of a loop: until the states leave the loop.
 * - At the start of a peeled trip: later trips are compared with it.
 * - A call can get more exit states: until all calls have them and the late states went by.
 *   In a peeled trip the call waits.
 * - An async callback can start again: until the check ends.
 */
static bool flow_keep(struct bpf_verifier_env *env, struct flow_state *s)
{
	const struct bpf_verifier_state *st = &s->st;
	struct loop_stack_entry *e, *header_entry = flow_header_entry(st);
	struct flow_instance *instance = env->flow->instances[st->instance_id];
	bool in_loop = false, keep;
	u32 fr, i;

	if (!test_bit(st->insn_idx, env->flow->join_points) || env->path_sensitive ||
	    s->kind == FLOW_AGAIN)
		return false;
	if (s->started_instance)
		return true;
	s->late_exit_reaches = true;
	s->kept_frameno = U8_MAX;
	for (fr = 0; fr <= st->curframe; fr++) {
		e = st->frame[fr]->loop_stack;
		for (i = 0; i < st->frame[fr]->loop_stack_cnt; i++, e++) {
			if (s->kind == FLOW_LEFTOVER && e == bpf_top_loop(st->frame[st->curframe]))
				break;
			if (e == header_entry && e->peeled && s->kind == FLOW_AT &&
			    flow_keep_peeled(env, e))
				s->kind = FLOW_PEELED;
			keep = !e->peeled || (e == header_entry && s->kind == FLOW_PEELED);
			if (e->loop->kind != BPF_LOOP_RECURSION && (e->peeled || !in_loop)) {
				s->late_exit_reaches &= !e->peeled;
				s->kept_frameno = fr;
				s->kept_depth = i;
				in_loop = keep;
			}
			if (e == header_entry && keep)
				break;
		}
	}
	if (s->late_exit_reaches && st->frame[0]->in_async_callback_fn)
		return true;
	keep = in_loop || (s->late_exit_reaches && instance->open_call_cnt);
	if (keep)
		list_add_tail(&s->node, &instance->done);
	return keep;
}

/* Later trips find @s without the number of its trip */
static void flow_insert_peeled(struct bpf_verifier_env *env, struct flow_state *s)
{
	flow_header_entry(&s->st)->trip = 0;
	flow_tree_remove(s, &env->flow->state_tree);
	flow_find(env, s);
	flow_tree_insert(s, &env->flow->state_tree);
}

/* @next is the next pending state. Did the states leave the loop that @s is kept for? */
static bool flow_loop_is_left(struct flow_state *s, const struct flow_state *next)
{
	const struct loop_stack_entry *es, *en;
	const struct bpf_func_state *fs, *fn;
	u32 fr, i;

	/* a call returned late */
	if (!flow_less(&s->rb, &next->rb))
		return false;
	if (next->st.curframe < s->kept_frameno)
		return true;
	for (fr = 0; fr <= s->kept_frameno; fr++) {
		fs = s->st.frame[fr];
		fn = next->st.frame[fr];
		if (fs->subprogno != fn->subprogno || fs->callsite != fn->callsite)
			return true;
		for (i = 0;
		     i < (fr < s->kept_frameno ? fs->loop_stack_cnt : s->kept_depth + 1); i++) {
			es = &fs->loop_stack[i];
			en = &fn->loop_stack[i];
			if (i >= fn->loop_stack_cnt || es->loop != en->loop)
				return true;
			if (es->peeled && (!en->peeled || es->trip != en->trip) &&
			    !(s->kind != FLOW_AT && en->peeled && fr == s->kept_frameno &&
			      i == s->kept_depth))
				return true;
		}
	}
	return false;
}

static struct flow_instance *flow_new_instance(struct bpf_verifier_env *env,
					       struct flow_state *entry)
{
	const struct bpf_func_state *f = entry ? entry->st.frame[0] : NULL;
	struct bpf_flow *flow = env->flow;
	struct flow_instance **instances, *instance;
	u32 cap;

	if (flow->instance_cnt == flow->instance_cap) {
		cap = 2 * flow->instance_cap + 2;
		instances = kvrealloc(flow->instances, cap * sizeof(*instances), BPF_VERIFIER_GFP);
		if (!instances)
			return NULL;
		flow->instances = instances;
		flow->instance_cap = cap;
	}
	instance = kzalloc_obj(*instance, BPF_VERIFIER_GFP);
	if (!instance)
		return NULL;
	INIT_LIST_HEAD(&instance->waiting_calls);
	INIT_LIST_HEAD(&instance->exit_states);
	INIT_LIST_HEAD(&instance->done);
	instance->entry_state = entry;
	instance->group = flow->groups;
	if (f && f->loop_stack_cnt && !f->loop_stack->peeled)
		instance->group += env->subprog_info[f->subprogno].cycle;
	instance->next_in_group = instance->group->instances;
	instance->group->instances = instance;
	env->mem += INSTANCE_BYTES;
	instance->id = flow->instance_cnt++;
	flow->instances[instance->id] = instance;
	return instance;
}

static bool flow_same_join_key(struct bpf_verifier_env *env, const struct flow_state *t,
			       struct flow_state *s)
{
	/* The tree has a half of the hash. A collision there is random and costs nothing. */
	if (t->hash != s->hash)
		return false;
	if (t->join_key_id == s->join_key_id)
		return true;
	bpf_add_cost(env, bpf_xreg_cnt(&t->st) + t->st.acquired_refs, BPF_COST_COPY);
	if (t->kind != s->kind || t->st.insn_idx != s->st.insn_idx ||
	    !bpf_same_join_key(&t->st, &s->st))
		return false;
	s->join_key_id = t->join_key_id;
	return true;
}

/* After flow_find(), unless @s is a call */
static void flow_insert(struct bpf_verifier_env *env, struct flow_state *s)
{
	u32 *nr = &env->flow->nr_states[s->st.insn_idx];

	bpf_charge_state(env, &s->st);
	if (s->callee)
		list_add_tail(&s->node, &s->callee->waiting_calls);
	else
		flow_tree_insert(s, &env->flow->state_tree);
	if (s->kind == FLOW_FUNC_EXIT)
		list_add_tail(&s->node, &env->flow->instances[s->st.instance_id]->exit_states);
	env->max_states_per_insn = max(env->max_states_per_insn, ++*nr);
}

static void flow_link(struct bpf_verifier_env *env, struct flow_state *s)
{
	flow_insert(env, s);
	flow_set_pending(env, s);
}

/* The entry of @loop in the top frame of @st */
static struct loop_stack_entry *flow_loop_entry(const struct bpf_verifier_state *st,
						const struct bpf_loop *loop)
{
	struct bpf_func_state *frame = st->frame[st->curframe];
	u32 i = frame->loop_stack_cnt;

	while (frame->loop_stack[--i].loop != loop)
		;
	return &frame->loop_stack[i];
}

/*
 * @s came around @loop and arrives at @t. Does @s come from @t?
 *	ret = 0; if (...) { denied++; ret = -EPERM; }
 *	bpf_for(i, 0, n) { ... } return ret;
 * Two states enter the loop. What comes around with 0 is for the state with 0. Next to -EPERM
 * it looks like a number that grew.
 */
static bool flow_same_entry(struct bpf_loop *loop, const struct flow_state *t,
			    const struct flow_state *s)
{
	return s->kind == FLOW_FUNC_EXIT ||
	       flow_loop_entry(&t->st, loop)->entry_id == flow_loop_entry(&s->st, loop)->entry_id;
}

/*
 * @t subsumes @s. The caller prunes @s, @t continues for it. If @s made more trips it can
 * come from @t:
 *
 *	t --> ... --> header --> ... --> s
 *	^                                |
 *	`----------- subsumes -----------'
 *
 * A back edge adds a trip and a join has the larger number. So each cycle of states has such
 * an edge for the outermost loop that it goes around. All pruned states come here.
 * Speculation ends by itself.
 *
 * The loop ends if the trip index k of @s is small each time. That is the trip count:
 *
 *  trip count:  guess -> state holds k -> jumps refine k -> k is small ?
 *                                                           yes: no guard   no: add may_goto
 *
 * A loop that can run longer than that gets may_goto.
 * There is no trip count without CAP_PERFMON (allow_uninit_stack).
 */
static int flow_check_trip_counts(struct bpf_verifier_env *env, const struct flow_state *t,
				  const struct flow_state *s)
{
	const struct loop_stack_entry *e;
	u32 fr, i;
	u64 max_trip;
	int err;

	for (fr = 0; fr <= s->st.curframe && !s->st.speculative; fr++) {
		e = s->st.frame[fr]->loop_stack;
		for (i = 0; i < s->st.frame[fr]->loop_stack_cnt; i++, e++) {
			if (e->loop->kind != BPF_LOOP_JUMPS ||
			    e->trip <= t->st.frame[fr]->loop_stack[i].trip)
				continue;
			max_trip = cnum64_umax(e->trip_index.r64);
			if (!e->peeled && max_trip <= BPF_MAX_TRIPS && env->allow_uninit_stack) {
				if (env->log.level & BPF_LOG_LEVEL2)
					verbose(env, "loop at %d has trip count %llu\n",
						e->loop->header, max_trip + 1);
				continue;
			}
			err = bpf_flow_needs_guard(env, e->loop);
			if (err)
				return err;
		}
	}
	return 0;
}

/* @t is from an earlier walk over a leftover. The header state of @s subsumes that of @t. */
static bool flow_is_stale(const struct flow_state *t, const struct flow_state *s)
{
	const struct loop_stack_entry *a, *b;
	u32 fr, i;

	for (fr = 0; !t->pending && fr <= s->st.curframe; fr++) {
		a = t->st.frame[fr]->loop_stack;
		b = s->st.frame[fr]->loop_stack;
		for (i = 0; i < s->st.frame[fr]->loop_stack_cnt; i++, a++, b++)
			if (a->entry_id == b->entry_id && a->trip < b->trip)
				return true;
	}
	return false;
}

/*
 * All states arrive here. @s is
 * - pruned, if a state subsumes it,
 * - joined with a state, unless the join rule keeps them apart,
 * - pending otherwise.
 * @loop: @s came around it, or @enters its leftover.
 */
static int flow_prune_or_join(struct bpf_verifier_env *env, struct flow_state *s,
			      struct bpf_loop *loop, bool enters)
{
	bool log = (env->log.level & BPF_LOG_LEVEL2) && s->kind == FLOW_AT, widen, subsumed;
	int insn_idx = s->st.insn_idx, prev = s->prev_insn_idx, err = 0;
	struct loop_stack_entry *e;
	struct flow_state *t, *tn;
	bool joined = false, widened = false;
	struct bpf_loop *leftover_loop;

again:
	err = err ?: bpf_check_limits(env);
	if (err)
		goto free;

	flow_for_each_near(env, s, t, tn) {
		if (!flow_same_join_key(env, t, s))
			continue;
		/* an exit state can get into the function again */
		leftover_loop = s->kind == FLOW_FUNC_EXIT && t->pending ? NULL : loop;
		e = leftover_loop ? flow_loop_entry(&s->st, leftover_loop) : NULL;
		if (bpf_must_keep_apart(env, &t->st, &s->st,
					e && flow_same_entry(leftover_loop, t, s) ?
					BPF_JOIN_POINT_HEADER : BPF_JOIN_POINT, e))
			continue;
		if (e && e->peeled)
			leftover_loop = NULL;
		subsumed = bpf_state_subsumes(env, &t->st, &s->st);
		if (!subsumed && t->st.speculative != s->st.speculative)
			continue;
		if (subsumed) {
			if (env->log.level & BPF_LOG_LEVEL2)
				verbose(env, "from %d to %d: pruned\n", prev, insn_idx);
			err = flow_check_trip_counts(env, t, s);
			goto free;
		}
		/* what grows in a loop is widened, it is not replaced */
		if (!leftover_loop && bpf_state_subsumes(env, &s->st, &t->st)) {
			err = flow_check_trip_counts(env, s, t);
			if (err)
				goto free;
			/* it goes on with the leftover that @t started */
			if (s->kind == FLOW_LEFTOVER)
				bpf_top_loop(s->st.frame[s->st.curframe])->entry_id =
				bpf_top_loop(t->st.frame[t->st.curframe])->entry_id;
			flow_free_state(env, t);
			joined = true;
			continue;
		}
		if (!leftover_loop && s->kind == FLOW_AT && flow_is_stale(t, s)) {
			flow_free_state(env, t);
			continue;
		}
		joined = true;
		widened = leftover_loop;
		/* what enters did not grow in this loop */
		widen = !t->pending && !enters;
		flow_unlink(env, t);
		err = bpf_states_join(env, &t->st, &s->st, leftover_loop, widen);
		swap(s->st, t->st);
		s->st.last_insn_idx = prev;
		flow_free_state(env, t);
		/* another state can subsume the join, or have a join with it */
		goto again;
	}

	/*
	 * The state is printed when its turn comes. That says enough about a state that
	 * is new, and about a state that goes on to the next insn.
	 */
	if (prev >= 0 && insn_idx == prev + 1 + bpf_is_ldimm64(&env->prog->insnsi[prev]) &&
	    !widened)
		joined = false;
	if (log && joined)
		verbose(env, "from %d to %d: %s\n", prev, insn_idx, widened ? "widened" : "joined");
	err = enters && !widened ? bpf_guess_first_trips(env, &s->st, loop) : 0;
	if (err < 0)
		goto free;
	if (err)
		flow_find(env, s);
	flow_link(env, s);
	return 0;
free:
	flow_free_state(env, s);
	return err;
}

/*
 * @s starts a peeled trip of @loop. Does it repeat the state of an earlier trip? It is compared
 * with trip 0, 1, 2, 4, 8, ... That finds any period. If @s comes from that state, the verifier
 * sees no end of the loop. So the loop needs may_goto.
 * A state that has less than the earlier one can be on its way to the end of the loop:
 *	for (i = 7; i >= 0; i--) { if (i >= n) continue; ... }
 * It is pruned for the price of may_goto. So is a state of another entry. If that causes
 * an error, the next pass sets no_peel_prune.
 */
static int flow_prune_peeled(struct bpf_verifier_env *env, struct flow_state *s,
			     struct bpf_loop *loop)
{
	struct loop_stack_entry *entry = flow_loop_entry(&s->st, loop);
	struct flow_state *t, *tn;
	u32 trip = entry->trip;
	int ret = 0;

	entry->trip = 0;
	s->kind = FLOW_PEELED;
	flow_for_each_near(env, s, t, tn) {
		if (!flow_same_join_key(env, t, s) || !bpf_state_subsumes(env, &t->st, &s->st))
			continue;
		if (!loop->rt_bounded && !loop->this_pass.needs_guard && !s->st.speculative &&
		    (!flow_same_entry(loop, t, s) || !bpf_state_subsumes(env, &s->st, &t->st))) {
			if (loop->no_peel_prune)
				continue;
			loop->this_pass.peel_pruned = true;
		}
		if (env->log.level & BPF_LOG_LEVEL2)
			verbose(env, "from %d to %d: pruned\n", s->prev_insn_idx, s->st.insn_idx);
		entry->trip = trip;
		ret = flow_check_trip_counts(env, t, s) ?: 1;
		break;
	}
	s->kind = FLOW_AT;
	entry->trip = trip;
	return ret;
}

/*
 * The current state starts a peeled trip. An earlier trip can have all that it has in the
 * deps. Then more peeled trips cannot help, and the leftover starts. If the earlier trip
 * subsumes the full state, the trip counts as new: flow_prune_peeled() prunes it.
 */
bool bpf_flow_trip_is_new(struct bpf_verifier_env *env, struct loop_stack_entry *entry)
{
	struct flow_state *s = container_of(env->cur_state, struct flow_state, st), *t, *tn;
	u32 trip = entry->trip;
	bool is_new = true;

	if (entry->loop->kind == BPF_LOOP_RECURSION || entry->loop->no_peel_prune)
		return true;
	entry->trip = 0;
	s->kind = FLOW_PEELED;
	flow_for_each_near(env, s, t, tn) {
		if (!flow_same_join_key(env, t, s) || bpf_values_grew_in_deps(env, &t->st, &s->st))
			continue;
		is_new = bpf_state_subsumes(env, &t->st, &s->st);
		if (is_new)
			break;
	}
	s->kind = FLOW_AT;
	entry->trip = trip;
	entry->loop->this_pass.peel_pruned |= !is_new;
	return is_new;
}

/* @s is taken. @starts_leftover: the states of FLOW_LEFTOVER are joined, start the leftover */
static int flow_add(struct bpf_verifier_env *env, struct flow_state *s, bool starts_leftover)
{
	struct bpf_verifier_state *cur = env->cur_state;
	int cur_idx = env->insn_idx, err;
	struct bpf_loop *loop = NULL;
	u32 id_gen = env->id_gen;
	bool leftover = false;

	env->cur_state = &s->st;
	env->insn_idx = s->st.insn_idx;
	s->kind = FLOW_AT;
	err = starts_leftover ? bpf_flow_start_leftover(env) :
	      bpf_flow_loop_enter(env, &loop, &leftover);
	env->cur_state = cur;
	env->insn_idx = cur_idx;
	if (err < 0)
		err = bpf_flow_edge_unproven(env, &s->st, s->st.insn_idx, err);
	/* a pointer to the packet that moves in the loop got an id */
	if (!err && env->id_gen != id_gen)
		err = bpf_renumber_ids(env, &s->st);
	if (!err && env->path_sensitive) {
		if (test_bit(s->st.insn_idx, env->flow->join_points))
			err = bpf_failing_path_was_here(env, &s->st);
	} else if (!err && loop && flow_loop_entry(&s->st, loop)->peeled) {
		err = flow_prune_peeled(env, s, loop);
	}
	if (err) {
		flow_free_state(env, s);
		return min(err, 0);
	}
	if (env->path_sensitive) {
		flow_link(env, s);
		return 0;
	}
	if (leftover)
		s->kind = FLOW_LEFTOVER;
	if (starts_leftover)
		loop = env->insn_aux_data[s->st.insn_idx].loop;
	return flow_prune_or_join(env, s, loop, starts_leftover);
}

/*
 * @st gets to @insn_idx. The flow takes what it has and leaves @st empty.
 * @again: the insn is checked again, for a part of the values. There is no join.
 */
int bpf_flow_deliver(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
		     int insn_idx, int prev_insn_idx, bool again)
{
	struct flow_state *s;
	int err;

	if (insn_idx < 0 || insn_idx >= env->prog->len) {
		verbose(env, "invalid insn idx %d insn_cnt %d\n", insn_idx, env->prog->len);
		return -EFAULT;
	}

	/* the check starts */
	if (!env->flow->instance_cnt && !flow_new_instance(env, NULL))
		return -ENOMEM;
	s = flow_new_state(env, prev_insn_idx);
	if (!s)
		return -ENOMEM;
	s->st = *st;
	memset(st, 0, sizeof(*st));
	s->st.insn_idx = insn_idx;
	s->st.last_insn_idx = prev_insn_idx;

	if (env->path_sensitive && (s->st.infeasible || s->st.speculative ||
				    bpf_failing_path_hops(env, &s->st) == U32_MAX)) {
		flow_free_state(env, s);
		return 0;
	}
	err = bpf_clean_verifier_state(env, &s->st);
	if (err) {
		flow_free_state(env, s);
		return err;
	}
	if (again) {
		s->kind = FLOW_AGAIN;
		flow_find(env, s);
		flow_link(env, s);
		return 0;
	}
	return flow_add(env, s, false);
}

/* @x is an exit state of the instance of the call @w. @w can leave the instance. */
static int flow_apply_exit(struct bpf_verifier_env *env, struct flow_state *w,
			   struct flow_state *x)
{
	int call_idx = w->st.insn_idx, err;
	struct bpf_verifier_state st = {};

	err = bpf_copy_verifier_state(env, &st, &w->st) ?:
	      bpf_flow_return(env, &st, &x->st, call_idx);
	if (!err)
		err = bpf_flow_deliver(env, &st, call_idx + 1, call_idx, false);
	else if (err < 0 && st.speculative)
		err = min(bpf_flow_edge_unproven(env, &st, call_idx + 1, err), 0);
	else if (err < 0)
		err = min(bpf_flow_edge_unproven(env, &x->st, x->prev_insn_idx, err), 0);
	bpf_free_verifier_state(env, &st, false);
	if (err <= 0)
		return err;

	/* The call is checked again in the frames of the caller */
	flow_unlink(env, w);
	flow_find(env, w);
	flow_link(env, w);
	return 0;
}

/* The arguments that are readable */
static u64 flow_readable_args(const struct bpf_func_state *f)
{
	u64 mask = 0;
	u32 i;

	for (i = BPF_REG_1; i <= BPF_REG_5; i++)
		mask |= (u64)(f->regs[i].type != NOT_INIT) << i;
	for (i = 0; i < f->out_stack_arg_cnt; i++)
		mask |= (u64)(f->stack_arg_regs[i].type != NOT_INIT) << (MAX_BPF_REG + i);
	return mask;
}

/* The exit states of @old are exit states of @instance too */
static int flow_copy_exit_states(struct bpf_verifier_env *env, struct flow_instance *instance,
				 struct flow_instance *old)
{
	struct flow_state *x, *copy;
	int err;

	list_for_each_entry(x, &old->exit_states, node) {
		if (x->pending)
			continue;
		copy = flow_new_state(env, x->prev_insn_idx);
		if (!copy)
			return -ENOMEM;
		err = bpf_copy_verifier_state(env, &copy->st, &x->st);
		if (err) {
			flow_free_state(env, copy);
			return err;
		}
		copy->kind = FLOW_FUNC_EXIT;
		copy->st.instance_id = instance->id;
		flow_find(env, copy);
		flow_insert(env, copy);
	}
	return 0;
}

/* @s gets to the first insn. @t is there and does not subsume @s. */
static int flow_grow_instance(struct bpf_verifier_env *env, struct flow_state *t,
			      struct flow_state *s, struct bpf_loop *leftover_loop)
{
	u64 args = flow_readable_args(t->st.frame[0]);
	struct flow_instance *old = t->started_instance, *instance = old;
	int err;

	if (!old->entry_state) {
		instance = flow_new_instance(env, t);
		if (!instance)
			return -ENOMEM;
		instance->cost = old->cost;
	}
	flow_unlink(env, t);
	err = bpf_states_join(env, &t->st, &s->st, leftover_loop ?: &env->flow->call_loop,
			      instance != old);
	t->started_instance = instance;
	flow_find(env, t);
	flow_link(env, t);
	if (args != flow_readable_args(t->st.frame[0]))
		flow_free_list(env, &instance->exit_states);
	else if (!err && instance != old)
		err = flow_copy_exit_states(env, instance, old);
	old->replaced = instance != old;
	if (old->ended)
		flow_free_list(env, &old->exit_states);
	return err;
}

/*
 * A chain of calls multiplies the instances. The functions that have more than one instance
 * divide a budget. When a function has used its part, the next calls are joined.
 */
static bool flow_may_add_instance(struct bpf_verifier_env *env, int subprog)
{
	struct bpf_flow *flow = env->flow;

	if (flow->cost[subprog] * flow->budget_func_cnt <= flow->budget)
		return true;
	env->calls_joined = true;
	return false;
}

static bool flow_in_peeled_trip(const struct bpf_verifier_state *st)
{
	const struct loop_stack_entry *e;
	u32 fr, i;

	for (fr = 0; fr <= st->curframe; fr++)
		for (i = 0, e = st->frame[fr]->loop_stack; i < st->frame[fr]->loop_stack_cnt; i++)
			if (e[i].peeled && e[i].loop->kind != BPF_LOOP_RECURSION)
				return true;
	return false;
}

/*
 * The call at @call_idx in @caller goes to a function that is verified on its own. @entry is
 * the state at its first insn. Both states are taken. The first insn is the only join point
 * for the states of two calls.
 *
 *  call1 f(0) --+                       pass 0: join          -> one instance for both calls
 *  call2 f(1) --+--> first insn of f    data dep r1 differs   -> one instance for each call
 *
 * An instance that has started does not grow. The join starts a new instance:
 *
 *  call1 f(0)   instance 1: f(0)      exits 1 --> call1
 *  call2 f(1)   instance 2: f(0..1)   exits 1 --> call2, call3   at once: the caller continues
 *  call3 f(2)               f(0..2)   exits 2 --> call2, call3   later, if they have more
 *
 * An argument can have another type or object. Then the old exit states can refer to what the
 * new call did not pass in, so the call waits. It waits in a peeled trip too: a late exit state
 * checks all later trips again.
 */
int bpf_flow_call(struct bpf_verifier_env *env, struct bpf_verifier_state *caller,
		  struct bpf_verifier_state *entry, int subprog, int call_idx)
{
	struct loop_stack_entry *e = bpf_top_loop(entry->frame[0]);
	struct bpf_loop *leftover_loop = e && e->trip && !e->peeled ? e->loop : NULL;
	struct flow_instance *instance, *from = env->flow->instances[caller->instance_id];
	u64 *cost = &env->flow->cost[subprog];
	struct flow_state *w, *s, *t, *tn, *x;
	bool subsumed;
	int err;

	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "call at %d waits for func#%d\n", call_idx, subprog);

	s = flow_new_state(env, call_idx);
	if (!s)
		return -ENOMEM;
	swap(s->st, *entry);
	s->st.insn_idx = env->subprog_info[subprog].start;
	s->st.last_insn_idx = call_idx;
	s->kind = FLOW_FUNC_ENTRY;
	err = bpf_clean_verifier_state(env, &s->st);
	if (err)
		goto free;
again:
	flow_for_each_near(env, s, t, tn) {
		if (!flow_same_join_key(env, t, s) ||
		    bpf_must_keep_apart(env, &t->st, &s->st, s->kind == FLOW_JOINED_CALLS ||
					(leftover_loop && flow_same_entry(leftover_loop, t, s)) ?
					BPF_JOIN_POINT_HEADER : BPF_JOIN_POINT_CALLS,
					leftover_loop ? e : NULL))
			continue;
		subsumed = bpf_state_subsumes(env, &t->st, &s->st);
		if (!subsumed && t->st.speculative != s->st.speculative)
			continue;
		env->imprecise |= !env->err;
		if (!subsumed)
			err = flow_grow_instance(env, t, s, leftover_loop);
		flow_free_state(env, s);
		if (err)
			return err;
		goto wait;
	}
	if (s->kind == FLOW_FUNC_ENTRY && !flow_may_add_instance(env, subprog)) {
		s->kind = FLOW_JOINED_CALLS;
		goto again;
	}
	t = s;
	t->started_instance = flow_new_instance(env, t);
	if (!t->started_instance) {
		err = -ENOMEM;
		goto free;
	}
	/* the first instance is free */
	if ((*cost)++)
		t->started_instance->cost = cost;
	env->flow->budget_func_cnt += *cost == 2;
	flow_link(env, t);
wait:
	w = flow_new_state(env, caller->last_insn_idx);
	if (!w)
		return -ENOMEM;
	swap(w->st, *caller);
	w->st.insn_idx = call_idx;
	instance = w->callee = t->started_instance;
	from->open_call_cnt++;
	from->self_call_cnt += from == instance;
	from->group->busy_cnt += from->group != instance->group;
	flow_insert(env, w);
	instance->in_peeled_trip |= t->kind == FLOW_FUNC_ENTRY &&
				    (from->in_peeled_trip || flow_in_peeled_trip(&w->st));
	if (instance->entry_state &&
	    (list_empty(&instance->exit_states) || instance->in_peeled_trip))
		flow_set_pending(env, w);
	list_for_each_entry(x, &instance->exit_states, node)
		if (!err && !x->pending && w->callee)
			err = flow_apply_exit(env, w, x);
	if (instance->ended && w->callee)
		flow_free_state(env, w);
	return err;
free:
	flow_free_state(env, s);
	return err;
}

/* @st came to exit of the function that is verified on its own. It is taken. */
int bpf_flow_exit(struct bpf_verifier_env *env, struct bpf_verifier_state *st, int exit_idx)
{
	struct bpf_subprog_info *sub = &env->subprog_info[st->frame[0]->subprogno];
	struct loop_stack_entry *e = bpf_top_loop(st->frame[0]);
	struct flow_state *x;
	int err;

	st->insn_idx = exit_idx;
	err = bpf_clean_verifier_state(env, st);
	if (err)
		return err;
	x = flow_new_state(env, exit_idx);
	if (!x)
		return -ENOMEM;
	x->st = *st;
	memset(st, 0, sizeof(*st));
	/* all exit states are compared at the first exit */
	sub->first_exit = sub->first_exit ?: exit_idx;
	x->st.insn_idx = sub->first_exit;
	x->kind = FLOW_FUNC_EXIT;
	return flow_prune_or_join(env, x, e && !e->peeled ? e->loop : NULL, false);
}

static void flow_add_ended(struct flow_instance *instance, struct flow_instance **ended)
{
	if (instance->ended)
		return;
	instance->ended = true;
	instance->next = *ended;
	*ended = instance;
}

/*
 * A state of @instance comes from another state of it, or from an exit state that one of its
 * open calls gets. If there is none of these, @instance ended. The same holds for a group.
 * The instances in the leftover of a recursion are a group: they can wait for each other.
 * All other instances are group 0.
 */
static void flow_find_ended(struct flow_instance *instance, struct flow_instance **ended)
{
	struct flow_group *group = instance->group;

	if (!instance->pending_cnt && instance->open_call_cnt == instance->self_call_cnt)
		flow_add_ended(instance, ended);
	while (!group->busy_cnt && group->instances) {
		flow_add_ended(group->instances, ended);
		group->instances = group->instances->next_in_group;
	}
}

/* If an instance ended, its waiting calls have all exit states */
static void flow_end_instance(struct bpf_verifier_env *env, struct flow_instance *instance)
{
	struct flow_instance *from, *ended = NULL;
	struct flow_state *w, *wn;

	flow_find_ended(instance, &ended);
	while ((instance = ended)) {
		ended = instance->next;
		list_for_each_entry_safe(w, wn, &instance->waiting_calls, node) {
			from = flow_state_instance(env->flow, w);
			flow_free_state(env, w);
			flow_find_ended(from, &ended);
		}
		flow_free_list(env, &instance->done);
		if (instance->replaced)
			flow_free_list(env, &instance->exit_states);
	}
}

/*
 * Make the next pending state the current one. env->cur_state has to be empty.
 * Returns -ENOENT when nothing is pending.
 */
int bpf_flow_next(struct bpf_verifier_env *env, int *prev_insn_idx, u64 *log_pos, u64 *diag_pos)
{
	struct bpf_flow *flow = env->flow;
	struct flow_state *s, *t, *tn;
	struct flow_instance *instance;
	struct rb_node *n;
	bool leftover, starts;
	int err = 0;

again:
	if (flow->last_instance && flow->last_instance->cost)
		*flow->last_instance->cost += env->cost - flow->charged_cost;
	if (flow->last_is_apart)
		flow->apart_cost += env->cost - flow->charged_cost;
	flow->charged_cost = env->cost;
	if (flow->last_instance)
		flow_end_instance(env, flow->last_instance);
	n = rb_first_cached(&flow->pending);
	if (!n)
		return -ENOENT;
	s = rb_entry(n, struct flow_state, rb);
	flow_clear_pending(flow, s);
	flow->last_instance = flow_state_instance(flow, s);
	/*
	 * Is another state at this insn? In a loop the states go one by one, and only the join
	 * points of a leftover keep them. So a yes holds up to a join point that is not peeled.
	 */
	if (test_bit(s->st.insn_idx, flow->join_points) && !flow_in_peeled_trip(&s->st))
		s->from_apart = false;
	flow->last_is_apart = s->from_apart || flow->nr_states[s->st.insn_idx] > 1;
	instance = s->callee;
	if (instance) {
		if (instance->entry_state && !instance->priority) {
			instance->priority = BIT_ULL(63) - ++flow->priority_gen;
			flow_clear_pending(flow, instance->entry_state);
			flow_set_pending(env, instance->entry_state);
		}
		goto again;
	}
	instance = flow->instances[s->st.instance_id];
	while (!s->started_instance && !list_empty(&instance->done)) {
		t = list_last_entry(&instance->done, struct flow_state, node);
		if ((t->late_exit_reaches && instance->open_call_cnt) || !flow_loop_is_left(t, s))
			break;
		flow_free_state(env, t);
	}

	flow_free_unused(env);

	env->insn_idx = s->st.insn_idx;
	if (s->kind == FLOW_FUNC_EXIT) {
		list_for_each_entry_safe(t, tn, &instance->waiting_calls, node) {
			err = flow_apply_exit(env, t, s);
			if (err)
				return err;
		}
		goto again;
	}
	*prev_insn_idx = s->prev_insn_idx;
	if (env->path_sensitive) {
		*log_pos = s->log_pos;
		*diag_pos = s->diag_pos;
	}
	leftover = s->kind == FLOW_LEFTOVER;
	starts = leftover || s->started_instance;
	if (!flow_keep(env, s)) {
		flow_unlink(env, s);
	} else if (!starts) {
		err = bpf_copy_verifier_state(env, env->cur_state, &s->st);
		if (s->kind != FLOW_AT)
			flow_insert_peeled(env, s);
		goto out;
	} else {
		t = s;
		s = flow_new_state(env, t->prev_insn_idx);
		if (!s)
			return -ENOMEM;
		err = bpf_copy_verifier_state(env, &s->st, &t->st);
		if (err) {
			flow_free_state(env, s);
			return err;
		}
		if (t->started_instance) {
			s->st.instance_id = t->started_instance->id;
			t->started_instance->entry_state = NULL;
		}
	}
	if (starts) {
		err = flow_add(env, s, leftover);
		if (err)
			return err;
		goto again;
	}
	swap(*env->cur_state, s->st);
	flow_free_state(env, s);
out:
	/* all ids have names, see bpf_renumber_ids() */
	env->id_gen = 0;
	/* the state at the header stays as it was widened, else the sequence possibly never ends */
	if (!err && env->cur_state->equations.needs_refine)
		bpf_equations_refine_all(env, env->cur_state);
	return err;
}
