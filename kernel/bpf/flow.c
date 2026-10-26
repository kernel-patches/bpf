// SPDX-License-Identifier: GPL-2.0-only
/*
 * The main pass of the verifier as a fixpoint over the control flow graph.
 *
 * Every insn that starts a basic block has a set of states. The state that
 * arrives there is
 * - dropped, if it is within a state of the set,
 * - joined with a state of the set, if there is a join, see bpf_states_join(),
 *   that doesn't make up what neither of them has, see flow_join_makes_up(),
 * - added to the set otherwise.
 * What is new in the set is pending. Pending states are processed in the order
 * of the program in which a loop is done with before what follows it, see
 * flow_compute_order(). The pass ends when nothing is pending.
 *
 * Loops. The state that enters a loop is made to stand for all iterations with
 * what scalar evolution knows about the loop, see bpf_flow_loop_enter().
 * The state that comes back to the loop head is expected to be within it.
 * If it is not, the two are joined, what grew is forgotten, and the loop is
 * done again.
 *
 * Functions. A static function that gets nothing but numbers and pointers to
 * what is not the stack is verified on its own, for the states at its entry
 * and not for every chain of calls. The call waits. What comes out of the
 * function goes to all calls that wait for the states it comes from.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/jhash.h>
#include <linux/rbtree.h>
#include <linux/slab.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/*
 * States at an insn that have no join: kinds of values, references, chains of calls.
 * A state that arrives is compared with all of them, so the work is the square of it.
 */
#define BPF_FLOW_MAX_STATES	1024
/* All states that are there at a time: that many for every insn of the prog, and some. */
#define BPF_FLOW_LIVE_PER_INSN	16
#define BPF_FLOW_LIVE_BASE	4096
/* All states that were ever there. It bounds the work by the size of the prog. */
#define BPF_FLOW_TOTAL_PER_INSN	256
#define BPF_FLOW_TOTAL_BASE	65536
/* A state that was joined that many times is in a cycle that has no loop head. */
#define BPF_FLOW_MAX_JOINS	16
/* bpf_loop() with that many iterations at most is walked. */
#define BPF_FLOW_MAX_CALLBACKS	8
/* What a callback returns to the helper with is joined that many times before it is widened. */
#define BPF_FLOW_CALLBACK_JOINS	4
/* That many states in a loop that differ in their iterators: the loop makes new ones. */
#define BPF_FLOW_MAX_ITERS	8

enum flow_cycle {
	FLOW_NO_CYCLE,
	/* what grew is forgotten */
	FLOW_CYCLE,
	/* after a while. A flag that a callback sets doesn't grow any further. */
	FLOW_CALLBACK_CYCLE,
};

struct flow_state {
	struct bpf_verifier_state st;
	struct list_head node;		/* states at the insn */
	struct rb_node rb;		/* pending states */
	int prev_insn_idx;
	u32 seq;
	/* see flow_kind() */
	u32 kind;
	u16 joins;
	bool pending;
	/* the order of pending states, see flow_set_pending() */
	u8 key_len;
	u32 key[MAX_CALL_FRAMES + 1];
};

/* the call that waits for what comes out of the function */
struct flow_waiter {
	struct list_head node;
	struct bpf_verifier_state st;
	u32 entry;
	int call_idx;
	/* the call is verified in the context of the caller */
	bool dead;
};

struct flow_exit {
	struct list_head node;
	struct bpf_verifier_state st;
	u32 entry;
	u16 joins;
};

struct flow_func {
	struct list_head waiters;
	struct list_head exits;
	int exit_idx;			/* all exits are compared as if they were here */
};

struct flow_united {
	u32 subprog;
	u32 a, b;
};

struct flow_kept {
	struct list_head node;
	struct bpf_verifier_state st;
};

/* What has to stay a known constant at an insn */
struct flow_need {
	u64 slots;			/* of the stack, fp-8 is bit 0 */
	u16 regs;
};

struct bpf_flow {
	/* computed once */
	u32 len;			/* of the prog during the pass */
	u32 nr_funcs;
	u32 *pos;			/* place of the insn in the order */
	u32 *rank;			/* callers go first */
	struct flow_need *need_const;	/* see flow_compute_need_const() */
	struct flow_need *stack_off;
	struct flow_need *tested;
	unsigned long *point;		/* insn starts a basic block */
	unsigned long *keep;		/* states that were processed are compared with */

	/* of the pass */
	struct list_head *states;	/* per insn */
	struct list_head *enter;	/* per insn: the states that enter the loop at its head */
	u32 *nr_states;
	struct rb_root_cached pending;
	struct flow_func *funcs;
	u32 *entry_up;			/* entries that met are one set */
	u32 entry_cnt, entry_cap;
	struct flow_united *united;
	u32 united_cnt, united_cap;
	struct list_head kept;
	/* what leaves a loop if its guard is going to, see bpf_flow_park(), and what does */
	struct list_head parked;
	struct list_head unparked;
	struct bpf_verifier_state tmp;
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
	int len = env->prog->len, i, s, n, h, top, depth;
	int *next, *head, *tail, *stack;
	unsigned long *linked;
	u32 pos = 0;
	int err = -ENOMEM;

	/* lists of members are indexed by loop head, len is the function */
	next = kvmalloc_array(len, sizeof(int), GFP_KERNEL_ACCOUNT);
	head = kvmalloc_array(len + 1, sizeof(int), GFP_KERNEL_ACCOUNT);
	tail = kvmalloc_array(len + 1, sizeof(int), GFP_KERNEL_ACCOUNT);
	stack = kvmalloc_array(len + 1, sizeof(int), GFP_KERNEL_ACCOUNT);
	linked = kvcalloc(BITS_TO_LONGS(len), sizeof(long), GFP_KERNEL_ACCOUNT);
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
	/* as long as the program doesn't go on when there is nothing left, see iter_is_drained() */
	return bpf_insn_is_iter_next(env, insn);
}

/*
 * What stops a loop at run time is a fact about the program: may_goto or
 * bpf_iter_*_next() that every trip goes through. A loop without it gets
 * may_goto unless the number of its trips turns out to be known.
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

static void flow_place_guards(struct bpf_verifier_env *env, int h, u32 *seen)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_loop *loop = aux[h].loop;
	int i, n, o, found = -1;

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
			if (!loop->backedges[i].latches_cnt ||
			    loop->backedges[i].latches[0] != loop->backedges[i].from)
				goto header;
		for (i = 0; i < loop->backedges_cnt; i++)
			flow_set_guard(env, h, loop->backedges[i].from);
		return;
	}

	/* seen[n]: the number of back edges that n dominates */
	for (i = 0; i < loop->backedges_cnt; i++)
		for (n = loop->backedges[i].from; n >= 0; n = n == h ? -1 : env->idoms[n])
			seen[n]++;
	for (n = loop->backedges[0].from; n >= 0 && found < 0; n = n == h ? -1 : env->idoms[n])
		if (seen[n] == loop->backedges_cnt && bpf_insn_leaves_loop(env, h, n))
			found = n;
	for (i = 0; i < loop->backedges_cnt; i++)
		for (n = loop->backedges[i].from; n >= 0; n = n == h ? -1 : env->idoms[n])
			seen[n] = 0;
	if (found >= 0) {
		flow_set_guard(env, h, found);
		return;
	}

	for (i = 0; i < loop->backedges_cnt; i++)
		if (!loop->backedges[i].latches_cnt)
			goto header;
	for (i = 0; i < loop->backedges_cnt; i++)
		flow_set_guard(env, h, loop->backedges[i].latches[0]);
	return;

header:
	/*
	 * In front of a jump may_goto goes where the jump goes. From the head to where the loop
	 * is left is not an edge of the program: it skips what is in the loop. If that is what
	 * stops a loop around this one, bpf_iter_*_next() or i++, and the exit leads back to
	 * the head of that loop, the program goes round and round from may_goto to may_goto.
	 * So leave all loops.
	 */
	for (o = h; aux[o].loop_header >= 0; o = aux[o].loop_header)
		;
	/* a loop that has no exit can only be stopped together with the program */
	if (!aux[o].loop->exits_cnt)
		return;
	aux[h].guard_place = true;
	aux[h].guard_at_header = true;
	aux[h].guard_to = aux[o].loop->exits[0].to;
	loop->has_guards = true;
}

static int flow_compute_loop_bounds(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	int len = env->prog->len, h, i, n;
	struct bpf_loop *loop;
	u32 *seen;

	seen = kvcalloc(len, sizeof(*seen), GFP_KERNEL_ACCOUNT);
	if (!seen)
		return -ENOMEM;

	for (i = 0; i < len; i++) {
		for (h = bpf_loop_at_index(env, i); h >= 0; h = aux[h].loop_header) {
			aux[h].loop->nr_insns++;
			if (bpf_pseudo_call(&env->prog->insnsi[i]) ||
			    bpf_is_callx(&env->prog->insnsi[i]))
				aux[h].loop->has_calls = true;
		}
	}

	for (h = 0; h < len; h++) {
		loop = aux[h].loop;
		if (!loop)
			continue;
		/* see flow_place_guards() about loops with more than one entry */
		loop->rt_bounded = !loop->backedges_overflow && !loop->irreducible;
		for (i = 0; i < loop->backedges_cnt && loop->rt_bounded; i++) {
			for (n = loop->backedges[i].from; n >= 0 && n != h; n = env->idoms[n])
				if (flow_is_bound(env, h, n))
					break;
			if (n < 0 || !flow_is_bound(env, h, n))
				loop->rt_bounded = false;
		}
		/* also when it's bounded: the main pass may find that it's not */
		flow_place_guards(env, h, seen);
	}
	kvfree(seen);
	return 0;
}

/* The slot that @insn spills to or fills from, if it's one that struct flow_need has a bit for */
static int flow_fp_slot(const struct bpf_insn *insn, u8 base)
{
	u8 mode = BPF_MODE(insn->code);

	if (base != BPF_REG_FP || (mode != BPF_MEM && mode != BPF_MEMSX) ||
	    insn->off >= 0 || insn->off < -64 * BPF_REG_SIZE || insn->off % BPF_REG_SIZE)
		return -1;
	return -insn->off / BPF_REG_SIZE - 1;
}

/*
 * A number is added to a pointer to the stack. A store at an offset that is not known
 * forgets what the slots it may hit hold, pointers above all.
 */
static u16 flow_stack_off_regs(struct bpf_verifier_env *env, int idx)
{
	u16 ptrs = env->insn_aux_data[idx].stack_ptrs;
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	u8 op = BPF_OP(insn->code);

	if (BPF_CLASS(insn->code) != BPF_ALU64 || BPF_SRC(insn->code) != BPF_X ||
	    (op != BPF_ADD && op != BPF_SUB))
		return 0;
	if ((ptrs & BIT(insn->dst_reg)) && !(ptrs & BIT(insn->src_reg)))
		return BIT(insn->src_reg);
	if (op == BPF_ADD && (ptrs & BIT(insn->src_reg)) && !(ptrs & BIT(insn->dst_reg)))
		return BIT(insn->dst_reg);
	return 0;
}

/* A jump that compares a register with a constant */
static u16 flow_tested_regs(const struct bpf_insn *insn)
{
	u8 class = BPF_CLASS(insn->code), op = BPF_OP(insn->code);

	if ((class != BPF_JMP && class != BPF_JMP32) || BPF_SRC(insn->code) != BPF_K ||
	    op == BPF_JA || op == BPF_CALL || op == BPF_EXIT || op == BPF_JCOND)
		return 0;
	return BIT(insn->dst_reg);
}

static bool flow_is_copy(const struct bpf_insn *insn)
{
	return BPF_OP(insn->code) == BPF_MOV && BPF_SRC(insn->code) == BPF_X &&
	       !insn->off && !insn->imm;
}

enum flow_need_kind {
	FLOW_NEED_ARG,
	FLOW_NEED_STACK_OFF,
	FLOW_NEED_JUMP,
};

/*
 * Some arguments of kfuncs and helpers have to be known constants: the id of a type,
 * the size of what is reserved in a ring buffer.
 * A compiler makes one call of
 *	if (x) p = bpf_rdonly_cast(q, ID); else p = bpf_rdonly_cast(q, 0);
 * and one store of
 *	if (x) a[n++] = p; else b[m++] = p;
 * where a and b are on the stack.
 * The join of two constants is not a constant. Find the registers and the slots of the stack
 * that end up in such arguments, or in offsets in the stack, like live
 * registers are found: backwards, until nothing changes.
 * States in which they differ are not joined.
 * Nothing depends on it but what is known: it's fine to miss a store through a pointer.
 *
 * FLOW_NEED_JUMP: those that a jump ahead compares with a constant, as they are, see
 * flow_join_makes_up().
 */
static int flow_compute_need_const(struct bpf_verifier_env *env, struct flow_need **pneed,
				   enum flow_need_kind kind)
{
	struct bpf_insn *insns = env->prog->insnsi, *insn;
	struct flow_need in, out, *need;
	struct bpf_iarray *succ;
	bool changed = true, any = false;
	int i, s, idx, slot;
	u16 *gen;
	u8 class;

	need = kvcalloc(env->prog->len, sizeof(*need), GFP_KERNEL_ACCOUNT);
	gen = kvcalloc(env->prog->len, sizeof(u16), GFP_KERNEL_ACCOUNT);
	*pneed = need;
	if (!need || !gen) {
		kvfree(gen);
		return -ENOMEM;
	}
	for (i = 0; i < env->prog->len; i++) {
		if (kind == FLOW_NEED_JUMP)
			gen[i] = flow_tested_regs(&insns[i]);
		else if (kind == FLOW_NEED_STACK_OFF)
			gen[i] = flow_stack_off_regs(env, i);
		else if (bpf_pseudo_kfunc_call(&insns[i]))
			gen[i] = bpf_kfunc_const_arg_regs(env, &insns[i]);
		else if (bpf_helper_call(&insns[i]))
			gen[i] = bpf_helper_const_arg_regs(env, &insns[i]);
		any |= gen[i];
	}
	while (any && changed) {
		changed = false;
		for (i = 0; i < env->cfg.cur_postorder; i++) {
			idx = env->cfg.insn_postorder[i];
			insn = &insns[idx];
			class = BPF_CLASS(insn->code);
			succ = bpf_insn_successors(env, idx);
			out.regs = 0;
			out.slots = 0;
			for (s = 0; s < succ->cnt; s++) {
				out.regs |= need[succ->items[s]].regs;
				out.slots |= need[succ->items[s]].slots;
			}
			in = out;
			if (class == BPF_JMP && BPF_OP(insn->code) == BPF_CALL) {
				in.regs &= ~GENMASK(BPF_REG_5, BPF_REG_0);
				s = idx + insn->imm + 1;
				if (bpf_pseudo_call(insn) &&
				    !bpf_subprog_is_global(env, bpf_find_subprog(env, s)))
					in.regs |= need[s].regs & GENMASK(BPF_REG_5, BPF_REG_1);
			} else if (class == BPF_LDX || class == BPF_LD) {
				slot = class == BPF_LDX ? flow_fp_slot(insn, insn->src_reg) : -1;
				if (slot >= 0 && (out.regs & BIT(insn->dst_reg)))
					in.slots |= BIT_ULL(slot);
				in.regs &= ~BIT(insn->dst_reg);
			} else if (class == BPF_STX || class == BPF_ST) {
				slot = flow_fp_slot(insn, insn->dst_reg);
				if (slot >= 0 && (out.slots & BIT_ULL(slot))) {
					in.slots &= ~BIT_ULL(slot);
					if (class == BPF_STX)
						in.regs |= BIT(insn->src_reg);
				}
			} else if ((class == BPF_ALU || class == BPF_ALU64) &&
				   (out.regs & BIT(insn->dst_reg)) && kind == FLOW_NEED_JUMP) {
				in.regs &= ~BIT(insn->dst_reg);
				if (flow_is_copy(insn))
					in.regs |= BIT(insn->src_reg);
			} else if ((class == BPF_ALU || class == BPF_ALU64) &&
				   (out.regs & BIT(insn->dst_reg))) {
				/* the result is known when what it is made of is */
				if (BPF_OP(insn->code) == BPF_MOV)
					in.regs &= ~BIT(insn->dst_reg);
				if (BPF_SRC(insn->code) == BPF_X)
					in.regs |= BIT(insn->src_reg);
			}
			in.regs |= gen[idx];
			if (in.regs != need[idx].regs || in.slots != need[idx].slots) {
				need[idx] = in;
				changed = true;
			}
		}
	}
	kvfree(gen);
	if (!any) {
		kvfree(need);
		*pneed = NULL;
	}
	return 0;
}

int bpf_flow_prepare(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct bpf_insn *insns = env->prog->insnsi;
	int len = env->prog->len, i, s, err;
	struct bpf_iarray *succ;
	struct bpf_flow *flow;
	u8 *preds;

	flow = kzalloc_obj(*flow, GFP_KERNEL_ACCOUNT);
	if (!flow)
		return -ENOMEM;
	env->flow = flow;
	INIT_LIST_HEAD(&flow->kept);
	INIT_LIST_HEAD(&flow->parked);
	INIT_LIST_HEAD(&flow->unparked);
	flow->pending = RB_ROOT_CACHED;

	flow->pos = kvcalloc(len, sizeof(u32), GFP_KERNEL_ACCOUNT);
	flow->rank = kvcalloc(env->subprog_cnt + 1, sizeof(u32), GFP_KERNEL_ACCOUNT);
	flow->point = kvcalloc(BITS_TO_LONGS(len), sizeof(long), GFP_KERNEL_ACCOUNT);
	flow->keep = kvcalloc(BITS_TO_LONGS(len), sizeof(long), GFP_KERNEL_ACCOUNT);
	flow->states = kvmalloc_array(len, sizeof(*flow->states), GFP_KERNEL_ACCOUNT);
	flow->enter = kvmalloc_array(len, sizeof(*flow->enter), GFP_KERNEL_ACCOUNT);
	flow->nr_states = kvcalloc(len, sizeof(u32), GFP_KERNEL_ACCOUNT);
	flow->funcs = kvcalloc(env->subprog_cnt + 1, sizeof(*flow->funcs), GFP_KERNEL_ACCOUNT);
	preds = kvcalloc(len, 1, GFP_KERNEL_ACCOUNT);
	if (!flow->pos || !flow->rank || !flow->point || !flow->keep || !flow->states ||
	    !flow->enter ||
	    !flow->nr_states || !flow->funcs || !preds) {
		kvfree(preds);
		return -ENOMEM;
	}
	for (i = 0; i < len; i++) {
		INIT_LIST_HEAD(&flow->states[i]);
		INIT_LIST_HEAD(&flow->enter[i]);
	}
	for (i = 0; i <= env->subprog_cnt; i++) {
		INIT_LIST_HEAD(&flow->funcs[i].waiters);
		INIT_LIST_HEAD(&flow->funcs[i].exits);
		flow->funcs[i].exit_idx = -1;
	}
	/* from here on there is something for bpf_flow_reset() to look at */
	flow->len = len;
	flow->nr_funcs = env->subprog_cnt + 1;

	/* subprog_topo_order[] has callees first */
	for (i = 0; i < env->subprog_cnt; i++)
		flow->rank[env->subprog_topo_order[i]] = env->subprog_cnt - i;

	for (i = 0; i < len; i++) {
		succ = bpf_insn_successors(env, i);
		iarray_for_each(s, succ) {
			if (preds[s] < 2)
				preds[s]++;
			if (aux[i].bb_end)
				__set_bit(s, flow->point);
		}
		/* where the callees come back to */
		if (bpf_pseudo_call(&insns[i]) || bpf_is_callx(&insns[i])) {
			if (i + 1 < len) {
				__set_bit(i + 1, flow->point);
				__set_bit(i + 1, flow->keep);
			}
		}
		if (aux[i].calls_callback) {
			__set_bit(i, flow->point);
			__set_bit(i, flow->keep);
		}
		if (aux[i].loop) {
			__set_bit(i, flow->point);
			__set_bit(i, flow->keep);
		}
		if (bpf_is_ldimm64(&insns[i]))
			i++;
	}
	for (i = 0; i < len; i++)
		if (preds[i] > 1)
			__set_bit(i, flow->keep);
	for (i = 0; i < env->subprog_cnt; i++) {
		__set_bit(env->subprog_info[i].start, flow->point);
		__set_bit(env->subprog_info[i].start, flow->keep);
	}
	kvfree(preds);

	err = flow_compute_order(env, flow);
	if (err)
		return err;
	err = flow_compute_need_const(env, &flow->need_const, FLOW_NEED_ARG);
	err = err ?: flow_compute_need_const(env, &flow->stack_off, FLOW_NEED_STACK_OFF);
	err = err ?: flow_compute_need_const(env, &flow->tested, FLOW_NEED_JUMP);
	if (err)
		return err;
	return flow_compute_loop_bounds(env);
}

static void flow_free_state(struct bpf_verifier_env *env, struct flow_state *s)
{
	bpf_free_verifier_state(&s->st, false);
	kfree(s);
	env->flow->live_states--;
}

/* What a pass leaves behind. */
void bpf_flow_reset(struct bpf_verifier_env *env)
{
	struct bpf_flow *flow = env->flow;
	struct flow_waiter *w, *wn;
	struct flow_state *s, *sn;
	struct flow_kept *k, *kn;
	struct flow_exit *x, *xn;
	int i;

	if (!flow || !flow->states || !flow->enter)
		return;
	for (i = 0; i < flow->len; i++) {
		list_for_each_entry_safe(s, sn, &flow->states[i], node) {
			list_del(&s->node);
			flow_free_state(env, s);
		}
		list_for_each_entry_safe(s, sn, &flow->enter[i], node) {
			list_del(&s->node);
			flow_free_state(env, s);
		}
		flow->nr_states[i] = 0;
	}
	flow->pending = RB_ROOT_CACHED;
	for (i = 0; i < flow->nr_funcs && flow->funcs; i++) {
		list_for_each_entry_safe(w, wn, &flow->funcs[i].waiters, node) {
			bpf_free_verifier_state(&w->st, false);
			kfree(w);
		}
		list_for_each_entry_safe(x, xn, &flow->funcs[i].exits, node) {
			bpf_free_verifier_state(&x->st, false);
			kfree(x);
		}
		INIT_LIST_HEAD(&flow->funcs[i].waiters);
		INIT_LIST_HEAD(&flow->funcs[i].exits);
		flow->funcs[i].exit_idx = -1;
	}
	list_for_each_entry_safe(k, kn, &flow->kept, node) {
		bpf_free_verifier_state(&k->st, false);
		kfree(k);
	}
	INIT_LIST_HEAD(&flow->kept);
	list_splice_init(&flow->unparked, &flow->parked);
	list_for_each_entry_safe(s, sn, &flow->parked, node) {
		list_del(&s->node);
		flow_free_state(env, s);
	}
	bpf_free_verifier_state(&flow->tmp, false);
	memset(&flow->tmp, 0, sizeof(flow->tmp));
	flow->entry_cnt = 0;
	flow->united_cnt = 0;
}

void bpf_flow_free(struct bpf_verifier_env *env)
{
	struct bpf_flow *flow = env->flow;

	if (!flow)
		return;
	bpf_flow_reset(env);
	kvfree(flow->pos);
	kvfree(flow->rank);
	kvfree(flow->need_const);
	kvfree(flow->stack_off);
	kvfree(flow->tested);
	kvfree(flow->point);
	kvfree(flow->keep);
	kvfree(flow->states);
	kvfree(flow->enter);
	kvfree(flow->nr_states);
	kvfree(flow->funcs);
	kvfree(flow->entry_up);
	kvfree(flow->united);
	kfree(flow);
	env->flow = NULL;
}

bool bpf_flow_is_point(struct bpf_verifier_env *env, int insn_idx)
{
	return test_bit(insn_idx, env->flow->point);
}

/* A copy of @st that lives as long as the pass. */
struct bpf_verifier_state *bpf_flow_keep_state(struct bpf_verifier_env *env,
					       const struct bpf_verifier_state *st)
{
	struct flow_kept *k = kzalloc_obj(*k, GFP_KERNEL_ACCOUNT);

	if (!k)
		return NULL;
	list_add(&k->node, &env->flow->kept);
	if (bpf_copy_verifier_state(&k->st, st))
		return NULL;
	return &k->st;
}

/*
 * Both are in a loop whose iterations are kept apart: an iteration is done with before
 * the next one begins. A back edge in the middle of the loop would run ahead otherwise and
 * leave the rest of every iteration behind, see flow_earlier_trip(). The state that stands
 * for all iterations comes last.
 */
static int flow_cmp_trips(const struct bpf_func_state *fa, const struct bpf_func_state *fb)
{
	const struct loop_stack_entry *ea, *eb;
	u32 i, ta, tb;

	for (i = 0; i < fa->loop_stack_cnt && i < fb->loop_stack_cnt; i++) {
		ea = &fa->loop_stack[i];
		eb = &fb->loop_stack[i];
		if (ea->loop_id != eb->loop_id)
			break;
		ta = ea->apart ? ea->trip : U32_MAX;
		tb = eb->apart ? eb->trip : U32_MAX;
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

	for (i = 0; i < a->key_len && i < b->key_len; i++) {
		/* key[i] is the place in frame[i - 1] */
		if (i) {
			cmp = flow_cmp_trips(a->st.frame[i - 1], b->st.frame[i - 1]);
			if (cmp)
				return cmp < 0;
		}
		if (a->key[i] != b->key[i])
			return a->key[i] < b->key[i];
	}
	if (a->key_len != b->key_len)
		return a->key_len < b->key_len;
	return a->seq < b->seq;
}

/*
 * Callers first, so that the calls of a function get to it before it is looked
 * at. Then by the place of the call in every frame: what is called is done
 * with before what follows the call.
 */
static void flow_set_pending(struct bpf_flow *flow, struct flow_state *s)
{
	const struct bpf_verifier_state *st = &s->st;
	u32 i;

	s->key[0] = flow->rank[st->frame[0]->subprogno];
	/* the place in the function makes the rank of the function redundant below */
	for (i = 0; i < st->curframe && i + 2 < ARRAY_SIZE(s->key); i++)
		s->key[i + 1] = flow->pos[st->frame[i + 1]->callsite];
	s->key[i + 1] = flow->pos[st->insn_idx];
	s->key_len = i + 2;
	s->pending = true;
	rb_add_cached(&s->rb, &flow->pending, flow_less);
}

static void flow_unlink(struct bpf_verifier_env *env, struct flow_state *s)
{
	struct bpf_flow *flow = env->flow;

	if (s->pending)
		rb_erase_cached(&s->rb, &flow->pending);
	s->pending = false;
	list_del(&s->node);
	flow->nr_states[s->st.insn_idx]--;
}

/* Entries of a function whose states met are one set: what comes out is for all of them. */
static u32 flow_entry_find(struct bpf_flow *flow, u32 e)
{
	while (flow->entry_up[e] != e) {
		flow->entry_up[e] = flow->entry_up[flow->entry_up[e]];
		e = flow->entry_up[e];
	}
	return e;
}

static int flow_entry_new(struct bpf_flow *flow)
{
	u32 *up, cap;

	if (flow->entry_cnt + 1 >= flow->entry_cap) {
		cap = max(64U, flow->entry_cap * 2);
		up = kvrealloc(flow->entry_up, cap * sizeof(u32), GFP_KERNEL_ACCOUNT);
		if (!up)
			return -ENOMEM;
		flow->entry_up = up;
		flow->entry_cap = cap;
	}
	flow->entry_cnt++;
	flow->entry_up[flow->entry_cnt] = flow->entry_cnt;
	return flow->entry_cnt;
}

static bool flow_same_entry(struct bpf_flow *flow, const struct bpf_verifier_state *a,
			    const struct bpf_verifier_state *b)
{
	if (!a->flow_entry || !b->flow_entry)
		return a->flow_entry == b->flow_entry;
	return flow_entry_find(flow, a->flow_entry) == flow_entry_find(flow, b->flow_entry);
}

/* It delivers states, so it is done when nothing is in the middle of that. */
static int flow_unite(struct bpf_flow *flow, const struct bpf_verifier_state *st, u32 a, u32 b)
{
	struct flow_united *u;
	u32 cap;

	if (!a || !b || flow_entry_find(flow, a) == flow_entry_find(flow, b))
		return 0;
	if (flow->united_cnt == flow->united_cap) {
		cap = max(16U, flow->united_cap * 2);
		u = kvrealloc(flow->united, cap * sizeof(*u), GFP_KERNEL_ACCOUNT);
		if (!u)
			return -ENOMEM;
		flow->united = u;
		flow->united_cap = cap;
	}
	u = &flow->united[flow->united_cnt++];
	u->subprog = st->frame[0]->subprogno;
	u->a = a;
	u->b = b;
	return 0;
}

/*
 * What is known about a counted loop comes from the state it was entered
 * with. @t stands for @s only if that holds for these states too.
 */
static bool flow_loops_within(struct bpf_verifier_env *env, const struct bpf_verifier_state *t,
			      const struct bpf_verifier_state *s)
{
	const struct loop_stack_entry *lt, *ls;
	u32 fr, i;

	for (fr = 0; fr <= t->curframe; fr++) {
		if (t->frame[fr]->loop_stack_cnt != s->frame[fr]->loop_stack_cnt)
			return false;
		for (i = 0; i < t->frame[fr]->loop_stack_cnt; i++) {
			lt = &t->frame[fr]->loop_stack[i];
			ls = &s->frame[fr]->loop_stack[i];
			if (!lt->terminates || lt->entry_state == ls->entry_state)
				continue;
			if (!ls->terminates ||
			    !bpf_state_subsumes(env, lt->entry_state, ls->entry_state))
				return false;
		}
	}
	return true;
}

/*
 * bpf_iter_*_next() stops the loop if it is the same iterator in every trip.
 * The one that was destroyed and created again starts from the beginning.
 */
static bool flow_same_iters(const struct bpf_verifier_state *t, const struct bpf_verifier_state *s)
{
	const struct bpf_stack_state *a, *b;
	u32 fr, i;

	if (t->curframe != s->curframe)
		return false;
	for (fr = 0; fr <= t->curframe; fr++) {
		for (i = 0; i < bpf_stack_nr_slots(t->frame[fr]) &&
			    i < bpf_stack_nr_slots(s->frame[fr]); i++) {
			a = bpf_stack_slot(t->frame[fr], i);
			b = bpf_stack_slot(s->frame[fr], i);
			if (a->slot_type[BPF_REG_SIZE - 1] == STACK_ITER &&
			    b->slot_type[BPF_REG_SIZE - 1] == STACK_ITER &&
			    a->spilled_ptr.id != b->spilled_ptr.id)
				return false;
		}
	}
	return true;
}

/* In a loop that has nothing but may_goto or bpf_iter_*_next() of the program to stop it */
static bool flow_in_bounded_loop(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	u32 fr, i, h;

	for (fr = 0; fr <= st->curframe; fr++) {
		for (i = 0; i < st->frame[fr]->loop_stack_cnt; i++) {
			h = st->frame[fr]->loop_stack[i].loop_id;
			if (env->insn_aux_data[h].loop->rt_bounded)
				return true;
		}
	}
	return false;
}

/* The loops around @st make new iterators. So it's not an iterator that stops them. */
static int flow_iters_are_remade(struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	u32 fr, i, h;

	for (fr = 0; fr <= st->curframe; fr++) {
		for (i = 0; i < st->frame[fr]->loop_stack_cnt; i++) {
			h = st->frame[fr]->loop_stack[i].loop_id;
			env->insn_aux_data[h].loop->rt_bounded = false;
		}
	}
	env->restart = true;
	return -EINVAL;
}

static bool flow_within(struct bpf_verifier_env *env, struct bpf_verifier_state *t,
			struct bpf_verifier_state *s)
{
	return t->curframe == s->curframe &&
	       t->frame[0]->subprogno == s->frame[0]->subprogno &&
	       bpf_state_subsumes(env, t, s) && flow_loops_within(env, t, s);
}

/*
 * @t is of an earlier iteration of a loop whose iterations are kept apart than @s.
 * What comes after @s is of later iterations too, so @t is not going to be
 * of use. If something of its iteration does come it is looked at again.
 */
static bool flow_earlier_trip(const struct bpf_verifier_state *t,
			      const struct bpf_verifier_state *s)
{
	const struct bpf_func_state *ft, *fs;
	u32 fr, i;

	if (t->curframe != s->curframe)
		return false;
	for (fr = 0; fr <= t->curframe; fr++) {
		ft = t->frame[fr];
		fs = s->frame[fr];
		if (ft->subprogno != fs->subprogno || ft->callsite != fs->callsite ||
		    ft->loop_stack_cnt != fs->loop_stack_cnt)
			return false;
		for (i = 0; i < ft->loop_stack_cnt; i++) {
			if (ft->loop_stack[i].loop_id != fs->loop_stack[i].loop_id ||
			    ft->loop_stack[i].apart != fs->loop_stack[i].apart)
				return false;
			if (ft->loop_stack[i].trip != fs->loop_stack[i].trip)
				return ft->loop_stack[i].trip + 1 < fs->loop_stack[i].trip;
		}
	}
	return false;
}

static bool flow_two_consts(const struct bpf_reg_state *ra, const struct bpf_reg_state *rb)
{
	return ra->type == SCALAR_VALUE && rb->type == SCALAR_VALUE &&
	       tnum_is_const(ra->var_off) && tnum_is_const(rb->var_off) &&
	       ra->var_off.value != rb->var_off.value;
}

/*
 * A function returns one of a few numbers, true or false, less, equal or greater,
 * the variant of an enum, and the caller is about to look at it. It may have
 * no code for a number that is never returned.
 */
static bool flow_rets_differ(const struct bpf_verifier_state *a, const struct bpf_verifier_state *b)
{
	return flow_two_consts(&a->frame[a->curframe]->regs[BPF_REG_0],
			       &b->frame[b->curframe]->regs[BPF_REG_0]);
}

/* Constants that have to stay constants, see flow_compute_need_const() */
static bool flow_needed_consts_differ(const struct flow_need *needs,
				      const struct bpf_verifier_state *a,
				      const struct bpf_verifier_state *b)
{
	const struct bpf_stack_state *sa, *sb;
	const struct bpf_func_state *fa, *fb;
	const struct flow_need *need;
	u32 fr, i, nr;

	if (!needs || a->curframe != b->curframe)
		return false;
	for (fr = 0; fr <= a->curframe; fr++) {
		/* the callers need what they need when the call returns */
		need = &needs[fr == a->curframe ? a->insn_idx : a->frame[fr + 1]->callsite + 1];
		fa = a->frame[fr];
		fb = b->frame[fr];
		for (i = BPF_REG_0; need->regs && i < BPF_REG_FP; i++)
			if ((need->regs & BIT(i)) && flow_two_consts(&fa->regs[i], &fb->regs[i]))
				return true;
		nr = min(bpf_stack_nr_slots(fa), bpf_stack_nr_slots(fb));
		for (i = 0; i < nr && i < 64 && need->slots >> i; i++) {
			sa = bpf_stack_slot(fa, i);
			sb = bpf_stack_slot(fb, i);
			if ((need->slots & BIT_ULL(i)) &&
			    bpf_is_spilled_scalar_reg(sa) && bpf_is_spilled_scalar_reg(sb) &&
			    flow_two_consts(&sa->spilled_ptr, &sb->spilled_ptr))
				return true;
		}
	}
	return false;
}

/*
 * Put *@ps into @set, one of the sets of states at its insn. Returns
 * 1 if it is within a state of the set. It is gone then.
 * 0 if it is in the set now, as it was or joined with states of the set.
 * @cycle: it came around a cycle, what grew is forgotten.
 */
/*
 * A state is within another one, or has a join with it, only when the chains of calls and the
 * loops they are in are the same, iterations that are kept apart included. A walk leaves
 * a state per iteration at every point of the loop and of what it calls. Tell
 * them apart before the registers are compared or, for a join, copied.
 */
static u32 flow_kind(const struct bpf_verifier_state *st)
{
	const struct loop_stack_entry *entry;
	const struct bpf_func_state *frame;
	u32 kind = st->curframe, fr, i;

	for (fr = 0; fr <= st->curframe; fr++) {
		frame = st->frame[fr];
		kind = jhash_3words(frame->subprogno, frame->callsite, frame->loop_stack_cnt, kind);
		for (i = 0; i < frame->loop_stack_cnt; i++) {
			entry = &frame->loop_stack[i];
			kind = jhash_3words(entry->loop_id << 2 | entry->terminates << 1 |
					    entry->apart,
					    entry->max_header_count, entry->trip, kind);
		}
	}
	return kind;
}

/*
 * Two things of which one is there: "if (hdr->ipv4) ... else if (hdr->ipv6)". The one that
 * is not there is 0. What the other one is may be unknown, e.g. a pointer to the packet
 * after the packet was changed. (0, x) is not within (y, 0) and the join (?, ?) forgets that
 * it's one or the other.
 * The same for a number that was compared with 0: 0 on one path, not 0 on the other.
 */
/*
 * bpf_loop(N, ...) with a small N: the calls of the callback are looked at one by one, like
 * the iterations of a loop that is walked. The call stops to enter the callback when
 * callback_depth gets to N.
 */
static bool flow_callback_depth_differs(struct bpf_verifier_env *env,
					const struct bpf_verifier_state *a,
					const struct bpf_verifier_state *b)
{
	u32 max = BPF_FLOW_MAX_CALLBACKS, fr;
	const struct bpf_func_state *fa, *fb;
	struct bpf_insn *insn;

	if (a->curframe != b->curframe)
		return false;
	/* at the call, and in the callback and what it calls */
	for (fr = 0; fr <= a->curframe; fr++) {
		insn = &env->prog->insnsi[fr == a->curframe ? a->insn_idx :
					  a->frame[fr + 1]->callsite];
		if (!bpf_helper_call(insn) || insn->imm != BPF_FUNC_loop)
			continue;
		fa = a->frame[fr];
		fb = b->frame[fr];
		if (fa->callback_depth != fb->callback_depth &&
		    fa->regs[BPF_REG_1].type == SCALAR_VALUE &&
		    reg_umax(&fa->regs[BPF_REG_1]) <= max &&
		    fb->regs[BPF_REG_1].type == SCALAR_VALUE &&
		    reg_umax(&fb->regs[BPF_REG_1]) <= max)
			return true;
	}
	return false;
}

static const struct bpf_reg_state *flow_slot_number(const struct bpf_func_state *frame, u32 i)
{
	const struct bpf_stack_state *slot = bpf_stack_slot(frame, i);

	if (slot->slot_type[0] != STACK_SPILL || slot->slot_type[BPF_REG_SIZE - 1] != STACK_SPILL ||
	    slot->spilled_ptr.type != SCALAR_VALUE)
		return NULL;
	return &slot->spilled_ptr;
}

/* Returns true when the answer is known */
static bool flow_null_pair(const struct bpf_reg_state *ra, const struct bpf_reg_state *rb,
			   bool *a_null, bool *b_null)
{
	if (tnum_equals_const(ra->var_off, 0) && !tnum_is_const(rb->var_off)) {
		*a_null = true;
		if (reg_umin(rb) == 1 && reg_umax(rb) == U64_MAX)
			return true;
	}
	if (tnum_equals_const(rb->var_off, 0) && !tnum_is_const(ra->var_off)) {
		*b_null = true;
		if (reg_umin(ra) == 1 && reg_umax(ra) == U64_MAX)
			return true;
	}
	return *a_null && *b_null;
}

static bool flow_null_differs(const struct bpf_verifier_state *a,
			      const struct bpf_verifier_state *b)
{
	const struct bpf_func_state *fa, *fb;
	const struct bpf_reg_state *ra, *rb;
	bool a_null = false, b_null = false;
	u32 i;

	if (a->curframe != b->curframe)
		return false;
	fa = a->frame[a->curframe];
	fb = b->frame[b->curframe];
	for (i = BPF_REG_0; i < BPF_REG_FP; i++) {
		ra = &fa->regs[i];
		rb = &fb->regs[i];
		if (ra->type == SCALAR_VALUE && rb->type == SCALAR_VALUE &&
		    flow_null_pair(ra, rb, &a_null, &b_null))
			return true;
	}
	for (i = 0; i < bpf_stack_nr_slots(fa) && i < bpf_stack_nr_slots(fb); i++) {
		ra = flow_slot_number(fa, i);
		rb = flow_slot_number(fb, i);
		if (ra && rb && flow_null_pair(ra, rb, &a_null, &b_null))
			return true;
	}
	return false;
}

static const struct bpf_reg_state *flow_number_at(const struct bpf_func_state *frame, u8 loc)
{
	const struct bpf_reg_state *reg;

	if (loc <= BPF_REG_FP)
		reg = &frame->regs[loc];
	else if (loc - BPF_REG_FP - 1 < bpf_stack_nr_slots(frame) &&
		 bpf_is_spilled_scalar_reg(bpf_stack_slot(frame, loc - BPF_REG_FP - 1)))
		reg = &bpf_stack_slot(frame, loc - BPF_REG_FP - 1)->spilled_ptr;
	else
		return NULL;
	return reg->type == SCALAR_VALUE ? reg : NULL;
}

/*
 * A register is set in one of the states and not in the other. Only live registers are in
 * a state, so something ahead may read it. The state in which it's not set doesn't get there:
 * a jump sends it another way. The join would not know which way to go, and would get
 * there without the register. There is nothing to gain from such a join but a state less.
 */
static bool flow_unset_differs(const struct bpf_verifier_state *a,
			       const struct bpf_verifier_state *b)
{
	u32 fr, i;

	for (fr = 0; fr <= a->curframe; fr++)
		for (i = BPF_REG_0; i < BPF_REG_FP; i++)
			if ((a->frame[fr]->regs[i].type == NOT_INIT) !=
			    (b->frame[fr]->regs[i].type == NOT_INIT))
				return true;
	return false;
}

static bool flow_disjoint(const struct bpf_reg_state *a, const struct bpf_reg_state *b)
{
	return cnum64_is_empty(cnum64_intersect(a->r64, b->r64)) ||
	       cnum32_is_empty(cnum32_intersect(a->r32, b->r32)) ||
	       ((a->var_off.value ^ b->var_off.value) & ~(a->var_off.mask | b->var_off.mask));
}

/* The smallest range that has both has numbers that are in neither */
static bool flow_gap(const struct bpf_reg_state *a, const struct bpf_reg_state *b)
{
	if (cnum64_is_empty(cnum64_intersect(a->r64, b->r64)) &&
	    a->r64.size + b->r64.size + 1 > a->r64.size &&
	    cnum64_union(a->r64, b->r64).size > a->r64.size + b->r64.size + 1)
		return true;
	return cnum32_is_empty(cnum32_intersect(a->r32, b->r32)) &&
	       cnum32_union(a->r32, b->r32).size > (u64)a->r32.size + b->r32.size + 1;
}

/*
 * Numbers always have a join. It must not make up what neither state has where a jump ahead
 * can see it. flow->tested has the registers and the stack slots that a jump ahead compares
 * with a constant.
 *
 *	if (ret < 0) goto err; if (ret > 0) goto skip; use(p);
 * ret = -2 and ret = 1, both without p, meet in front of that. [-2, 1] has 0, gets through both
 * jumps, and there is no p. So two ranges that leave a gap are not joined. Ranges that
 * touch, 0 and 1, -1 and 0, or have something in common lose nothing.
 *
 *	err = update(); ret = err < 0 ? DROP : 0; ... if (err < 0) goto out; ... if (ret < 0) ...
 * (err >= 0, ret = 0) and (err < 0, ret = DROP) meet. The join has err < 0 with ret = 0. So
 * two numbers, each with nothing in common between the states, are not joined either.
 *
 * The states go on to the jumps on their own. Behind the last one the numbers are dead, and what
 * is left is joined.
 */
static bool flow_join_makes_up(const struct bpf_flow *flow, const struct bpf_verifier_state *a,
			       const struct bpf_verifier_state *b)
{
	const struct bpf_reg_state *ra, *rb;
	const struct flow_need *need;
	u32 fr, i, id = 0;
	bool one = false;

	if (!flow->tested)
		return false;
	for (fr = 0; fr <= a->curframe; fr++) {
		/* the callers go on when the call returns */
		need = &flow->tested[fr == a->curframe ? a->insn_idx :
				     a->frame[fr + 1]->callsite + 1];
		for (i = BPF_REG_0; i < BPF_REG_FP + 1 + 64; i++) {
			if (i <= BPF_REG_FP ? !(need->regs & BIT(i)) :
					      !(need->slots & BIT_ULL(i - BPF_REG_FP - 1)))
				continue;
			ra = flow_number_at(a->frame[fr], i);
			rb = flow_number_at(b->frame[fr], i);
			if (!ra || !rb || !flow_disjoint(ra, rb))
				continue;
			if (flow_gap(ra, rb))
				return true;
			/* copies of a number are one number */
			if (one && (!id || id != (ra->id & ~BPF_ADD_CONST)))
				return true;
			one = true;
			id = ra->id & ~BPF_ADD_CONST;
		}
	}
	return false;
}

/*
 * States that have a join are kept apart while there is room: half of every limit.
 * After that they are joined, which may lose what the prog needs, and does not run into the limit.
 */
static bool flow_has_room(const struct bpf_verifier_env *env, u32 nr_states)
{
	u64 len = env->prog->len;

	return nr_states < BPF_FLOW_MAX_STATES / 2 &&
	       env->flow->live_states < (BPF_FLOW_LIVE_PER_INSN * len + BPF_FLOW_LIVE_BASE) / 2 &&
	       env->total_states < (BPF_FLOW_TOTAL_PER_INSN * len + BPF_FLOW_TOTAL_BASE) / 2;
}

static int flow_merge(struct bpf_verifier_env *env, struct list_head *set,
		      struct flow_state **ps, enum flow_cycle cycle)
{
	struct bpf_flow *flow = env->flow;
	struct flow_state *s = *ps, *t, *tn;
	int insn_idx = s->st.insn_idx, err;
	bool widen_all, widen, iters;
	/* the set of the states that enter a loop is a stop on the way, see bpf_flow_deliver() */
	bool log = (env->log.level & BPF_LOG_LEVEL2) && set != &flow->enter[insn_idx];
	const char *what = NULL;
	int prev = s->prev_insn_idx;
	u32 other_iters;

	/*
	 * Not only where the cycle is closed: the state with a new iterator must not
	 * disappear in the one with the old iterator on the way there.
	 */
	iters = flow_in_bounded_loop(env, &s->st);
again:
	other_iters = 0;
	if (signal_pending(current)) {
		err = -EAGAIN;
		goto err_free;
	}
	if (need_resched())
		cond_resched();

	s->kind = flow_kind(&s->st);
	list_for_each_entry(t, set, node) {
		if (t->kind != s->kind ||
		    !flow_within(env, &t->st, &s->st))
			continue;
		if (iters && !flow_same_iters(&t->st, &s->st))
			continue;
		if (env->log.level & BPF_LOG_LEVEL2)
			verbose(env, "from %d to %d: within\n", prev, insn_idx);
		err = flow_unite(flow, &s->st, s->st.flow_entry, t->st.flow_entry);
		flow_free_state(env, s);
		return err ?: 1;
	}

	widen_all = cycle == FLOW_CYCLE || s->joins > BPF_FLOW_MAX_JOINS;
	list_for_each_entry_safe(t, tn, set, node) {
		if (t->st.frame[0]->subprogno != s->st.frame[0]->subprogno)
			continue;
		widen = widen_all || (cycle == FLOW_CALLBACK_CYCLE &&
				      max(s->joins, t->joins) >= BPF_FLOW_CALLBACK_JOINS);
		if (!t->pending && flow_earlier_trip(&t->st, &s->st)) {
			flow_unlink(env, t);
			flow_free_state(env, t);
			continue;
		}
		if (t->kind != s->kind)
			continue;
		if (iters && !flow_same_iters(&t->st, &s->st)) {
			if (++other_iters < BPF_FLOW_MAX_ITERS)
				continue;
			err = flow_iters_are_remade(env, &s->st);
			goto err_free;
		}
		if (!widen && flow_has_room(env, flow->nr_states[insn_idx]) &&
		    flow_null_differs(&t->st, &s->st))
			continue;
		if (!widen && flow_needed_consts_differ(flow->need_const, &t->st, &s->st))
			continue;
		if (flow_callback_depth_differs(env, &t->st, &s->st))
			continue;
		/* what grows in a loop is not replaced with what is larger, it is forgotten */
		if (!widen && flow_within(env, &s->st, &t->st)) {
			err = flow_unite(flow, &s->st, s->st.flow_entry, t->st.flow_entry);
			if (err)
				goto err_free;
			s->joins = max(s->joins, t->joins);
			flow_unlink(env, t);
			flow_free_state(env, t);
			what = what ?: "joined";
			continue;
		}
		if (!widen && flow_has_room(env, flow->nr_states[insn_idx]) &&
		    (flow_unset_differs(&t->st, &s->st) ||
		     flow_join_makes_up(flow, &t->st, &s->st)))
			continue;
		/*
		 * Around a loop too:
		 *	u8 stack[10], depth = 0;
		 *	loop {
		 *		if (...) { if (depth >= 10) break; stack[depth++] = x; }
		 *		else { depth--; if (depth >= 10) break; x = stack[depth]; }
		 *	}
		 * depth is in a 32-bit register. A compiler tests 'depth & 255' and computes it
		 * anew for the index. What is found out about a copy says nothing about
		 * a range, and everything about a constant.
		 */
		if (flow_has_room(env, flow->nr_states[insn_idx]) &&
		    flow_needed_consts_differ(flow->stack_off, &t->st, &s->st))
			continue;
		err = bpf_states_join(env, &flow->tmp, &t->st, &s->st, widen);
		if (err < 0)
			goto err_free;
		if (err)
			continue;
		what = widen ? "widened" : "joined";
		err = flow_unite(flow, &s->st, s->st.flow_entry, t->st.flow_entry);
		if (err)
			goto err_free;
		flow->tmp.flow_entry = t->st.flow_entry;
		flow->tmp.last_insn_idx = s->prev_insn_idx;
		s->joins = max(s->joins, t->joins) + 1;
		bpf_free_verifier_state(&s->st, false);
		s->st = flow->tmp;
		memset(&flow->tmp, 0, sizeof(flow->tmp));
		flow_unlink(env, t);
		flow_free_state(env, t);
		/* the join may be within, or have a join with, what is left in the set */
		goto again;
	}

	if (flow->nr_states[insn_idx] >= BPF_FLOW_MAX_STATES) {
		verbose(env, "more than %d states that cannot be joined at insn %d\n",
			BPF_FLOW_MAX_STATES, insn_idx);
		err = -E2BIG;
		goto err_free;
	}
	if (flow->live_states > BPF_FLOW_LIVE_PER_INSN * env->prog->len + BPF_FLOW_LIVE_BASE ||
	    env->total_states >
	    BPF_FLOW_TOTAL_PER_INSN * (u64)env->prog->len + BPF_FLOW_TOTAL_BASE) {
		verbose(env, "too many states for %d insns: %d, %d at a time\n",
			env->prog->len, env->total_states, flow->live_states);
		err = -E2BIG;
		goto err_free;
	}
	/*
	 * The state is printed when its turn comes. That says enough about a state that
	 * is new, and about a state that goes on to the next insn.
	 */
	if (prev >= 0 && insn_idx == prev + 1 + bpf_is_ldimm64(&env->prog->insnsi[prev]) &&
	    what && !strcmp(what, "joined"))
		what = NULL;
	if (log && what)
		verbose(env, "from %d to %d: %s\n", prev, insn_idx, what);
	list_add_tail(&s->node, set);
	flow->nr_states[insn_idx]++;
	env->max_states_per_insn = max(env->max_states_per_insn, flow->nr_states[insn_idx]);
	return 0;

err_free:
	flow_free_state(env, s);
	return err;
}

static struct flow_state *flow_new_state(struct bpf_verifier_env *env, int prev_insn_idx)
{
	struct flow_state *s = kzalloc_obj(*s, GFP_KERNEL_ACCOUNT);
	struct bpf_flow *flow = env->flow;

	if (!s)
		return NULL;
	s->prev_insn_idx = prev_insn_idx;
	s->seq = ++flow->seq;
	env->total_states++;
	flow->live_states++;
	env->peak_states = max(env->peak_states, flow->live_states);
	return s;
}

/* What @st holds is taken and @st is left empty. What doesn't matter at @insn_idx goes. */
static struct flow_state *flow_arrive(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				      int insn_idx, int prev_insn_idx, bool *enters)
{
	struct bpf_verifier_state *cur = env->cur_state;
	int cur_idx = env->insn_idx, err;
	struct flow_state *s;

	if (insn_idx < 0 || insn_idx >= env->prog->len) {
		verbose(env, "invalid insn idx %d insn_cnt %d\n", insn_idx, env->prog->len);
		return ERR_PTR(-EFAULT);
	}

	s = flow_new_state(env, prev_insn_idx);
	if (!s)
		return ERR_PTR(-ENOMEM);
	s->st = *st;
	memset(st, 0, sizeof(*st));
	s->st.insn_idx = insn_idx;
	s->st.last_insn_idx = prev_insn_idx;

	env->cur_state = &s->st;
	env->insn_idx = insn_idx;
	err = bpf_flow_loop_leave(env, enters);
	if (!err)
		err = bpf_clean_verifier_state(env, &s->st);
	env->cur_state = cur;
	env->insn_idx = cur_idx;
	if (err) {
		flow_free_state(env, s);
		return ERR_PTR(err);
	}
	/* when the registers that it was shared with are dead, or are those of the caller */
	bpf_clear_singular_ids(env, &s->st);
	return s;
}

/*
 * @st gets to @insn_idx if the guard at @prev_insn_idx is going to leave the loop, see
 * check_loop_guard(). Nothing is joined: the states may never meet.
 */
int bpf_flow_park(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
		  int insn_idx, int prev_insn_idx)
{
	struct bpf_flow *flow = env->flow;
	struct flow_state *s, *t, *tn;
	bool enters;

	s = flow_arrive(env, st, insn_idx, prev_insn_idx, &enters);
	if (IS_ERR(s))
		return PTR_ERR(s);
	list_for_each_entry_safe(t, tn, &flow->parked, node) {
		if (t->prev_insn_idx != prev_insn_idx || !flow_same_entry(flow, &t->st, &s->st))
			continue;
		if (flow_within(env, &t->st, &s->st)) {
			flow_free_state(env, s);
			return 0;
		}
		if (flow_within(env, &s->st, &t->st)) {
			list_del(&t->node);
			flow_free_state(env, t);
		}
	}
	list_add_tail(&s->node, &flow->parked);
	return 0;
}

/* The guard at @prev_insn_idx leaves the loop */
void bpf_flow_unpark(struct bpf_verifier_env *env, int prev_insn_idx)
{
	struct bpf_flow *flow = env->flow;
	struct flow_state *s, *sn;

	list_for_each_entry_safe(s, sn, &flow->parked, node)
		if (s->prev_insn_idx == prev_insn_idx)
			list_move_tail(&s->node, &flow->unparked);
}

int bpf_flow_deliver_unparked(struct bpf_verifier_env *env)
{
	struct bpf_flow *flow = env->flow;
	struct flow_state *s;
	int err = 0;

	while (!err && !list_empty(&flow->unparked)) {
		s = list_first_entry(&flow->unparked, struct flow_state, node);
		list_del(&s->node);
		err = bpf_flow_deliver(env, &s->st, s->st.insn_idx, s->prev_insn_idx);
		flow_free_state(env, s);
	}
	return err;
}

/*
 * @st gets to @insn_idx. What it holds is taken and @st is left empty.
 */
int bpf_flow_deliver(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
		     int insn_idx, int prev_insn_idx)
{
	struct bpf_verifier_state *cur = env->cur_state;
	bool backedge = false, enters = false, drop = false;
	struct bpf_flow *flow = env->flow;
	enum flow_cycle cycle;
	int cur_idx = env->insn_idx, err;
	struct bpf_subprog_info *sub;
	struct flow_state *s, *e;

	s = flow_arrive(env, st, insn_idx, prev_insn_idx, &enters);
	if (IS_ERR(s))
		return PTR_ERR(s);

	/*
	 * Cycles that have no loop head: the callback that came back to the helper
	 * that calls it, and calls that go through the entry of a function.
	 */
	sub = bpf_find_containing_subprog(env, insn_idx);
	cycle = FLOW_NO_CYCLE;
	if (sub->recursive && sub->start == insn_idx)
		cycle = FLOW_CYCLE;
	else if (env->insn_aux_data[insn_idx].calls_callback && prev_insn_idx >= 0 &&
		 env->prog->insnsi[prev_insn_idx].code == (BPF_JMP | BPF_EXIT))
		cycle = FLOW_CALLBACK_CYCLE;

	/*
	 * What is known about a loop is derived from the state that enters it. So
	 * the states that enter are a set of their own, and what gets to
	 * the set at the head of the loop is derived from what is new in it.
	 */
	if (enters) {
		err = flow_merge(env, &flow->enter[insn_idx], &s, cycle);
		if (err)
			return err < 0 ? err : 0;
		cycle = FLOW_NO_CYCLE;
		e = s;
		s = flow_new_state(env, prev_insn_idx);
		if (!s)
			return -ENOMEM;
		err = bpf_copy_verifier_state(&s->st, &e->st);
		if (err)
			goto err_free;
	}

	env->cur_state = &s->st;
	env->insn_idx = insn_idx;
	err = bpf_flow_loop_enter(env, &backedge, &drop);
	env->cur_state = cur;
	env->insn_idx = cur_idx;
	if (err || drop)
		goto err_free;

	err = flow_merge(env, &flow->states[insn_idx], &s, backedge ? FLOW_CYCLE : cycle);
	if (err)
		return err < 0 ? err : 0;
	flow_set_pending(flow, s);
	return 0;

err_free:
	flow_free_state(env, s);
	return err;
}

static int flow_apply_exit(struct bpf_verifier_env *env, struct flow_waiter *w,
			   struct flow_exit *x)
{
	struct bpf_verifier_state st = {};
	int err;

	if (w->dead)
		return 0;
	err = bpf_copy_verifier_state(&st, &w->st);
	if (!err)
		err = bpf_flow_return(env, &st, &x->st, w->call_idx);
	if (!err)
		err = bpf_flow_deliver(env, &st, w->call_idx + 1, w->call_idx);
	if (err == 1) {
		struct flow_state *s;

		/*
		 * Do the call again. Not with bpf_flow_deliver(): the state was
		 * at the insn before, it may be there still.
		 */
		w->dead = true;
		s = flow_new_state(env, w->st.last_insn_idx);
		if (!s) {
			err = -ENOMEM;
			goto out;
		}
		err = bpf_copy_verifier_state(&s->st, &w->st);
		if (err) {
			flow_free_state(env, s);
			goto out;
		}
		s->st.insn_idx = w->call_idx;
		s->kind = flow_kind(&s->st);
		list_add_tail(&s->node, &env->flow->states[w->call_idx]);
		env->flow->nr_states[w->call_idx]++;
		flow_set_pending(env->flow, s);
	}
out:
	bpf_free_verifier_state(&st, false);
	return err;
}

static int flow_do_united(struct bpf_verifier_env *env)
{
	struct bpf_flow *flow = env->flow;
	struct flow_waiter *w;
	struct flow_united u;
	struct flow_func *f;
	struct flow_exit *x;
	u32 a, b, we, xe;
	int err;

	while (flow->united_cnt) {
		u = flow->united[--flow->united_cnt];
		a = flow_entry_find(flow, u.a);
		b = flow_entry_find(flow, u.b);
		if (a == b)
			continue;
		f = &flow->funcs[u.subprog];
		/* what came out for one goes to the calls that wait for the other */
		list_for_each_entry(x, &f->exits, node) {
			xe = flow_entry_find(flow, x->entry);
			if (xe != a && xe != b)
				continue;
			list_for_each_entry(w, &f->waiters, node) {
				we = flow_entry_find(flow, w->entry);
				if (we == xe || (we != a && we != b))
					continue;
				err = flow_apply_exit(env, w, x);
				if (err)
					return err;
			}
		}
		flow->entry_up[a] = b;
	}
	return 0;
}

/*
 * The call at @call_idx in @caller of a function that is verified on its own,
 * @entry is the state at its first insn. Both are taken.
 */
int bpf_flow_call(struct bpf_verifier_env *env, struct bpf_verifier_state *caller,
		  struct bpf_verifier_state *entry, int subprog, int call_idx)
{
	struct bpf_flow *flow = env->flow;
	struct flow_func *f = &flow->funcs[subprog];
	struct flow_waiter *w, *o, *on;
	int id;

	caller->insn_idx = call_idx;
	list_for_each_entry_safe(o, on, &f->waiters, node) {
		if (o->call_idx != call_idx || o->dead)
			continue;
		/* it gets what the call that is there gets */
		if (o->st.flow_entry == caller->flow_entry && flow_within(env, &o->st, caller))
			return 0;
	}

	id = flow_entry_new(flow);
	if (id < 0)
		return id;
	w = kzalloc_obj(*w, GFP_KERNEL_ACCOUNT);
	if (!w)
		return -ENOMEM;
	w->st = *caller;
	memset(caller, 0, sizeof(*caller));
	w->call_idx = call_idx;
	w->entry = id;
	list_add_tail(&w->node, &f->waiters);

	entry->flow_entry = id;
	if (env->log.level & BPF_LOG_LEVEL2)
		verbose(env, "call at %d waits for func#%d\n", call_idx, subprog);
	return bpf_flow_deliver(env, entry, env->subprog_info[subprog].start, call_idx);
}

/* @st came to exit of the function that is verified on its own. It is taken. */
int bpf_flow_exit(struct bpf_verifier_env *env, struct bpf_verifier_state *st, int exit_idx)
{
	struct bpf_flow *flow = env->flow;
	struct flow_func *f = &flow->funcs[st->frame[0]->subprogno];
	struct flow_exit *x, *o, *on;
	struct flow_waiter *w;
	u16 joins = 0;
	u32 entry, cnt = 0;
	int err;

	st->insn_idx = exit_idx;
	err = bpf_clean_verifier_state(env, st);
	if (err)
		return err;
	if (f->exit_idx < 0)
		f->exit_idx = exit_idx;
	st->insn_idx = f->exit_idx;
	entry = flow_entry_find(flow, st->flow_entry);

	list_for_each_entry_safe(o, on, &f->exits, node) {
		if (flow_entry_find(flow, o->entry) != entry)
			continue;
		if (bpf_state_subsumes(env, &o->st, st))
			return 0;
		if (flow_has_room(env, ++cnt) && flow_rets_differ(&o->st, st))
			continue;
		/* what comes out of a recursive function gets into it again */
		err = bpf_states_join(env, &flow->tmp, &o->st, st,
				      env->subprog_info[st->frame[0]->subprogno].recursive ||
				      o->joins > BPF_FLOW_MAX_JOINS);
		if (err < 0)
			return err;
		if (err)
			continue;
		joins = max(joins, o->joins) + 1;
		bpf_free_verifier_state(st, false);
		*st = flow->tmp;
		memset(&flow->tmp, 0, sizeof(flow->tmp));
		st->flow_entry = entry;
		list_del(&o->node);
		bpf_free_verifier_state(&o->st, false);
		kfree(o);
	}

	x = kzalloc_obj(*x, GFP_KERNEL_ACCOUNT);
	if (!x)
		return -ENOMEM;
	x->st = *st;
	memset(st, 0, sizeof(*st));
	x->entry = entry;
	x->joins = joins;
	list_add_tail(&x->node, &f->exits);

	list_for_each_entry(w, &f->waiters, node) {
		if (flow_entry_find(flow, w->entry) != entry)
			continue;
		err = flow_apply_exit(env, w, x);
		if (err)
			return err;
	}
	return 0;
}

/*
 * Make the next pending state the current one. env->cur_state has to be empty.
 * Returns -ENOENT when nothing is pending.
 */
int bpf_flow_next(struct bpf_verifier_env *env, int *prev_insn_idx)
{
	struct bpf_flow *flow = env->flow;
	struct flow_state *s;
	struct rb_node *n;
	int err;

	err = flow_do_united(env);
	if (err)
		return err;
	n = rb_first_cached(&flow->pending);
	if (!n)
		return -ENOENT;
	s = rb_entry(n, struct flow_state, rb);
	rb_erase_cached(&s->rb, &flow->pending);
	s->pending = false;

	env->insn_idx = s->st.insn_idx;
	*prev_insn_idx = s->prev_insn_idx;
	if (test_bit(s->st.insn_idx, flow->keep))
		return bpf_copy_verifier_state(env->cur_state, &s->st);
	*env->cur_state = s->st;
	memset(&s->st, 0, sizeof(s->st));
	s->st.insn_idx = env->insn_idx;
	flow_unlink(env, s);
	flow_free_state(env, s);
	return 0;
}
