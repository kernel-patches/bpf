// SPDX-License-Identifier: GPL-2.0-only
/*
 * Join of verifier states.
 *
 * Two states at one insn with the same join_key always have a join, see bpf_same_join_key().
 *
 *  map ptr  |  scalar      -> unreadable -+
 *  two objects             -> unreadable -+-> a use is unproven -> partition
 *  p+1, p+2, ... at header -> p+unknown  -+
 *
 * Values of one type and object differ only in a number, see bpf_same_type_and_object().
 * Numbers are joined. At a loop header they are widened, so the sequence of states ends.
 *
 * bpf_clean_verifier_state() cleans the inputs: dead xregs are the same in both.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/cnum.h>
#include <linux/filter.h>

struct join {
	struct bpf_verifier_env *env;
	struct bpf_verifier_state *dst;
	struct bpf_loop *leftover_loop;	/* the states are at its header, in its leftover */
	bool widen;
	u32 fr;
	u32 xregno;		/* see MAX_BPF_XREG, BPF_REG_FP for stack args */
	int err;
};

/*
 * A number can grow in each trip. The bound that moved goes to a threshold. The constants of
 * the loop give the thresholds:
 *	do { a[i] = 0; i += 3; } while (i < 30);		29 at most comes back to the header
 *	while (i < 30) { a[i] = 0; i += 3; }			32
 *	loop { if (...) { if (n >= 64) break; a[n++] = x; } }	64
 * A threshold is a guess. The state that comes back to the header is compared with it.
 *
 * Only a number on a cycle grows again and again. So the first growth is a join.
 *	x = 0; loop { a[x]; x = rnd & 7; }
 */
static void join_range(struct join *j, struct bpf_reg_state *dst, const struct bpf_reg_state *src)
{
	s64 min_threshold = S64_MIN, max_threshold = S64_MAX, off;
	struct bpf_loop *loop = j->leftover_loop;
	struct bpf_reg_state old = *dst;
	bool in_deps;
	int i, n;

	if (scalar_equal(scalar_of(dst), scalar_of(src)))
		return;
	scalar_union(scalar_of(dst), scalar_of(src));
	if (loop && !scalar_equal(scalar_of(dst), scalar_of(&old))) {
		if (!j->widen || !old.grew_once)
			goto out;
		/* two pointers are compared by their offsets up to there */
		if (dst->type != SCALAR_VALUE) {
			if (reg_smax(dst) < BPF_MAX_VAR_OFF)
				max_threshold = BPF_MAX_VAR_OFF - 1;
			if (reg_smin(dst) > -BPF_MAX_VAR_OFF)
				min_threshold = -BPF_MAX_VAR_OFF + 1;
		}
		in_deps = bpf_xreg_in_deps(j->env, j->dst, j->fr, j->xregno);
		if (in_deps)
			j->err = j->err ?: bpf_loop_collect_thresholds(j->env, loop);
		/* at the constant or one before it, and the largest step or this step further */
		for (i = 0; i < 6 && in_deps && !j->err; i++) {
			off = i & 4 ? reg_smax(dst) - reg_smax(&old) : i & 2 ? loop->max_step : 0;
			off -= i & 1;
			n = bpf_loop_thresholds_below(loop, reg_smax(dst) - off);
			if (n < loop->threshold_cnt && loop->thresholds[n] + off >= reg_smax(dst))
				max_threshold = min(max_threshold, loop->thresholds[n] + off);
			off = i & 4 ? reg_smin(dst) - reg_smin(&old) : i & 2 ? loop->min_step : 0;
			off += i & 1;
			n = bpf_loop_thresholds_below(loop, reg_smin(dst) - off + 1);
			if (n && loop->thresholds[n - 1] + off <= reg_smin(dst))
				min_threshold = max(min_threshold, loop->thresholds[n - 1] + off);
		}
		scalar_widen(scalar_of(dst), scalar_of(&old), min_threshold, max_threshold);
out:
		dst->grew_once = true;
	}
	if (!bpf_scalar_subsumes(dst, &old) || !bpf_scalar_subsumes(dst, src))
		scalar_set_unknown(scalar_of(dst));
}

/*
 * Pointers to the packet that share an id keep their displacement. No id is an id too:
 * the start of the packet plus a constant, see find_good_pkt_pointers().
 */
static u32 join_pkt_id(struct bpf_verifier_env *env, const struct bpf_reg_state *ra,
		       const struct bpf_reg_state *rb)
{
	struct bpf_pkt_pair new = { ra->id, rb->id, rb->r64.base - ra->r64.base, ra->type, ra->id };
	struct bpf_pkt_pair *p = env->pkt_pairs;
	bool taken = !ra->id;

	bpf_add_cost(env, env->pkt_pair_cnt, BPF_COST_SCAN);
	for (; p < env->pkt_pairs + env->pkt_pair_cnt; taken |= p++->id == ra->id)
		if (!memcmp(p, &new, offsetof(struct bpf_pkt_pair, id)))
			return p->id;
	if (taken && (new.old || new.cur || new.delta))
		new.id = bpf_new_id(env);
	/* with no memory the load fails, see bpf_check_limits() */
	bpf_add_pkt_pair(env, &new);
	return new.id;
}

/* The bytes that are left after the pointer in both states are left in the join */
static void join_pkt(struct join *j, struct bpf_reg_state *dst, const struct bpf_reg_state *src)
{
	struct bpf_reg_state old = *dst;
	struct cnum64 both = cnum64_union(old.r64, src->r64);

	dst->id = join_pkt_id(j->env, &old, src);
	join_range(j, dst, src);
	dst->pkt_min_len = min(pkt_min_len(&old), pkt_min_len(src));
	if (old.r64.size == dst->r64.size && src->r64.size == dst->r64.size) {
		if (old.range != src->range)
			dst->range = max(min(old.range, src->range), 0);
		return;
	}
	if (pkt_has_bytes_left(&old) && pkt_has_bytes_left(src) && pkt_has_bytes_left(dst))
		dst->range = reg_smax(dst) + min(pkt_bytes_left(&old), pkt_bytes_left(src));
	else
		dst->range = 0;
	dst->range = max(dst->range, dst->pkt_min_len);
	/* pointers that share an id have ranges of the same size */
	if (cnum64_umax(dst->r64) > MAX_PACKET_OFF || dst->r64.size != both.size)
		dst->id = bpf_new_id(j->env);
}

static void join_reg(struct join *j, struct bpf_reg_state *dst, const struct bpf_reg_state *src)
{
	bool from_unproven = dst->from_unproven || (src && src->from_unproven);

	if (!src || dst->type == NOT_INIT || !bpf_same_type_and_object(j->env, dst, src))
		bpf_mark_reg_not_init(j->env, dst);
	else if (type_is_pkt_pointer(dst->type))
		join_pkt(j, dst, src);
	else if (base_type(dst->type) != PTR_TO_ARENA) /* its offset is not tracked */
		join_range(j, dst, src);
	dst->from_unproven = from_unproven;
}

/* What a byte of a slot is if the number in the slot is not known */
static u8 join_byte(struct bpf_stack_state *s, int i)
{
	if (s->slot_type[i] != STACK_SPILL)
		return s->slot_type[i];
	return bpf_register_is_null(&s->spilled_ptr) ? STACK_ZERO : STACK_MISC;
}

static bool byte_is_set(u8 t)
{
	return t != STACK_INVALID && t != STACK_POISON;
}

static void join_slot(struct join *j, struct bpf_stack_state *dst, struct bpf_stack_state *src)
{
	u8 x, y, ptr_type = STACK_SPILL;
	bool ptr;
	int i;

	/* it is in the join_key */
	if (bpf_slot_is_held(dst))
		return;
	if (!memcmp(dst->slot_type, src->slot_type, sizeof(dst->slot_type))) {
		if (bpf_is_spilled_reg(dst))
			join_reg(j, &dst->spilled_ptr, &src->spilled_ptr);
		return;
	}
	ptr = (bpf_is_spilled_reg(dst) && !bpf_is_spilled_scalar_reg(dst)) ||
	      (bpf_is_spilled_reg(src) && !bpf_is_spilled_scalar_reg(src));
	/* a byte that is possibly not written is not read, not even into an unreadable register */
	for (i = 0; i < BPF_REG_SIZE && !j->env->allow_uninit_stack; i++)
		if (!byte_is_set(dst->slot_type[i]) || !byte_is_set(src->slot_type[i]))
			ptr_type = STACK_INVALID;
	for (i = 0; i < BPF_REG_SIZE; i++) {
		x = join_byte(dst, i);
		y = join_byte(src, i);
		dst->slot_type[i] = ptr ? ptr_type : !byte_is_set(x) || x == y ? x :
				    !byte_is_set(y) ? STACK_INVALID : STACK_MISC;
	}
	bpf_mark_reg_not_init(j->env, &dst->spilled_ptr);
}

static void join_func(struct join *j, struct bpf_func_state *dst, struct bpf_func_state *src,
		      u16 live_regs)
{
	static struct bpf_stack_state invalid_slot;
	const struct loop_stack_entry *s;
	struct loop_stack_entry *d;
	u32 i;

	for (i = 0; i < dst->loop_stack_cnt; i++) {
		d = &dst->loop_stack[i];
		s = &src->loop_stack[i];
		d->trip = max(d->trip, s->trip);
		d->held_cnt = min(d->held_cnt, s->held_cnt);
	}
	for (i = 0; i < BPF_REG_FP; i++) {
		j->xregno = i;
		if (live_regs & BIT(i))
			join_reg(j, &dst->regs[i], &src->regs[i]);
		else
			bpf_mark_reg_not_init(j->env, &dst->regs[i]);
	}
	/* slots and arguments that only @src has are unreadable */
	for (i = 0; i < bpf_stack_nr_slots(dst); i++) {
		j->xregno = bpf_spi_to_xreg(i);
		join_slot(j, bpf_stack_slot(dst, i),
			  i < bpf_stack_nr_slots(src) ? bpf_stack_slot(src, i) : &invalid_slot);
	}
	j->xregno = BPF_REG_FP;
	for (i = 0; i < dst->out_stack_arg_cnt; i++)
		join_reg(j, &dst->stack_arg_regs[i],
			 bpf_stack_arg(dst, src, i) ? bpf_stack_arg(src, dst, i) : NULL);
	dst->no_stack_arg_load |= src->no_stack_arg_load;
	dst->callback_depth = min(dst->callback_depth, src->callback_depth);
}

/*
 * Make @dst describe all that @dst or @src describe. They have the same join_key.
 * Both are speculative, or neither is.
 * @leftover_loop: they are at its header, in its leftover.
 */
int bpf_states_join(struct bpf_verifier_env *env, struct bpf_verifier_state *dst,
		    const struct bpf_verifier_state *src, struct bpf_loop *leftover_loop,
		    bool widen)
{
	struct join j = { .env = env, .dst = dst, .leftover_loop = leftover_loop, .widen = widen };

	bpf_add_cost(env, bpf_xreg_cnt(dst), BPF_COST_XREG);
	env->pkt_pair_cnt = 0;
	env->imprecise |= !env->err;
	dst->suspect_loops |= src->suspect_loops;
	bpf_equations_pre_join(env, dst, src, leftover_loop, leftover_loop && widen);
	for (j.fr = 0; j.fr <= dst->curframe; j.fr++)
		join_func(&j, dst->frame[j.fr], src->frame[j.fr],
			  env->insn_aux_data[bpf_frame_insn_idx(dst, j.fr)].live_regs_before);
	bpf_equations_post_join(env, dst, src);
	dst->max_held_cnt = max(dst->max_held_cnt, src->max_held_cnt);
	/* no equation is found over a limit */
	if (env->test_reg_invariants && !bpf_state_subsumes(env, dst, src) &&
	    verifier_bug_if(!bpf_check_limits(env), env, "join at %d", dst->insn_idx))
		return -EFAULT;
	/* the first xreg that had an id can be gone */
	return j.err ?: bpf_renumber_ids(env, dst);
}
