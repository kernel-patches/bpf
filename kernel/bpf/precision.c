// SPDX-License-Identifier: GPL-2.0-only
/*
 * Which states a pass keeps apart. Pass 0 joins all numbers, see bpf_hash_live_types(). After
 * an error the next pass keeps more apart (trace partitioning), see do_check_all() and
 * bpf_partition_more(). An insn whose check fails is unproven. A later pass can prove it.
 *
 * The deps are the xregs that the unproven insn depends on:
 * data_deps:    their value flows into an operand of the insn
 * control_deps: their value flows into a jump that can skip the insn
 *
 *	if (r7 == 0) goto L1;		r7 is in control_deps
 *	r2 = r6;			r6 is in data_deps
 *	r0 = *(u8 *)(r2 + 0);		unproven insn
 *  L1:
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/slab.h>

#include "precision.h"

static unsigned long *mask_at(struct bpf_verifier_env *env, unsigned long *masks, u32 func, u32 idx)
{
	const struct bpf_precision *prec = env->precision;

	return masks + prec->func[func].first +
	       (size_t)(idx - env->subprog_info[func].start) * prec->func[func].words;
}

/* @masks for frame @fr of @st. A caller needs what the callee reads and what follows the call. */
u32 bpf_frame_mask(struct bpf_verifier_env *env, unsigned long *masks,
		   const struct bpf_verifier_state *st, u32 fr, unsigned long *out)
{
	u32 func = st->frame[fr]->subprogno, words = env->precision->func[func].words, i;
	const unsigned long *m = mask_at(env, masks, func, bpf_frame_insn_idx(st, fr));

	for (i = 0; i < words; i++)
		out[i] = m[i] | (fr < st->curframe ? m[words + i] : 0);
	return words * BITS_PER_LONG;
}

bool bpf_xreg_in_data_deps(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			   u32 fr, u32 xregno)
{
	unsigned long data_deps[XREG_WORDS];

	return env->precision->data_deps &&
	       xregno < bpf_frame_mask(env, env->precision->data_deps, st, fr, data_deps) &&
	       test_bit(xregno, data_deps);
}

bool bpf_xreg_in_deps(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
		      u32 fr, u32 xregno)
{
	unsigned long data_deps[XREG_WORDS], control_deps[XREG_WORDS];

	if (!env->precision->data_deps ||
	    xregno >= bpf_frame_mask(env, env->precision->data_deps, st, fr, data_deps))
		return false;
	bpf_frame_mask(env, env->precision->control_deps, st, fr, control_deps);
	return test_bit(xregno, data_deps) || test_bit(xregno, control_deps);
}

/*
 * On its own a function does not get the equations of its arguments @args:
 *	if (!ok(x)) return 0;  buf[x];		the test in ok() has to bound x
 */
bool bpf_call_needs_frames(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			   u16 args)
{
	struct bpf_precision *prec = env->precision;
	u32 func = st->frame[st->curframe]->subprogno, idx = st->insn_idx;

	args &= bpf_args_with_equation(st);
	if (prec->data_deps) {
		if (args & *mask_at(env, prec->in_frames, func, idx))
			return true;
		prec->this_pass.arg_lost_equation |=
			args & (*mask_at(env, prec->data_deps, func, idx) |
				*mask_at(env, prec->control_deps, func, idx));
	}
	env->imprecise |= args && !env->err;
	return false;
}

/* The value in a slot. NULL if the slot has bytes of several types. */
static const struct bpf_reg_state *slot_value(struct bpf_verifier_env *env,
					      const struct bpf_func_state *f, u32 spi,
					      struct bpf_reg_state *tmp)
{
	const struct bpf_stack_state *slot;
	u32 i, byte_types = BIT(STACK_INVALID);

	if (spi < bpf_stack_nr_slots(f)) {
		slot = bpf_stack_slot(f, spi);
		if (bpf_is_spilled_reg(slot) || bpf_slot_is_held(slot))
			return &slot->spilled_ptr;
		for (i = 0, byte_types = 0; i < BPF_REG_SIZE; i++)
			byte_types |= BIT(slot->slot_type[i]);
	}
	byte_types &= ~BIT(STACK_POISON);
	if (env->allow_uninit_stack && (byte_types & BIT(STACK_INVALID)))
		byte_types = (byte_types & ~BIT(STACK_INVALID)) | BIT(STACK_MISC);
	if (byte_types == BIT(STACK_ZERO))
		bpf_mark_reg_known_scalar(tmp, 0);
	else if (byte_types == BIT(STACK_MISC))
		bpf_mark_reg_unknown(tmp);
	else if (!(byte_types & ~BIT(STACK_INVALID)))
		bpf_mark_reg_not_init(env, tmp);
	else
		return NULL;
	return tmp;
}

const struct bpf_reg_state *bpf_xreg_value(struct bpf_verifier_env *env,
					   const struct bpf_func_state *f, u32 xregno,
					   struct bpf_reg_state *tmp)
{
	return xregno < MAX_BPF_REG ? &f->regs[xregno] :
	       slot_value(env, f, bpf_xreg_to_spi(xregno), tmp);
}

static u64 hash_type(const struct bpf_reg_state *reg, u64 hash)
{
	if (type_is_pkt_pointer(reg->type) || base_type(reg->type) == PTR_TO_ARENA)
		return bpf_hash64(&reg->type, sizeof(reg->type), hash);
	return bpf_hash64(reg, offsetof(typeof(*reg), var_off), hash);
}

/*
 * States with another type or object in data_deps stay apart. Hash these like the join_key.
 * @consts: find a state with the same constants in all deps.
 */
u64 bpf_hash_apart_xregs(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			 u64 hash, bool consts)
{
	unsigned long data_deps[XREG_WORDS], control_deps[XREG_WORDS];
	const struct bpf_reg_state *reg;
	struct bpf_reg_state tmp;
	u32 fr, xregno, bits;

	for (fr = 0; env->precision->data_deps && fr <= st->curframe; fr++) {
		bits = bpf_frame_mask(env, env->precision->type_apart, st, fr, data_deps);
		if (env->allow_uninit_stack)
			bits = min(bits, bpf_spi_to_xreg(bpf_stack_nr_slots(st->frame[fr])));
		if (consts) {
			bpf_frame_mask(env, env->precision->control_deps, st, fr, control_deps);
			bitmap_or(data_deps, data_deps, control_deps, bits);
		}
		bpf_add_cost(env, 2 * bitmap_weight(data_deps, bits), BPF_COST_XREG);
		for_each_set_bit(xregno, data_deps, bits) {
			reg = bpf_xreg_value(env, st->frame[fr], xregno, &tmp);
			if (reg && consts && tnum_is_const(reg->var_off))
				hash = bpf_hash64(&reg->var_off.value, sizeof(u64), hash + xregno);
			if (reg && reg->type != SCALAR_VALUE)
				hash = hash_type(reg, hash + xregno);
		}
	}
	return hash;
}

static u64 hash_number(const struct bpf_reg_state *reg, u64 hash)
{
	if (reg->type == NOT_INIT || base_type(reg->type) == PTR_TO_ARENA)
		return hash;
	return bpf_hash64(&reg->r64, sizeof(reg->r64), hash);
}

/* Calls with other numbers in data_deps do not share an instance */
u64 bpf_hash_args(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, u64 hash)
{
	const struct bpf_func_state *f = st->frame[0];
	unsigned long data_deps;
	u32 i;

	if (!env->precision->data_deps)
		return hash;
	data_deps = *mask_at(env, env->precision->data_deps, f->subprogno, st->insn_idx);
	for (i = BPF_REG_1; i <= BPF_REG_5; i++)
		if (data_deps & BIT(i))
			hash = hash_number(&f->regs[i], hash + i);
	for (i = 0; (data_deps & BIT(XREG_STACK_ARGS)) && i < f->out_stack_arg_cnt; i++)
		hash = hash_number(&f->stack_arg_regs[i], hash + i);
	return hash;
}

static u32 clamp_number(s64 x)
{
	return clamp_t(s64, x, S32_MIN, S32_MAX) - S32_MIN;
}

/* The range of the xreg that kept two states apart at this insn, and one step more */
void bpf_range_of_data_dep(struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			   u32 *first, u32 *last)
{
	u32 xregno = env->precision->data_deps ? env->precision->apart_xregno[st->insn_idx] : 0;
	const struct bpf_reg_state *reg;
	struct bpf_reg_state tmp;

	reg = xregno ? bpf_xreg_value(env, st->frame[st->curframe], xregno - 1, &tmp) : NULL;
	if (!reg || reg->type == NOT_INIT || base_type(reg->type) == PTR_TO_ARENA)
		return;
	*first = clamp_number(max_t(s64, reg_smin(reg), S32_MIN) - reg->step + 1);
	*last = clamp_number(min_t(s64, reg_smax(reg), S32_MAX) + reg->step);
}

enum {
	CMP_NEW		= BIT(0),	/* the new state has what the old one does not have */
	CMP_OLD		= BIT(1),
	CMP_DISJOINT	= BIT(2),
	CMP_GAP		= BIT(3),	/* the join has what is in neither */
	CMP_TYPE	= BIT(4),
	CMP_ALL		= CMP_NEW | CMP_OLD | CMP_DISJOINT | CMP_GAP | CMP_TYPE,
};

/* 0 and 3 have no gap: the join is 0..3 step 3. Most accesses ignore the step. */
static bool has_gap(const struct bpf_reg_state *a, const struct bpf_reg_state *b, bool in64,
		    bool in32)
{
	struct scalar join = *scalar_of(a);
	u64 size;

	scalar_union(&join, scalar_of(b));
	if (a->type != SCALAR_VALUE || (a->r64.size && a->step != join.step) ||
	    (b->r64.size && b->step != join.step))
		join.step = 1;
	size = a->r64.size + b->r64.size + join.step;
	return (in64 && size > a->r64.size && join.r64.size > size) ||
	       (in32 && join.r32.size > (u64)a->r32.size + b->r32.size + join.step);
}

/*
 * If two packet pointers share an id and their distance differs, the join gives them two ids,
 * see join_pkt_id(). Then a test of one checks no bytes for the other one.
 * A pointer with no id in both states is a constant: it is disjoint if it differs.
 */
static bool pkt_distance_differs(struct bpf_verifier_env *env, const struct bpf_reg_state *a,
				 const struct bpf_reg_state *b)
{
	struct bpf_pkt_pair pair = { a->id, b->id, b->r64.base - a->r64.base };
	const struct bpf_pkt_pair *p = env->pkt_pairs;

	if (!type_is_pkt_pointer(a->type) || !(a->id || b->id))
		return false;
	bpf_add_cost(env, env->pkt_pair_cnt, BPF_COST_SCAN);
	for (; p < env->pkt_pairs + env->pkt_pair_cnt; p++)
		if (p->old == pair.old && p->cur == pair.cur)
			return p->delta != pair.delta;
	bpf_add_pkt_pair(env, &pair);
	return false;
}

static u32 compare_values(struct bpf_verifier_env *env, const struct bpf_reg_state *a,
			  const struct bpf_reg_state *b)
{
	bool disjoint64, disjoint32;
	u32 flags, pkt_flags = 0;
	s64 left_a, left_b;

	bpf_add_cost(env, 1, BPF_COST_XREG);
	if (!bpf_same_type_and_object(env, a, b))
		return a->type == NOT_INIT ? CMP_OLD : b->type == NOT_INIT ? CMP_NEW :
		       reg_object_equal(a, b) ? CMP_ALL & ~CMP_TYPE : CMP_ALL;
	if (a->type == NOT_INIT || base_type(a->type) == PTR_TO_ARENA)
		return 0;
	if (type_is_pkt_pointer(a->type)) {
		if ((a->id && b->id && a->id != b->id) ||
		    (a->range != b->range && min(a->range, b->range) < 0))
			return CMP_ALL;
		left_a = a->range ? pkt_bytes_left(a) : S32_MIN;
		left_b = b->range ? pkt_bytes_left(b) : S32_MIN;
		pkt_flags = left_b < left_a ? CMP_NEW : left_b > left_a ? CMP_OLD : 0;
	}
	if (pkt_distance_differs(env, a, b))
		pkt_flags = CMP_NEW | CMP_OLD | CMP_GAP;
	if (scalar_equal(scalar_of(a), scalar_of(b)))
		return pkt_flags;
	flags = (bpf_scalar_subsumes(a, b) ? 0 : CMP_NEW) |
		(bpf_scalar_subsumes(b, a) ? 0 : CMP_OLD);
	if (pkt_flags && (flags & ~pkt_flags))
		flags |= CMP_GAP;
	flags |= pkt_flags;
	disjoint64 = cnum64_is_empty(cnum64_intersect(a->r64, b->r64));
	disjoint32 = cnum32_is_empty(cnum32_intersect(a->r32, b->r32));
	if (disjoint64 || disjoint32 ||
	    ((a->var_off.value ^ b->var_off.value) & ~(a->var_off.mask | b->var_off.mask)))
		flags |= CMP_DISJOINT;
	if ((disjoint64 || disjoint32) && has_gap(a, b, disjoint64, disjoint32))
		flags |= CMP_GAP;
	return flags;
}

/* An argument that is not there is unreadable */
static const struct bpf_reg_state *stack_arg_value(const struct bpf_func_state *f, u32 i)
{
	static const struct bpf_reg_state not_init;

	return i < f->out_stack_arg_cnt ? &f->stack_arg_regs[i] : &not_init;
}

static void note_cmp(struct state_cmp *cmp, u32 flags, bool data_dep, bool value)
{
	if (!(value ? flags : flags & CMP_TYPE))
		return;
	cmp->all |= flags;
	cmp->data_deps |= data_dep || !value ? flags : 0;
	cmp->cnt++;
}

static u32 compare_slots(struct bpf_verifier_env *env, struct state_cmp *cmp,
			 const struct bpf_func_state *fa, const struct bpf_func_state *fb, u32 spi)
{
	bool same = spi < bpf_stack_nr_slots(fa) && spi < bpf_stack_nr_slots(fb) &&
		    !memcmp(bpf_stack_slot(fa, spi)->slot_type, bpf_stack_slot(fb, spi)->slot_type,
			    BPF_REG_SIZE);
	const struct bpf_reg_state *a, *b;
	u32 flags;

	/* bytes and no value */
	if (same && !bpf_is_spilled_reg(bpf_stack_slot(fa, spi)) &&
	    !bpf_slot_is_held(bpf_stack_slot(fa, spi)))
		return 0;
	a = slot_value(env, fa, spi, &cmp->tmp[0]);
	b = slot_value(env, fb, spi, &cmp->tmp[1]);
	if (!a || !b)
		return same ? 0 : CMP_ALL;
	flags = compare_values(env, a, b);
	/* the join has the bytes and no value */
	if (!same && ((flags & CMP_NEW) ?: a != &cmp->tmp[0]) &&
	    ((flags & CMP_OLD) ?: b != &cmp->tmp[1]))
		return CMP_ALL;
	return flags;
}

/* What differs in the deps, or in the masks @only. The ivs of @iv_loop have no gaps. */
void bpf_compare_states(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
			const struct bpf_verifier_state *new, unsigned long *only,
			const struct bpf_loop *iv_loop, struct state_cmp *cmp)
{
	unsigned long data_deps[XREG_WORDS], deps[XREG_WORDS], all[XREG_WORDS];
	unsigned long disjoint_apart[XREG_WORDS];
	const struct bpf_reg_state *a, *b;
	const struct bpf_func_state *fa, *fb;
	struct bpf_precision *prec = env->precision;
	u32 fr, xregno, i, flags, arg_cnt, bits;

	cmp->all = cmp->data_deps = cmp->disjoint_apart = cmp->cnt = cmp->disjoint_xregno = 0;
	env->pkt_pair_cnt = 0;
	for (fr = 0; prec->data_deps && fr <= old->curframe; fr++) {
		fa = old->frame[fr];
		fb = new->frame[fr];
		bpf_frame_mask(env, prec->disjoint_apart, old, fr, disjoint_apart);
		bpf_frame_mask(env, only ?: prec->control_deps, old, fr, deps);
		bpf_frame_mask(env, only ?: prec->type_apart, old, fr, all);
		bits = min(bpf_frame_mask(env, only ?: prec->data_deps, old, fr, data_deps),
			   bpf_spi_to_xreg(max(bpf_stack_nr_slots(fa), bpf_stack_nr_slots(fb))));
		bitmap_or(all, all, deps, bits);
		bitmap_or(deps, deps, data_deps, bits);
		bpf_add_cost(env, 4 + bitmap_weight(all, bits), BPF_COST_COPY);
		/* r1 == r6 in one state only: two xregs differ, count both */
		flags = (bpf_equations_join_forgets(env, old, new, fr, data_deps, deps, bits) ?
			 CMP_NEW : 0) |
			(bpf_equations_join_forgets(env, new, old, fr, data_deps, deps, bits) ?
			 CMP_OLD : 0);
		note_cmp(cmp, flags, true, true);
		note_cmp(cmp, flags, true, true);
		for_each_set_bit(xregno, all, bits) {
			if (xregno == XREG_STACK_ARGS) {
				arg_cnt = max(fa->out_stack_arg_cnt, fb->out_stack_arg_cnt);
				for (i = 0; i < arg_cnt; i++) {
					flags = compare_values(env, stack_arg_value(fa, i),
							       stack_arg_value(fb, i));
					note_cmp(cmp, flags, test_bit(xregno, data_deps),
						 test_bit(xregno, deps));
					if (test_bit(xregno, disjoint_apart))
						cmp->disjoint_apart |= flags;
				}
				flags = 0;
			} else if (xregno < MAX_BPF_REG) {
				a = &fa->regs[xregno];
				b = &fb->regs[xregno];
				flags = compare_values(env, a, b);
			} else {
				flags = compare_slots(env, cmp, fa, fb, bpf_xreg_to_spi(xregno));
			}
			if (iv_loop && fr == old->curframe && !(flags & CMP_TYPE) &&
			    test_bit(xregno, iv_loop->linear_xregs) &&
			    !test_bit(xregno, iv_loop->nonlinear_xregs))
				flags &= ~(CMP_DISJOINT | CMP_GAP);
			note_cmp(cmp, flags, test_bit(xregno, data_deps), test_bit(xregno, deps));
			if (fr == old->curframe && (flags & CMP_DISJOINT) &&
			    test_bit(xregno, data_deps))
				cmp->disjoint_xregno = cmp->disjoint_xregno ?: xregno + 1;
			cmp->disjoint_apart |= test_bit(xregno, disjoint_apart) ? flags : 0;
		}
	}
}

/* See PARTITION_LOOP_DISJOINT_APART */
static bool in_disjoint_apart_loop(const struct bpf_verifier_state *st)
{
	const struct bpf_loop *loop;
	u32 fr, i;

	for (fr = 0; fr <= st->curframe; fr++) {
		for (i = 0; i < st->frame[fr]->loop_stack_cnt; i++) {
			loop = st->frame[fr]->loop_stack[i].loop;
			if (loop->disjoint_apart && bpf_loop_partition_is_active(loop))
				return true;
		}
	}
	return false;
}

/*
 * The join rule. Two states at one insn have the same join_key.
 *
 *  insn 5:       r6        r7			see the example at bpf_compute_deps()
 *   ok_state     0..7      0
 *   err_state    8..max    -22
 *                (data)    (control) -> keep apart
 *  insn 8:       r6        r7    r8
 *   ok_state     0..7      0     1
 *   ok_state     0..7      0     2
 *                                (control only) -> join
 *
 *  what differs               action
 *  data dep and control dep   keep apart
 *  two data deps              keep apart
 *  one data dep, with a gap   keep apart   (0..1 and 100)
 *  one data dep, no gap       join         (0..7 and 8..9, 0 and 3),
 *                                          apart after keep_disjoint_apart()
 *  control deps only          join
 *  other regs only            join
 *
 * If one state subsumes the other in the deps, the join adds no pair.
 *
 * BPF_JOIN_POINT_HEADER: @new came back to the header of the loop of @entry. Only a type or
 * an object keeps the states apart, unless the loop is partitioned. An imprecise join makes
 * the loop a suspect.
 * BPF_JOIN_POINT_CALLS: two calls get to the first insn of a function. The call counts as one
 * more xreg that differs.
 */
bool bpf_must_keep_apart(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
			 struct bpf_verifier_state *new, enum bpf_join_point kind,
			 const struct loop_stack_entry *entry)
{
	bool keep, disjoint_apart = in_disjoint_apart_loop(new);
	struct bpf_loop *loop;
	struct state_cmp cmp;

	/* in two entries an iv can have two values for one trip index */
	bpf_compare_states(env, old, new, NULL, disjoint_apart && entry &&
			   kind == BPF_JOIN_POINT_HEADER ? entry->loop : NULL, &cmp);
	if (kind == BPF_JOIN_POINT_CALLS)
		return cmp.data_deps;
	if ((cmp.data_deps & CMP_DISJOINT) && disjoint_apart)
		return true;
	keep = (cmp.data_deps & CMP_GAP) || (cmp.disjoint_apart & CMP_DISJOINT) ||
	       (cmp.data_deps && cmp.cnt > 1 && (cmp.all & CMP_NEW) && (cmp.all & CMP_OLD));
	env->precision->this_pass.disjoint_joined |= !keep && (cmp.data_deps & CMP_DISJOINT);
	if (keep && !env->precision->apart_xregno[new->insn_idx])
		env->precision->apart_xregno[new->insn_idx] = cmp.disjoint_xregno;
	if (keep && (kind == BPF_JOIN_POINT || (cmp.all & CMP_TYPE)))
		return true;
	if (!entry)
		return false;
	loop = entry->loop;
	if (keep && entry->peeled && loop->peeled_apart && bpf_loop_partition_is_active(loop))
		return true;
	if (entry->peeled ? keep : cmp.data_deps & CMP_NEW)
		new->suspect_loops |= loop->suspect_bit;
	loop->peeled_joined |= entry->peeled && keep;
	return false;
}

/* Does @new have more in the deps? */
bool bpf_values_grew_in_deps(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
			     const struct bpf_verifier_state *new)
{
	struct state_cmp cmp;

	bpf_compare_states(env, old, new, NULL, NULL, &cmp);
	return cmp.all & CMP_NEW;
}

/* The function that the insn at @idx calls, or hands to a helper. -1 if that is not known. */
int bpf_insn_callee(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[idx];
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	u16 funcs = aux->const_reg_subprog_mask & aux->use_regs;

	if (bpf_pseudo_call(insn))
		return bpf_find_subprog(env, idx + insn->imm + 1);
	if (hweight16(funcs) == 1 && (aux->calls_callback ||
				      bpf_is_async_callback_calling_insn(insn)))
		return aux->const_reg_vals[__ffs(funcs)];
	return -1;
}

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

/* What callers need of a function: the registers that it returns, and */
#define RET_REGS	(BIT(BPF_REG_0) | BIT(BPF_REG_2))
#define RET_HELD	BIT(4)	/* what is held */
#define RET_ACQUIRES	BIT(5)	/* it writes that */
#define RET_STORES	BIT(6)	/* what it stores to their frames */
#define RET_LOADS	BIT(7)	/* it needs what it loads from there */

/*
 * What is held is tracked like an xreg, with one bit per insn in held_insns. It includes the way
 * in which a function was left. It is in the join_key, so only the insns that write it matter.
 */
static bool reads_held(struct bpf_verifier_env *env, int idx)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[idx];
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	u8 class = BPF_CLASS(insn->code);

	if (bpf_is_unwind_goto(insn) || bpf_pseudo_call(insn) || bpf_is_callx(insn))
		return true;
	/* a loop header, ld_abs, a call, an exit */
	return test_bit(idx, env->precision->last_pass.unproven_insns) &&
	       (aux->loop || class == BPF_LD ||
		(class == BPF_JMP && !bpf_insn_is_cond_jump(insn->code)));
}

static bool has_slots(const unsigned long *mask, const unsigned long *slots, u32 bits)
{
	u32 i;

	for (i = 0; i < BITS_TO_LONGS(bits); i++)
		if (mask[i] & bpf_slots_to_xreg_word(slots, i))
			return true;
	return false;
}

/* The call at @idx needs @needs of function @t. Returns the arguments that @t needs. */
static u16 compute_call_deps(struct bpf_verifier_env *env, unsigned long *masks, u8 *ret, int t,
			     u8 needs, bool *held, bool *changed)
{
	u32 start = env->subprog_info[t].start;

	*changed |= needs & ~ret[t];
	ret[t] |= needs;
	*held |= test_bit(start, env->precision->held_insns);
	return *mask_at(env, masks, t, start) &
	       (GENMASK(BPF_REG_5, BPF_REG_1) | BIT(XREG_STACK_ARGS));
}

/* What the insn at @idx of function @s needs before it. @in has what is needed after it. */
static bool compute_insn_deps(struct bpf_verifier_env *env, unsigned long *masks, u8 *ret, int s,
			      int idx, bool is_seed, unsigned long *in, bool held)
{
	struct bpf_insn_aux_data *aux = &env->insn_aux_data[idx];
	struct bpf_insn *insn = &env->prog->insnsi[idx];
	u32 bits = env->precision->func[s].words * BITS_PER_LONG;
	u16 use = aux->use_regs, def = aux->def_regs, args = 0;
	bool changed = false, stores, reads, loads, call, held_after;
	struct taken_funcs *taken = &env->precision->taken;
	u8 class = BPF_CLASS(insn->code), needs;
	int t, callee;

	call = class == BPF_JMP && BPF_OP(insn->code) == BPF_CALL;
	/* the next call of the callback reads what this one stores */
	if (aux->calls_callback) {
		bitmap_or(in, in, mask_at(env, masks, s, idx), bits);
		held |= test_bit(idx, env->precision->held_insns);
	}
	if (insn->code == (BPF_JMP | BPF_EXIT) || bpf_is_throw_kfunc(insn))
		held = ret[s] & RET_HELD;
	held_after = held |= is_seed && reads_held(env, idx);
	stores = has_slots(in, aux->may_write_mask, bits) ||
		 (aux->writes_outer && (ret[s] & RET_STORES)) ||
		 ((is_stack_arg_st(insn) || is_stack_arg_stx(insn)) &&
		  test_bit(XREG_STACK_ARGS, in));
	needs = (in[0] & def & RET_REGS) | (stores ? RET_STORES : 0) | (held ? RET_HELD : 0);
	if ((in[0] & def & XREG_REGS) || stores)
		__set_bit(idx, env->precision->controlled_insns);
	/* what a helper stores is not known, whatever it reads */
	reads = (in[0] & def & XREG_REGS) || (stores && !call);
	loads = reads || test_bit(idx, env->precision->bad_value_insns) ||
		!(test_bit(idx, env->precision->last_pass.unproven_insns) ||
		  test_bit(idx, env->precision->last_pass.bad_read_insns));
	if (!loads && class == BPF_STX)
		use = BIT(insn->dst_reg);
	reads |= is_seed;
	in[0] &= ~(unsigned long)(def & XREG_REGS);
	for (t = 0; t < BITS_TO_LONGS(bits); t++)
		in[t] &= bpf_slots_to_xreg_word(aux->live_stack_before, t) |
			 (t ? 0 : BIT(MAX_BPF_EXT_REG) - 1);
	/* the address and the size decide if a helper keeps a slot */
	if (call && (has_slots(in, aux->may_write_mask, bits) ||
		     (aux->writes_outer && (ret[s] & RET_STORES))))
		in[0] |= use & (aux->stack_ptrs | aux->stack_ptrs << 1);

	callee = bpf_insn_callee(env, idx);
	if (callee > 0 && bpf_subprog_is_global(env, callee))
		callee = -1;
	if (callee > 0 && bpf_pseudo_call(insn)) {
		args = compute_call_deps(env, masks, ret, callee, needs, &held, &changed);
		use = env->insn_aux_data[env->subprog_info[callee].start].live_regs_before;
		reads = is_seed;
		needs = ret[callee];
	} else if (callee > 0) {
		reads |= compute_call_deps(env, masks, ret, callee, needs & ~RET_REGS, &held,
					   &changed);
		needs = ret[callee];
	} else if (bpf_is_callx(insn) || aux->calls_callback) {
		changed |= needs & ~taken->needs;
		taken->needs |= needs;
		held |= taken->held;
		args = taken->args;
		needs = taken->ret;
		reads |= args;
	} else {
		needs = 0;
	}
	if (insn->code == (BPF_JMP | BPF_EXIT))
		args = ret[s] & RET_REGS;
	if (held_after && (aux->acquires || aux->releases || (needs & RET_ACQUIRES) ||
			   bpf_is_unwind_exit(insn) || bpf_is_throw_kfunc(insn))) {
		__set_bit(idx, env->precision->last_pass.call_insns);
		reads |= aux->releases;
		changed |= !(ret[s] & RET_ACQUIRES);
		ret[s] |= RET_ACQUIRES;
	}
	if (held)
		changed |= !__test_and_set_bit(idx, env->precision->held_insns);
	in[0] |= args | (reads ? use & XREG_REGS : 0);
	if (reads && (call || is_stack_arg_ldx(insn)))
		__set_bit(XREG_STACK_ARGS, in);
	if ((reads && loads) || (needs & RET_LOADS)) {
		bpf_add_slots(in, aux->may_read_mask, bits);
		/* the callee reads what it wrote */
		if (needs & RET_LOADS)
			bpf_add_slots(in, aux->may_write_mask, bits);
		if ((aux->reads_outer || (call && aux->writes_outer)) && !(ret[s] & RET_LOADS)) {
			ret[s] |= RET_LOADS;
			changed = true;
		}
	}
	return changed;
}

/*
 * A backward slice: the same backward analysis as liveness, from other seeds.
 *
 *  liveness:      start from the reads of ALL insns
 *  data_deps:     start from the reads of the unproven insn
 *  control_deps:  start from the reads of the jumps that can skip the unproven insn
 *
 *                                        data     control
 *  1: r6 = ctx->idx                      r1       -
 *  2: r7 = 0                             r6       -
 *  3: if r6 <= 7 goto 5                  r6       r7
 *  4: r7 = -22                           r6       -
 *  5: r8 = 1               join point    r6       r7
 *  6: if r9 == 0 goto 8                  r6       r7 r8
 *  7: r8 = 2                             r6       r7
 *  8: if r8 == 3 goto exit join point    r6       r7 r8    <- seed of control_deps: r8
 *  9: if r7 != 0 goto exit               r6       r7       <- seed of control_deps: r7
 * 10: r2 = r6                            r6       -
 * 11: r2 <<= 3                           r2       -
 * 12: r3 = map value                     r2       -
 * 13: r3 += r2                           r2 r3    -
 * 14: r0 = *(u64 *)(r3 + 0)              r3       -        <- seed of data_deps: r3
 *
 * controlled_insns gets the insns that write an xreg of @masks, for add_transitive_deps().
 */
int bpf_compute_deps(struct bpf_verifier_env *env, unsigned long *masks,
		     const unsigned long *seed_insns)
{
	struct bpf_subprog_info *sub = env->subprog_info;
	struct bpf_precision *prec = env->precision;
	unsigned long in[XREG_WORDS], *old;
	int i, k, s, t, idx, err = 0;
	struct bpf_iarray *succ;
	bool changed = true, held;
	u32 bits;
	u8 *ret;

	ret = kvcalloc(env->subprog_cnt, sizeof(*ret), BPF_VERIFIER_GFP);
	if (!ret)
		return -ENOMEM;
	memset(masks, 0, prec->words * sizeof(long));
	bitmap_zero(prec->held_insns, env->prog->len);
	bitmap_zero(prec->controlled_insns, env->prog->len);
	prec->taken = (struct taken_funcs){};
	while (changed) {
		changed = false;
		bpf_add_cost(env, env->cfg.gotox_edges, BPF_COST_COPY);
		err = bpf_add_cost_and_check(env, prec->words + env->prog->len, BPF_COST_XREG);
		if (err)
			break;
		/* callees first */
		for (k = 0; k < env->subprog_cnt; k++) {
			s = env->subprog_topo_order[k];
			bits = prec->func[s].words * BITS_PER_LONG;
			for (i = sub[s].postorder_start; i <= sub[s + 1].postorder_start; i++) {
				/* it can be dead code, see push_unwind_exit() */
				idx = i < sub[s + 1].postorder_start ? env->cfg.insn_postorder[i] :
				      sub[s].bail_insn;
				if (idx < 0)
					break;
				bitmap_zero(in, bits);
				succ = bpf_insn_successors(env, idx);
				held = false;
				iarray_for_each(t, succ) {
					bitmap_or(in, in, mask_at(env, masks, s, t), bits);
					held |= test_bit(t, prec->held_insns);
				}
				t = bpf_head_guard_target(env, idx);
				if (t >= 0)
					bitmap_or(in, in, mask_at(env, masks, s, t), bits);
				changed |= compute_insn_deps(env, masks, ret, s, idx,
							     test_bit(idx, seed_insns), in, held);
				if (idx == prec->loop_carried_at) {
					bitmap_or(in, in, prec->loop_carried, bits);
					changed |= !(ret[s] & RET_STORES);
					ret[s] |= RET_STORES;
				}
				old = mask_at(env, masks, s, idx);
				changed |= !bitmap_subset(in, old, bits);
				bitmap_or(old, old, in, bits);
			}
			if (!sub[s].addr_taken)
				continue;
			prec->taken.args |= compute_call_deps(env, masks, ret, s, prec->taken.needs,
							      &prec->taken.held, &changed);
			prec->taken.ret |= ret[s];
		}
	}
	kvfree(ret);
	return err;
}

struct block {
	u32 first, last;
	/* @last leaves that loop to @out. It is the outermost one, 0 if none. */
	u32 header, out;
};

/* The basic blocks of @sub in post order */
static u32 find_blocks(struct bpf_verifier_env *env, struct bpf_subprog_info *sub, u32 *first,
		       struct block *blocks)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	struct block *b = blocks;
	struct bpf_iarray *succ;
	int i, n, s, t, h;

	for (i = sub->start; i < sub[1].start; i++)
		first[i] = bpf_flow_is_bb_start(env, i) ? i : first[i - 1];
	for (i = sub->postorder_start; i < sub[1].postorder_start; i++) {
		n = env->cfg.insn_postorder[i];
		succ = bpf_insn_successors(env, n);
		if (succ->cnt == 1 && !bpf_flow_is_bb_start(env, succ->items[0]))
			continue;
		*b = (struct block){ first[n], n };
		iarray_for_each(s, succ) {
			t = bpf_loop_at_index(env, s);
			for (h = bpf_loop_at_index(env, n);
			     h >= 0 && h != t && !bpf_is_nested_loop(env, t, h);
			     h = aux[h].loop_header) {
				b->header = h;
				b->out = s;
			}
		}
		b++;
	}
	return b - blocks;
}

static bool may_not_return(struct bpf_verifier_env *env, struct bpf_subprog_info *sub, u32 idx)
{
	struct bpf_insn *insn = &env->prog->insnsi[idx];

	if (bpf_pseudo_call(insn))
		return env->subprog_info[bpf_insn_callee(env, idx)].might_throw;
	return bpf_is_callx(insn) && sub->might_throw;
}

/*
 * The jumps that can skip one of controlled_insns: one edge leads to the insn, another does not.
 * A back edge leads to nothing, so 'continue' skips. The edge that stays in a loop leads to all
 * that the header leads to, so 'break' skips too. A call that throws skips too.
 */
static int find_control_seeds(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub = NULL;
	struct bpf_precision *prec = env->precision;
	u32 len = env->prog->len, idx = 0, cnt = 0, s, bit, *first;
	struct block *blocks, *b;
	struct bpf_iarray *succ;
	u64 *leads, any, all;
	int err = 0;

	leads = kvmalloc_array(len, sizeof(*leads) + sizeof(*blocks) + sizeof(*first),
			       BPF_VERIFIER_GFP);
	if (!leads)
		return -ENOMEM;
	blocks = (void *)(leads + len);
	first = (void *)(blocks + len);
	bitmap_andnot(prec->controlled_insns, prec->controlled_insns,
		      prec->controlled_insns_done, len);
	bitmap_or(prec->controlled_insns_done, prec->controlled_insns_done,
		  prec->controlled_insns, len);
	while (!err && (idx = find_next_bit(prec->controlled_insns, len, idx)) < len) {
		if (!sub || idx >= sub[1].start) {
			sub = bpf_find_containing_subprog(env, idx);
			cnt = find_blocks(env, sub, first, blocks);
			bpf_add_cost(env, sub[1].start - sub->start, BPF_COST_XREG);
		}
		for (b = blocks; b < blocks + cnt; b++)
			leads[b->first] = 0;
		for (bit = 0; bit < 64 && idx < sub[1].start; bit++) {
			leads[first[idx]] = BIT_ULL(bit);
			/* the other insns of the basic block have the same control seeds */
			while (++idx < sub[1].start && !bpf_flow_is_bb_start(env, idx))
				;
			idx = find_next_bit(prec->controlled_insns, len, idx);
		}
		for (b = blocks; b < blocks + cnt; b++) {
			if (bpf_is_throw_kfunc(&env->prog->insnsi[b->last]))
				continue;
			succ = bpf_insn_successors(env, b->last);
			bpf_add_cost(env, succ->cnt, BPF_COST_COPY);
			any = 0;
			all = U64_MAX;
			iarray_for_each(s, succ) {
				any |= leads[s];
				all &= leads[s];
			}
			if (succ->cnt > 1 ? any != all : any && may_not_return(env, sub, b->last))
				__set_bit(b->last, prec->control_seeds);
			leads[b->first] |= any;
		}
		for (b = blocks; b < blocks + cnt; b++)
			if (b->out && (leads[b->header] & ~leads[b->out]))
				__set_bit(b->last, prec->control_seeds);
		err = bpf_add_cost_and_check(env, cnt, BPF_COST_XREG);
	}
	kvfree(leads);
	return err;
}

/* The calls that lead to the unproven insns */
static int find_calls_to_unproven(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub = env->subprog_info;
	struct precision_per_pass *last_pass = &env->precision->last_pass;
	struct bpf_insn_aux_data *aux;
	bool taken = false, changed = true;
	int i, k, n, s, err = 0;

	while (changed && !err) {
		changed = false;
		for_each_set_bit(s, last_pass->unproven_funcs, env->subprog_cnt)
			taken |= sub[s].addr_taken;
		/* callees first. callx and a cycle of calls need more rounds. */
		for (k = 0; k < env->subprog_cnt; k++) {
			n = env->subprog_topo_order[k];
			for (i = sub[n].start; i < sub[n + 1].start; i++) {
				aux = &env->insn_aux_data[i];
				s = bpf_insn_callee(env, i);
				if (!aux->seen || !bpf_calls_function(env, i) ||
				    !(s > 0 ? test_bit(s, last_pass->unproven_funcs) : taken))
					continue;
				__set_bit(i, last_pass->call_insns);
				changed |= !__test_and_set_bit(n, last_pass->unproven_funcs);
			}
		}
		err = bpf_add_cost_and_check(env, env->prog->len, BPF_COST_XREG);
	}
	return err;
}

static bool add_masks(struct bpf_precision *prec, unsigned long *to, const unsigned long *from)
{
	bool more = false;
	size_t i;

	for (i = 0; i < prec->words; i++) {
		more |= from[i] & ~to[i];
		to[i] |= from[i];
	}
	return more;
}

/* The control_deps of controlled_insns. Returns 1 if there is more in the deps. */
static int add_control_deps(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	int err = find_control_seeds(env) ?:
		  bpf_compute_deps(env, prec->new_control_deps, prec->control_seeds);
	bool more;

	if (err)
		return err;
	more = add_masks(prec, prec->data_deps, prec->new_data_deps);
	more |= add_masks(prec, prec->control_deps, prec->new_control_deps);
	more |= add_masks(prec, prec->type_apart, prec->new_data_deps);
	return more;
}

static int compute_deps_of_unproven(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	u32 len = env->prog->len, i;
	int err;

	err = bpf_compute_deps(env, prec->new_data_deps, prec->last_pass.unproven_insns);
	if (err)
		return err;
	/* the insns that write data_deps wait for add_transitive_deps() */
	bitmap_copy(prec->def_insns, prec->controlled_insns, len);
	bitmap_zero(prec->controlled_insns_done, len);
	bitmap_zero(prec->control_seeds, len);
	bitmap_or(prec->controlled_insns, prec->last_pass.unproven_insns,
		  prec->last_pass.call_insns, len);
	/* the helper decides how many times the callback runs, callx what runs */
	for_each_set_bit(i, prec->last_pass.call_insns, len)
		if (bpf_calls_function(env, i) && !bpf_pseudo_call(&env->prog->insnsi[i]))
			__set_bit(i, prec->control_seeds);
	return add_control_deps(env);
}

/* An unreadable xreg needs one type and object, whatever the numbers are. Try that first. */
static int add_deps(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	u32 len = env->prog->len, i;
	int ret, more = 0;

	if (!bitmap_empty(prec->last_pass.bad_read_insns, len)) {
		ret = bpf_compute_deps(env, prec->new_data_deps, prec->last_pass.bad_read_insns);
		if (ret)
			return ret;
		more = add_masks(prec, prec->type_apart, prec->new_data_deps);
	}
	if (more)
		bitmap_andnot(prec->last_pass.unproven_insns, prec->last_pass.unproven_insns,
			      prec->last_pass.bad_read_insns, len);
	bitmap_or(prec->bad_read_insns_done, prec->bad_read_insns_done,
		  prec->last_pass.bad_read_insns, len);
	ret = compute_deps_of_unproven(env);
	for (i = 0; i < 5 * prec->words; i++)
		prec->kept[i] |= prec->data_deps[i] & ~prec->undo[i];
	bitmap_or(prec->earlier_unproven_insns, prec->earlier_unproven_insns,
		  prec->last_pass.unproven_insns, len);
	return ret < 0 ? ret : ret | more;
}

/* Add the jumps that decide which value an xreg of data_deps has */
static int add_transitive_deps(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	u32 cnt, len = env->prog->len;
	int ret = compute_deps_of_unproven(env);

	while (!ret) {
		cnt = bitmap_weight(prec->control_seeds, len);
		add_masks(prec, prec->new_data_deps, prec->new_control_deps);
		bitmap_or(prec->controlled_insns, prec->controlled_insns, prec->def_insns, len);
		bitmap_or(prec->controlled_insns, prec->controlled_insns,
			  prec->last_pass.call_insns, len);
		bitmap_or(prec->controlled_insns, prec->controlled_insns, prec->control_seeds, len);
		ret = add_control_deps(env);
		if (bitmap_weight(prec->control_seeds, len) == cnt)
			break;
	}
	return ret;
}

/* A copy of the deps. ADD_DEPS has no budget, so it must not add calls. */
static int check_calls_in_frames(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	bool more;

	if (!prec->last_pass.arg_lost_equation)
		return 0;
	more = add_masks(prec, prec->in_frames, prec->new_data_deps);
	more |= add_masks(prec, prec->in_frames, prec->new_control_deps);
	return more;
}

static int keep_disjoint_apart(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	return prec->last_pass.disjoint_joined &&
	       add_masks(prec, prec->disjoint_apart, prec->new_data_deps);
}

/* @loop is a suspect. Returns false if @kind adds nothing. */
static bool partition_loop(struct bpf_loop *loop, u32 kind)
{
	bool open = loop->last_pass.has_leftover || loop->last_pass.peel_pruned ||
		    (loop->budget && loop->last_pass.cost > loop->budget);

	switch (kind) {
	case PARTITION_PEEL:
		/* the first trip is often different from the other trips */
		loop->max_peel_cnt = loop->peel_cnt || loop->exit_trip ? U32_MAX : 1;
		break;
	case PARTITION_PEEL_MORE:
		loop->max_peel_cnt = min(4ULL * loop->peel_cnt ?: 1, U32_MAX);
		loop->no_peel_prune |= loop->last_pass.peel_pruned;
		break;
	case PARTITION_PEELED_APART:
		open = !loop->peeled_apart && loop->peeled_joined;
		loop->peeled_apart = true;
		loop->max_peel_cnt = U32_MAX;
		break;
	case PARTITION_LOOP_DISJOINT_APART:
		open = !loop->disjoint_apart &&
		       (loop->last_pass.has_leftover || loop->peel_cnt > 1);
		loop->peel_cnt = min(loop->peel_cnt, 1);
		loop->disjoint_apart = true;
		loop->max_peel_cnt = 0;
		break;
	}
	return open;
}

/*
 * The suspect loops divide half of the budget. If the cost to peel all trips is known, the
 * loop gets that, or it waits.
 */
static int partition_suspect_loops(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	struct bpf_loop *loop;
	u32 i, cnt = 0;
	int more = 0;
	u64 budget, bits = 0;

	for (i = 0; i < prec->loop_cnt; i++) {
		loop = prec->loops[i];
		loop->partitioned = (prec->last_pass.suspect_loops & loop->suspect_bit) &&
				    !(loop->tried & prec->partitioned_by) &&
				    partition_loop(loop, __ffs(prec->partitioned_by));
		if (!loop->partitioned)
			loop->precision = loop->undo;
		cnt += loop->partitioned;
		bits |= loop->partitioned ? loop->suspect_bit : 0;
	}
	budget = div_u64(prec->budget / 2, cnt ?: 1);
	for (i = 0; i < prec->loop_cnt; i++) {
		loop = prec->loops[i];
		if (!loop->partitioned)
			continue;
		loop->budget = max(loop->budget, budget);
		if (prec->partitioned_by == BIT(PARTITION_PEEL) && loop->max_peel_cnt > 1)
			loop->budget = max(loop->budget, loop->full_peel_cost);
		if (!memcmp(&loop->precision, &loop->undo, sizeof(loop->undo)) ||
		    loop->budget > 2 * prec->budget)
			loop->tried |= prec->partitioned_by | BIT(PARTITION_TOO_COSTLY);
		loop->partitioned = (bits & prec->last_pass.first_suspect_loops) &&
				    !(loop->tried & prec->partitioned_by);
		if (!loop->partitioned)
			loop->precision = loop->undo;
		prec->budget_left += loop->partitioned ? loop->budget - budget : 0;
		loop->changed |= loop->partitioned;
		more |= loop->partitioned;
	}
	return more;
}

static int (* const partition_by[])(struct bpf_verifier_env *env) = {
	[PARTITION_ADD_DEPS]		= add_deps,
	[PARTITION_PEEL]		= partition_suspect_loops,
	[PARTITION_TRANSITIVE_DEPS]	= add_transitive_deps,
	[PARTITION_PEELED_APART]	= partition_suspect_loops,
	[PARTITION_DISJOINT_APART]	= keep_disjoint_apart,
	[PARTITION_LOOP_DISJOINT_APART]	= partition_suspect_loops,
	[PARTITION_PEEL_MORE]		= partition_suspect_loops,
	[PARTITION_IN_FRAMES]		= check_calls_in_frames,
};

static int alloc_masks(struct bpf_verifier_env *env)
{
	struct bpf_subprog_info *sub = env->subprog_info;
	DECLARE_BITMAP(live, MAX_BPF_STACK_SLOTS);
	struct bpf_precision *prec = env->precision;
	struct bpf_insn_aux_data *aux;
	unsigned long *masks;
	u32 s, i, slots;
	int err;

	if (prec->func || prec->hops_to_err)
		return -ENOMEM;
	prec->func = kvcalloc(env->subprog_cnt, sizeof(*prec->func), BPF_VERIFIER_GFP);
	prec->hops_to_err = kvcalloc(5 * env->prog->len, sizeof(u16), BPF_VERIFIER_GFP);
	if (!prec->func || !prec->hops_to_err)
		return -ENOMEM;
	prec->hops_to_exit = prec->hops_to_err + env->prog->len;
	prec->apart_xregno = (void *)(prec->hops_to_exit + env->prog->len);
	for (s = 0; s < env->subprog_cnt; s++) {
		bitmap_zero(live, MAX_BPF_STACK_SLOTS);
		for (i = sub[s].start; i < sub[s + 1].start; i++) {
			aux = &env->insn_aux_data[i];
			bitmap_or(live, live, aux->live_stack_before, MAX_BPF_STACK_SLOTS);
			/* the callee reads what it wrote */
			if (bpf_pseudo_call(&env->prog->insnsi[i]))
				bitmap_or(live, live, aux->may_write_mask, MAX_BPF_STACK_SLOTS);
		}
		slots = find_last_bit(live, MAX_BPF_STACK_SLOTS) + 1;
		if (slots > MAX_BPF_STACK_SLOTS)
			slots = 0;
		prec->func[s].first = prec->words;
		prec->func[s].words = BITS_TO_LONGS(bpf_spi_to_xreg(slots));
		prec->words += (sub[s + 1].start - sub[s].start + 1) * prec->func[s].words;
	}
	env->mem += 18 * prec->words * sizeof(long) + 5 * env->prog->len * sizeof(u16);
	err = bpf_check_limits(env);
	masks = err ? NULL : kvcalloc(18 * prec->words, sizeof(long), BPF_VERIFIER_GFP);
	if (!masks) {
		env->mem -= 18 * prec->words * sizeof(long);
		return err ?: -ENOMEM;
	}
	prec->data_deps = masks;
	prec->control_deps = masks + prec->words;
	prec->disjoint_apart = masks + 2 * prec->words;
	prec->type_apart = masks + 3 * prec->words;
	prec->in_frames = masks + 4 * prec->words;
	prec->undo = masks + 5 * prec->words;
	prec->kept = masks + 10 * prec->words;
	prec->new_data_deps = masks + 15 * prec->words;
	prec->new_control_deps = masks + 16 * prec->words;
	prec->loop_control_deps = masks + 17 * prec->words;
	return 0;
}

u64 bpf_precision_budget(struct bpf_verifier_env *env)
{
	return env->precision->budget;
}

u64 bpf_precision_first_budget(struct bpf_verifier_env *env)
{
	return max(2 * env->precision->pass_cost, BPF_MIN_BUDGET);
}

/* The limit on cost of a pass */
u64 bpf_pass_max_cost(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	return env->cost + prec->pass_cost + prec->budget_left;
}

/*
 * @keep: the partition helped, keep the precision. Else undo all since the last keep.
 * If a partition was too costly for a loop, a later one is a second choice. It stays only
 * until the budget grows.
 */
static void keep_precision(struct bpf_precision *prec, bool keep)
{
	struct bpf_loop *loop;
	u16 second_choice = 0;
	u32 i;

	for (i = 0; keep && i < prec->loop_cnt; i++)
		second_choice |= prec->loops[i]->tried & BIT(PARTITION_TOO_COSTLY);
	prec->too_costly = 0;
	for (i = 0; i < prec->loop_cnt; i++)
		prec->loops[i]->tried &= second_choice;
	if (second_choice)
		return;
	memcpy(keep ? prec->kept : prec->data_deps, keep ? prec->data_deps : prec->kept,
	       5 * prec->words * sizeof(long));
	for (i = 0; i < prec->loop_cnt; i++) {
		loop = prec->loops[i];
		if (keep) {
			loop->kept = loop->precision;
			loop->full_peel_cost = 0;
		}
		loop->changed |= !!memcmp(&loop->precision, &loop->kept, sizeof(loop->kept));
		loop->precision = loop->kept;
	}
}

/* The first partition that adds something. If all others are too costly, start again. */
static int partition_next(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	int i, ret;
	u16 wait;

	prec->budget_left = prec->budget;
	memcpy(prec->undo, prec->data_deps, 5 * prec->words * sizeof(long));
	for (i = 0; i < prec->loop_cnt; i++) {
		prec->loops[i]->undo = prec->loops[i]->precision;
		prec->loops[i]->partitioned = false;
	}
	for (i = 0; i < ARRAY_SIZE(partition_by); i++) {
		prec->partitioned_by = BIT(i);
		ret = prec->too_costly & prec->partitioned_by ? 0 : partition_by[i](env);
		ret = ret ?: prec->new_nospec;
		if (ret)
			return ret;
	}
	wait = prec->too_costly | prec->last_pass.calls_joined;
	for (i = 0; i < prec->loop_cnt; i++)
		if (prec->last_pass.first_suspect_loops & prec->loops[i]->suspect_bit)
			wait |= prec->loops[i]->tried & BIT(PARTITION_TOO_COSTLY);
	prec->partitioned_by = 0;
	wait = wait && prec->budget < env->max_cost - env->cost;
	prec->budget_left = prec->budget = min(4 * prec->budget, env->max_cost - env->cost);
	prec->failing_path_due = prec->budget_grew = true;
	return wait;
}

static void undo_loop(struct bpf_precision *prec, struct bpf_loop *loop)
{
	loop->precision = loop->undo;
	loop->tried |= BIT(PARTITION_TOO_COSTLY);
	if (!loop->this_pass.starved)
		loop->tried |= prec->partitioned_by;
	if (prec->partitioned_by == BIT(PARTITION_PEEL) && loop->this_pass.peeled_cnt > 1 &&
	    loop->disjoint_apart == loop->kept.disjoint_apart)
		loop->full_peel_cost = div_u64(loop->this_pass.cost * 9 / 8,
					       loop->this_pass.peeled_cnt - 1) *
				       min(loop->exit_trip, U32_MAX);
	loop->changed = true;
}

/*
 * The first unproven insn of the last pass has no error now, and no old error came back.
 * A pass that is over its budget possibly did not get to that insn.
 */
static bool partition_helped(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	return prec->first_unproven_insn < env->prog->len &&
	       !test_bit(prec->first_unproven_insn, prec->this_pass.unproven_insns) &&
	       (!test_bit(env->err_insn, prec->earlier_unproven_insns) ||
		(test_bit(env->err_insn, prec->last_unproven_insns) &&
		 !prec->this_pass.over_budget));
}

/* The pass is over its budget. Returns true if another partition replaces the last one. */
bool bpf_undo_precision(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	bool over_budget = false, again = false;
	struct bpf_loop *loop;
	u32 i;

	prec->this_pass.over_budget = env->over_limit;
	prec->this_pass.calls_joined = env->calls_joined;
	if (!env->over_limit || env->cost > env->max_cost)
		return false;
	if (prec->partitioned_by <= BIT(PARTITION_ADD_DEPS) ||
	    (env->err && (prec->last_pass.over_budget || partition_helped(env)))) {
		env->over_limit = !env->err;
		return false;
	}
	env->over_limit = false;
	memcpy(prec->data_deps, prec->undo, 5 * prec->words * sizeof(long));
	for (i = 0; i < prec->loop_cnt; i++)
		over_budget |= prec->loops[i]->partitioned &&
			       !bpf_loop_has_budget(prec->loops[i]);
	for (i = 0; i < prec->loop_cnt; i++) {
		loop = prec->loops[i];
		if (loop->partitioned)
			undo_loop(prec, loop);
		/* if the old budget was enough, the pass possibly did not get to the loop */
		if (loop->partitioned && over_budget && bpf_loop_has_budget(loop))
			loop->tried &= ~prec->partitioned_by;
		/* peeled_apart did not help. The partition can fit without it. */
		if (loop->peeled_apart && !loop->kept.peeled_apart) {
			loop->peeled_apart = false;
			loop->tried |= BIT(PARTITION_PEELED_APART) |
				       BIT(PARTITION_TOO_COSTLY);
			loop->changed = again = true;
		}
	}
	if (partition_by[__ffs(prec->partitioned_by)] != partition_suspect_loops && !again)
		prec->too_costly |= prec->partitioned_by;
	return partition_next(env) > 0;
}

/*
 * Keep more apart in the next pass. Take the first line that adds something:
 *
 *  ADD_DEPS             the deps of the unproven insns; for an unreadable xreg
 *                       type_apart first
 *  PEEL                 suspect loops: one trip, then as many as the budget pays for
 *  PEELED_APART         suspect loops: the join rule holds at the start of a peeled trip
 *  TRANSITIVE_DEPS      data_deps |= control_deps; add the jumps that can skip their writes
 *  DISJOINT_APART       disjoint values in data_deps stay apart
 *  LOOP_DISJOINT_APART  suspect loops: the same, also at the header of the leftover;
 *                       it replaces peeling
 *  PEEL_MORE            suspect loops: 4, 16, 64, ... trips for each state that enters
 *  IN_FRAMES            calls with an argument that is in the deps and has an equation
 *
 * All but ADD_DEPS can be undone:
 *
 *            +-----------------+   in the budget, or it helped
 *       +--->| partition, pass |------------------------------------> keep
 *       |    +--------+--------+
 *       |             | over its part of the budget
 *       |             v
 *       +--- undo, take the next line
 *       |             | no line left, one was too costly
 *       |             v
 *       +--- budget *= 4, undo all since one helped, see keep_precision()
 *
 * Returns 1 if more is kept apart.
 */
int bpf_partition_more(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;
	bool helped, undone = false;
	struct bpf_loop *loop;
	int ret;
	u32 i;

	ret = prec->data_deps ? 0 : alloc_masks(env);
	if (ret)
		return ret;
	if (!test_bit(env->err_insn, prec->this_pass.unproven_insns))
		env->err_insn = find_first_bit(prec->this_pass.unproven_insns, env->prog->len);
	helped = partition_helped(env);
	for (i = 0; i < prec->loop_cnt; i++) {
		loop = prec->loops[i];
		if (loop->partitioned && !helped &&
		    (!bpf_loop_has_budget(loop) || loop->this_pass.starves)) {
			undo_loop(prec, loop);
			undone = true;
			continue;
		}
		/* the next PARTITION_PEEL_MORE sets no_peel_prune */
		if (loop->partitioned && loop->this_pass.peeled_cnt < loop->max_peel_cnt &&
		    !(prec->partitioned_by == BIT(PARTITION_PEEL_MORE) &&
		      loop->this_pass.peel_pruned))
			loop->tried |= prec->partitioned_by;
		if (loop->max_peel_cnt && bpf_loop_has_budget(loop)) {
			loop->peel_cnt = max(loop->peel_cnt, loop->this_pass.peeled_cnt);
			loop->max_peel_cnt = 0;
			if (!loop->peeled_apart && !loop->disjoint_apart)
				loop->budget = 0;
		}
		loop->last_pass = loop->this_pass;
	}
	/* what this pass found is not valid after the undo */
	if (undone)
		return partition_next(env);
	if (!prec->this_pass.over_budget)
		prec->pass_cost = max(prec->pass_cost, env->cost - prec->start_cost);
	if (prec->partitioned_by <= BIT(PARTITION_ADD_DEPS))
		prec->budget = max(prec->budget, bpf_precision_first_budget(env));
	swap(prec->this_pass, prec->last_pass);
	/* only the unproven insns of this pass: no check failed at the other ones */
	bitmap_or(prec->last_unproven_insns, prec->last_pass.unproven_insns,
		  prec->last_pass.bad_read_insns, env->prog->len);
	bitmap_and(prec->err_insns, prec->err_insns, prec->last_unproven_insns, env->prog->len);
	bitmap_copy(prec->last_unproven_insns, prec->last_pass.unproven_insns, env->prog->len);
	if (helped)
		keep_precision(prec, true);
	prec->failing_path_due |= helped;
	prec->first_unproven_insn = env->err_insn;
	return find_calls_to_unproven(env) ?: partition_next(env);
}

void bpf_precision_new_pass(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	bitmap_zero(prec->this_pass.unproven_insns, env->prog->len);
	bitmap_zero(prec->this_pass.bad_read_insns, env->prog->len);
	bitmap_zero(prec->this_pass.call_insns, env->prog->len);
	bitmap_zero(prec->this_pass.unproven_funcs, env->subprog_cnt);
	prec->this_pass.suspect_loops = prec->this_pass.first_suspect_loops =
		prec->this_pass.disjoint_joined = prec->this_pass.arg_lost_equation = 0;
	if (prec->apart_xregno)
		memset(prec->apart_xregno, 0, env->prog->len * sizeof(u16));
	if (prec->data_deps && !env->replay && (prec->budget_grew || env->for_log)) {
		keep_precision(prec, false);
		prec->partitioned_by = prec->pass_cost = 0;
	}
	prec->budget_grew = prec->new_nospec = false;
	prec->start_cost = env->cost;
	prec->last_unproven_left = bitmap_weight(prec->last_unproven_insns, env->prog->len);
	/* ADD_DEPS has no alternative, so it has no limit of its own */
	if (prec->partitioned_by > BIT(PARTITION_ADD_DEPS) && !env->replay)
		env->pass_max_cost = bpf_pass_max_cost(env);
}

static int add_loop(struct bpf_precision *prec, struct bpf_loop *loop)
{
	struct bpf_loop **loops = prec->loops;

	if (!loop || loop->suspect_bit)
		return 0;
	if (is_power_of_2(prec->loop_cnt + 1)) {
		loops = kvrealloc(loops, 2 * (prec->loop_cnt + 1) * sizeof(*loops),
				  BPF_VERIFIER_GFP);
		if (!loops)
			return -ENOMEM;
		prec->loops = loops;
	}
	loop->suspect_bit = BIT_ULL(prec->loop_cnt % 64);
	loops[prec->loop_cnt++] = loop;
	return 0;
}

int bpf_precision_init(struct bpf_verifier_env *env)
{
	struct bpf_insn_aux_data *aux = env->insn_aux_data;
	u32 words = BITS_TO_LONGS(env->prog->len), i;
	struct bpf_precision *prec;
	unsigned long *bits;
	int err = 0;

	prec = env->precision = kvzalloc(sizeof(*prec) + 20 * words * sizeof(long),
					 BPF_VERIFIER_GFP);
	if (!prec)
		return -ENOMEM;
	bits = (void *)(prec + 1);
	prec->this_pass.unproven_insns = bits;
	prec->this_pass.call_insns = bits + words;
	prec->this_pass.bad_read_insns = bits + 2 * words;
	prec->last_pass.unproven_insns = bits + 3 * words;
	prec->last_pass.call_insns = bits + 4 * words;
	prec->last_pass.bad_read_insns = bits + 5 * words;
	prec->held_insns = bits + 6 * words;
	prec->err_insns = bits + 7 * words;
	prec->earlier_unproven_insns = bits + 8 * words;
	prec->control_seeds = bits + 9 * words;
	prec->controlled_insns = bits + 10 * words;
	prec->bad_read_insns_done = bits + 11 * words;
	prec->controlled_insns_done = bits + 12 * words;
	prec->def_insns = bits + 13 * words;
	prec->last_unproven_insns = bits + 14 * words;
	prec->bad_value_insns = bits + 15 * words;
	prec->this_pass.unproven_funcs = bits + 16 * words;
	prec->last_pass.unproven_funcs = bits + 17 * words;
	prec->pass_cost = env->cost;
	prec->budget_left = prec->budget = bpf_precision_first_budget(env);
	prec->first_unproven_insn = prec->loop_carried_at = U32_MAX;
	for (i = 0; i < env->prog->len && !err; i++, aux++)
		err = add_loop(prec, aux->loop) ?: add_loop(prec, aux->callback_loop) ?:
		      add_loop(prec, aux->recursion_loop);
	return err;
}

void bpf_precision_free(struct bpf_verifier_env *env)
{
	struct bpf_precision *prec = env->precision;

	if (!prec)
		return;
	kvfree(prec->func);
	kvfree(prec->loops);
	kvfree(prec->hops_to_err);
	kvfree(prec->seen);
	kvfree(prec->data_deps);
	kvfree(prec);
	env->precision = NULL;
}
