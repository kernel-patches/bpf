// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/cnum.h>
#include <linux/filter.h>
#include <linux/siphash.h>

/* check %cur's range satisfies %old's */
static bool range_within(const struct scalar *old, const struct scalar *cur)
{
	if (!cnum64_is_subset(old->r64, cur->r64) ||
	    !cnum32_is_subset(old->r32, cur->r32))
		return false;

	if (old->step <= 1)
		return true;

	if (cnum64_is_const(cur->r64))
		return imod((s64)cnum64_smin(cur->r64), old->step) == old->base;

	/*
	 * Both `old` and `cur` define some sets of points.
	 * Return true, if points defined by `cur` are a subset of points defined by `old`:
	 * - bounds for `cur` should be within bounds for `old`;
	 * - cur->step should be dividable by old->step;
	 * - cur->base should start at integer number of old->step
	 *   steps from old->base.
	 *
	 * E.g. the following ranges are compatible:
	 * - old [0, 10] step 2
	 * - new [2, 10] step 4
	 */
	return cur->step % old->step == 0 &&
	       (cur->base - old->base) % old->step == 0;
}

bool scalar_subsumes(const struct scalar *old, const struct scalar *cur)
{
	return range_within(old, cur) && tnum_in(old->var_off, cur->var_off);
}

bool bpf_scalar_subsumes(const struct bpf_reg_state *old, const struct bpf_reg_state *cur)
{
	return scalar_subsumes(scalar_of(old), scalar_of(cur));
}

static void renumber_id(struct bpf_verifier_env *env, u32 *id, u32 new_id)
{
	struct bpf_idmap *map = &env->idmap_scratch;
	u32 i;

	if (!*id)
		return;
	for (i = 0; i < map->cnt && map->map[i].old != *id; i++)
		;
	bpf_add_cost(env, 2 * i, BPF_COST_SCAN);
	if (i == BPF_ID_MAP_SIZE)
		return;
	if (i == map->cnt)
		map->map[map->cnt++] = (struct bpf_id_pair){ *id, new_id };
	*id = map->map[i].cur;
}

static void renumber_reg_ids(struct bpf_verifier_env *env, struct bpf_reg_state *reg, u32 xreg)
{
	renumber_id(env, &reg->id, BPF_XREG_ID(3 * xreg));
	renumber_id(env, &reg->parent_id, BPF_XREG_ID(3 * xreg + 1));
	renumber_id(env, &reg->map_uid, BPF_XREG_ID(3 * xreg + 2));
}

/*
 * An id stands for the set of xregs that have it. Name it after the first one. What is held goes
 * first. Then states with the same sets have the same ids, and ids are compared as they are.
 * The name is the xreg, not a number in a sequence. So an xreg that is not set does not change
 * the names of other sets. But if only one state has r1 = r6, r6 has two names.
 * Visit an xreg once: a name can be the old id of another xreg.
 */
int bpf_renumber_ids(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	u32 mask[] = { BIT(STACK_SPILL),
		       BIT(STACK_DYNPTR) | BIT(STACK_ITER) | BIT(STACK_IRQ_FLAG) };
	struct bpf_idmap *map = &env->idmap_scratch;
	struct bpf_reg_state *reg;
	struct bpf_func_state *f;
	u32 fr, i, xreg;
	int held;

	map->cnt = 0;
	for (i = 0; i < st->acquired_refs && i < BPF_ID_MAP_SIZE; i++) {
		renumber_id(env, &st->refs[i].id, BPF_REF_ID(2 * i));
		if (st->refs[i].type == REF_TYPE_PTR)
			renumber_id(env, &st->refs[i].parent_id, BPF_REF_ID(2 * i + 1));
	}
	/* they are among these */
	renumber_id(env, &st->active_irq_id, 0);
	renumber_id(env, &st->active_lock_id, 0);
	for (held = 1; held >= 0; held--) {
		for (fr = 0; fr <= st->curframe; fr++) {
			f = st->frame[fr];
			/* registers, the frame, slots, arguments */
			xreg = fr * (BPF_ID_MAP_SIZE / MAX_CALL_FRAMES + 1) + MAX_BPF_REG;
			if (held)
				renumber_id(env, &f->frame_id, BPF_XREG_ID(3 * xreg));
			for (i = 0; i < bpf_stack_nr_slots(f); i++) {
				reg = bpf_get_spilled_reg(i, f, mask[held]);
				if (reg)
					renumber_reg_ids(env, reg, xreg + 1 + i);
			}
			if (held)
				continue;
			for (i = 0; i < MAX_BPF_REG; i++)
				renumber_reg_ids(env, &f->regs[i], xreg - MAX_BPF_REG + i);
			for (i = 0; i < f->out_stack_arg_cnt; i++)
				renumber_reg_ids(env, &f->stack_arg_regs[i],
						 xreg + 1 + MAX_BPF_STACK_SLOTS + i);
		}
	}
	if (map->cnt < BPF_ID_MAP_SIZE && st->acquired_refs < BPF_ID_MAP_SIZE)
		return 0;
	bpf_log(&env->log, "too many ids\n");
	return -E2BIG;
}

bool bpf_add_pkt_pair(struct bpf_verifier_env *env, const struct bpf_pkt_pair *pair)
{
	if (!bpf_grow_array(env, &env->pkt_pairs, &env->pkt_pair_cap, env->pkt_pair_cnt + 1,
			    sizeof(*pair)))
		return false;
	env->pkt_pairs[env->pkt_pair_cnt++] = *pair;
	return true;
}

/* Packet pointers that share an id in the old state share one in the new state, as far apart */
static bool check_pkt_ids(struct bpf_verifier_env *env, const struct bpf_reg_state *rold,
			  const struct bpf_reg_state *rcur)
{
	struct bpf_pkt_pair pair = { rold->id, rcur->id, rcur->r64.base - rold->r64.base };
	const struct bpf_pkt_pair *p = env->pkt_pairs;

	if (!rold->id)
		return !rcur->id;
	bpf_add_cost(env, env->pkt_pair_cnt, BPF_COST_SCAN);
	for (; p < env->pkt_pairs + env->pkt_pair_cnt; p++)
		if (p->old == pair.old)
			return p->cur == pair.cur && p->delta == pair.delta;
	return bpf_add_pkt_pair(env, &pair);
}

/*
 * The bytes that are checked for @rold are checked for @rcur. This matters even if the range
 * is below the offset: the program can move the pointer back.
 */
static bool pkt_range_safe(const struct bpf_reg_state *rold, const struct bpf_reg_state *rcur)
{
	if (pkt_min_len(rold) > pkt_min_len(rcur))
		return false;
	/* the range tells no more than pkt_min_len() */
	if (!rold->range || rold->range == pkt_min_len(rold))
		return true;
	/* AT_PKT_END or BEYOND_PKT_END */
	if (rold->range < 0 || rcur->range < 0)
		return rold->range == rcur->range;
	if (pkt_has_bytes_left(rold) && pkt_has_bytes_left(rcur))
		return pkt_bytes_left(rold) <= pkt_bytes_left(rcur);
	return rold->range <= rcur->range && rold->r64.base == rcur->r64.base &&
	       rold->r64.size == rcur->r64.size;
}

static void __clean_func_state(struct bpf_verifier_env *env,
			       struct bpf_func_state *st,
			       u16 live_regs, int frame)
{
	int i, j;

	for (i = 0; i < BPF_REG_FP; i++) {
		/* liveness must not touch this register anymore */
		if (!(live_regs & BIT(i)))
			/* since the register is unused, clear its state
			 * to make further comparison simpler
			 */
			bpf_mark_reg_not_init(env, &st->regs[i]);
	}

	/*
	 * Clean dead 4-byte halves within each SPI independently.
	 * half_spi 2*i   → lower half: slot_type[0..3] (closer to FP)
	 * half_spi 2*i+1 → upper half: slot_type[4..7] (farther from FP)
	 */
	for (i = 0; i < bpf_stack_nr_slots(st); i++) {
		bool lo_live = bpf_stack_slot_alive(env, frame, i * 2);
		bool hi_live = bpf_stack_slot_alive(env, frame, i * 2 + 1);
		struct bpf_stack_state *slot = bpf_stack_slot(st, i);

		/*
		 * Nothing ahead gets the pointer back into a register. What reads the slot sees
		 * unknown bytes, whatever the pointer is.
		 */
		if (env->allow_ptr_leaks && bpf_is_spilled_reg(slot) &&
		    slot->spilled_ptr.type != SCALAR_VALUE &&
		    !bpf_stack_slot_filled(env, frame, i * 2) &&
		    !bpf_stack_slot_filled(env, frame, i * 2 + 1)) {
			bpf_mark_reg_not_init(env, &slot->spilled_ptr);
			memset(slot->slot_type, STACK_MISC, sizeof(slot->slot_type));
		}

		if (!hi_live || !lo_live) {
			int start = !lo_live ? 0 : BPF_REG_SIZE / 2;
			int end = !hi_live ? BPF_REG_SIZE : BPF_REG_SIZE / 2;
			u8 stype = bpf_stack_slot(st, i)->slot_type[7];

			/*
			 * Don't clear special slots.
			 * destroy_if_dynptr_stack_slot() needs STACK_DYNPTR to
			 * detect overwrites and invalidate associated data slices.
			 * is_iter_reg_valid_uninit() and is_irq_flag_reg_valid_uninit()
			 * check for their respective slot types to detect double-create.
			 */
			if (stype == STACK_DYNPTR || stype == STACK_ITER ||
			    stype == STACK_IRQ_FLAG)
				continue;

			/*
			 * When the half-slot closer to FP is dead, what remains of a
			 * 64-bit spill looks like a 32-bit spill: the low 32 bits of
			 * the value. On big endian the other half-slot holds the upper
			 * 32 bits.
			 */
			if (hi_live && bpf_spill_size(bpf_stack_slot(st, i)) == BPF_REG_SIZE &&
			    !bpf_stack_narrow_access_ok(0, BPF_REG_SIZE / 2, BPF_REG_SIZE))
				continue;

			/*
			 * Only scalar spills can be degraded to raw stack bytes
			 * when their high half is dead. Pointer spills need the
			 * saved spilled_ptr metadata: without allow_ptr_leaks
			 * a partial fill is rejected.
			 * The code above replaces only pointers that no insn ahead can fill.
			 */
			if (!hi_live) {
				struct bpf_reg_state *spill = &bpf_stack_slot(st, i)->spilled_ptr;

				if (lo_live && stype == STACK_SPILL) {
					if (spill->type != SCALAR_VALUE)
						continue;
					/* keep what is known about the low half */
					if (bpf_register_is_null(spill))
						continue;
					for (j = 0; j < 4; j++) {
						u8 *t = &bpf_stack_slot(st, i)->slot_type[j];

						if (*t == STACK_SPILL)
							*t = STACK_MISC;
					}
				}
				bpf_mark_reg_not_init(env, spill);
			}
			for (j = start; j < end; j++)
				bpf_stack_slot(st, i)->slot_type[j] = STACK_POISON;
		}
	}
}

int bpf_clean_verifier_state(struct bpf_verifier_env *env, struct bpf_verifier_state *st)
{
	int i, err;

	bpf_add_cost(env, bpf_xreg_cnt(st), BPF_COST_XREG);
	err = bpf_live_stack_query_init(env, st);
	if (err)
		return err;
	for (i = 0; i <= st->curframe; i++) {
		u32 ip = bpf_frame_insn_idx(st, i);
		u16 live_regs = env->insn_aux_data[ip].live_regs_before;

		__clean_func_state(env, st->frame[i], live_regs, i);
	}
	bpf_equations_clean(env, st);
	return bpf_renumber_ids(env, st);
}

/*
 * Values of one type and object differ only in a number: the value of a scalar, the offset
 * of a pointer.
 *
 * Types have to match exactly, including their modifiers (like PTR_MAYBE_NULL, MEM_RDONLY, etc).
 * A pointer is not a number: numbers are allowed to leak while pointers are not. A pointer is
 * not its MAYBE_NULL variant: a NULL check changes all xregs with the same id.
 */
bool bpf_same_type_and_object(struct bpf_verifier_env *env, const struct bpf_reg_state *a,
			      const struct bpf_reg_state *b)
{
	if (a->type != b->type)
		return false;
	if (a->type == SCALAR_VALUE || a->type == NOT_INIT || type_is_pkt_pointer(a->type) ||
	    base_type(a->type) == PTR_TO_ARENA)
		return true;
	if (!reg_object_equal(a, b))
		return false;
	/* Only what an insn can make: see check_stack_access_for_ptr_arithmetic() */
	if (bpf_reg_has_range(a) && (a->type != PTR_TO_STACK || env->bypass_spec_v1))
		return true;
	return scalar_equal(scalar_of(a), scalar_of(b));
}

/* Returns true if (rold safe implies rcur safe) */
static bool regsafe(struct bpf_verifier_env *env, const struct bpf_reg_state *rold,
		    const struct bpf_reg_state *rcur)
{
	bpf_add_cost(env, 1, BPF_COST_XREG);
	if (rold->type == NOT_INIT)
		/* nothing can be done with it */
		return true;
	if (!rcur || !bpf_same_type_and_object(env, rold, rcur))
		return false;
	/* The offset is not tracked. */
	if (base_type(rold->type) == PTR_TO_ARENA)
		return true;
	if (type_is_pkt_pointer(rold->type) &&
	    (!pkt_range_safe(rold, rcur) || !check_pkt_ids(env, rold, rcur)))
		return false;
	/* new val must satisfy old val knowledge */
	return bpf_scalar_subsumes(rold, rcur);
}

static struct bpf_reg_state unbound_reg;

static __init int unbound_reg_init(void)
{
	bpf_mark_reg_unknown(&unbound_reg);
	return 0;
}
late_initcall(unbound_reg_init);

static bool is_spilled_scalar_after(const struct bpf_stack_state *stack, int im)
{
	return stack->slot_type[im] == STACK_SPILL &&
	       stack->spilled_ptr.type == SCALAR_VALUE;
}

static bool is_stack_misc_after(struct bpf_verifier_env *env,
				struct bpf_stack_state *stack, int im)
{
	u32 i;

	for (i = im; i < ARRAY_SIZE(stack->slot_type); ++i) {
		if ((stack->slot_type[i] == STACK_MISC) ||
		    ((stack->slot_type[i] == STACK_INVALID || stack->slot_type[i] == STACK_POISON) &&
		     env->allow_uninit_stack))
			continue;
		return false;
	}

	return true;
}

static struct bpf_reg_state *scalar_reg_for_stack(struct bpf_verifier_env *env,
						  struct bpf_stack_state *stack, int im)
{
	if (is_spilled_scalar_after(stack, im))
		return &stack->spilled_ptr;

	if (is_stack_misc_after(env, stack, im))
		return &unbound_reg;

	return NULL;
}

static bool stacksafe(struct bpf_verifier_env *env, struct bpf_func_state *old,
		      struct bpf_func_state *cur)
{
	int i, spi;

	/*
	 * walk slots of the old stack and ignore any additional
	 * slots in the current stack, since the old state
	 * can't use them
	 */
	for (i = 0; i < old->allocated_stack; i++) {
		struct bpf_stack_state *old_slot, *cur_slot;
		struct bpf_reg_state *old_reg, *cur_reg;
		int im = i % BPF_REG_SIZE;
		u8 old_type;

		bpf_add_cost(env, 1, BPF_COST_SCAN);
		spi = i / BPF_REG_SIZE;
		old_slot = bpf_stack_slot(old, spi);
		old_type = old_slot->slot_type[im];
		cur_slot = i < cur->allocated_stack ? bpf_stack_slot(cur, spi) : NULL;

		if (old_type == STACK_INVALID || old_type == STACK_POISON)
			continue;

		/* it can be filled into a register that is unreadable */
		if (old_type == STACK_SPILL && old_slot->spilled_ptr.type == NOT_INIT &&
		    (env->allow_uninit_stack ||
		     (cur_slot && cur_slot->slot_type[im] != STACK_INVALID &&
		      cur_slot->slot_type[im] != STACK_POISON)))
			continue;

		if (env->allow_uninit_stack && old_type == STACK_MISC)
			continue;

		/* old stack has more populated slots than current stack */
		if (!cur_slot)
			return false;

		/*
		 * The old spill is the first bytes of a wider spill. On big endian
		 * these are not the low bytes of the value.
		 */
		if (old_type == STACK_SPILL && bpf_is_spilled_reg(cur_slot) &&
		    !bpf_stack_narrow_access_ok(0, bpf_spill_size(old_slot),
						bpf_spill_size(cur_slot)))
			return false;

		/*
		 * 64 and 32-bit scalar spills vs MISC/INVALID slots and vice versa.
		 * Load from MISC/INVALID slots produces unbound scalar.
		 * Construct a fake register for such stack and call regsafe().
		 */
		if (im == 0 || im == 4) {
			old_reg = scalar_reg_for_stack(env, old_slot, im);
			cur_reg = scalar_reg_for_stack(env, cur_slot, im);
			if (old_reg && cur_reg) {
				if (!regsafe(env, old_reg, cur_reg))
					return false;
				i += (im == 0 ? BPF_REG_SIZE - 1 : 3);
				continue;
			}
		}

		/* if old state was safe with misc data in the stack
		 * it will be safe with zero-initialized stack.
		 * The opposite is not true
		 */
		if (old_type == STACK_MISC &&
		    (cur_slot->slot_type[im] == STACK_ZERO ||
		     is_spilled_scalar_after(cur_slot, im)))
			continue;
		if (old_type == STACK_ZERO && is_spilled_scalar_after(cur_slot, im) &&
		    bpf_register_is_null(&cur_slot->spilled_ptr))
			continue;
		if (old_type != cur_slot->slot_type[im])
			/*
			 * Ex: old state has STACK_SPILL in
			 * this stack slot, but current has STACK_MISC ->
			 * this verifier states are not equivalent
			 */
			return false;
		if (im != BPF_REG_SIZE - 1)
			continue;
		/* Both old and cur are having same slot_type */
		switch (old_type) {
		case STACK_SPILL:
			/*
			 * when old and current stack slot are both storing
			 * spilled registers, check that stored pointers types
			 * are the same as well.
			 * Ex: old state could have stored
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -8}
			 * but current state has stored:
			 * (bpf_reg_state) {.type = PTR_TO_STACK, .off = -16}
			 * such verifier states are not equivalent.
			 */
			if (!regsafe(env, &old_slot->spilled_ptr, &cur_slot->spilled_ptr))
				return false;
			break;
		case STACK_DYNPTR:
		case STACK_ITER:
		case STACK_IRQ_FLAG:
			if (!reg_object_equal(&old_slot->spilled_ptr, &cur_slot->spilled_ptr))
				return false;
			break;
		case STACK_MISC:
		case STACK_ZERO:
		case STACK_INVALID:
		case STACK_POISON:
			continue;
		/* Ensure that new unhandled slot types return false by default */
		default:
			return false;
		}
	}
	return true;
}

static const struct bpf_stack_state *held_slot(const struct bpf_func_state *f, u32 i)
{
	return i < bpf_stack_nr_slots(f) && bpf_slot_is_held(bpf_stack_slot(f, i)) ?
	       bpf_stack_slot(f, i) : NULL;
}

static bool same_refs(const struct bpf_verifier_state *a, const struct bpf_verifier_state *b)
{
	u32 i;

	for (i = 0; i < a->acquired_refs; i++)
		if (a->refs[i].type != b->refs[i].type || a->refs[i].id != b->refs[i].id ||
		    memcmp(&a->refs[i].ptr, &b->refs[i].ptr, sizeof(u64)))
			return false;
	return true;
}

/*
 * The join_key of a state is what has no join:
 * - what is held: references, locks, dynptrs, iterators, irq flags
 * - the call chain and the instance
 * - the peeled trip
 */
bool bpf_same_join_key(const struct bpf_verifier_state *a, const struct bpf_verifier_state *b)
{
	const struct bpf_stack_state *sa, *sb;
	const struct loop_stack_entry *ea, *eb;
	const struct bpf_func_state *fa, *fb;
	u32 fr, i;

	if (memcmp(&a->join_key, &b->join_key, sizeof(a->join_key)) ||
	    a->instance_id != b->instance_id || !same_refs(a, b))
		return false;
	for (fr = 0; fr <= a->curframe; fr++) {
		fa = a->frame[fr];
		fb = b->frame[fr];
		if (memcmp(&fa->join_key, &fb->join_key, sizeof(fa->join_key)) ||
		    fa->loop_stack_cnt != fb->loop_stack_cnt)
			return false;
		for (i = 0; i < fa->loop_stack_cnt; i++) {
			ea = &fa->loop_stack[i];
			eb = &fb->loop_stack[i];
			if (ea->loop != eb->loop || ea->peeled != eb->peeled ||
			    (ea->peeled && ea->trip != eb->trip))
				return false;
		}
		for (i = 0; i < max(bpf_stack_nr_slots(fa), bpf_stack_nr_slots(fb)); i++) {
			sa = held_slot(fa, i);
			sb = held_slot(fb, i);
			if (!sa != !sb || (sa && (sa->slot_type[0] != sb->slot_type[0] ||
						  !reg_object_equal(&sa->spilled_ptr,
								    &sb->spilled_ptr))))
				return false;
		}
	}
	return true;
}

u64 bpf_hash64(const void *p, size_t len, u64 hash)
{
	siphash_key_t key = {{ hash }};

	return siphash(p, len, &key);
}

/*
 * The hash of the join_key and of the insn. The seed is random, so a program cannot select
 * states that collide. Only a collision can change a result.
 */
u64 bpf_hash_join_key(const struct bpf_verifier_env *env, const struct bpf_verifier_state *st)
{
	u64 hash = bpf_hash64(&st->join_key, sizeof(st->join_key), env->hash_seed +
			      ((u64)st->instance_id << 32 | st->insn_idx));
	u32 fr, i, trip;
	const struct bpf_stack_state *slot;
	const struct loop_stack_entry *e;
	const struct bpf_func_state *f;

	for (i = 0; i < st->acquired_refs; i++)
		hash = bpf_hash64(&st->refs[i].ptr, sizeof(u64), hash + st->refs[i].type);
	for (fr = 0; fr <= st->curframe; fr++) {
		f = st->frame[fr];
		hash = bpf_hash64(&f->join_key, sizeof(f->join_key), hash);
		for (i = 0, e = f->loop_stack; i < f->loop_stack_cnt; i++, e++) {
			trip = e->peeled ? e->trip : -1;
			hash = bpf_hash64(&trip, sizeof(trip), hash);
		}
		for (i = 0; i < bpf_stack_nr_slots(f); i++) {
			slot = held_slot(f, i);
			if (!slot)
				continue;
			hash = bpf_hash64(&slot->spilled_ptr,
					  offsetof(struct bpf_reg_state, var_off), hash + i);
		}
	}
	return hash;
}

/*
 * If may_goto or an iterator stops the loop, its trip index can start again from a smaller
 * number, never from a larger one: see bpf_equations_next_trip().
 */
static bool trip_index_safe(const struct loop_stack_entry *old, const struct loop_stack_entry *cur)
{
	u64 min = cnum64_umin(old->trip_index.r64);
	struct scalar first;

	if (old->peeled || scalar_subsumes(&old->trip_index, &cur->trip_index))
		return true;
	if (!old->loop->rt_bounded && !old->loop->this_pass.needs_guard)
		return false;
	scalar_set_const(&first, min);
	return min <= cnum64_umin(cur->trip_index.r64) &&
	       scalar_subsumes(&old->trip_index, &first);
}

static bool loop_stack_safe(struct bpf_func_state *old, struct bpf_func_state *cur)
{
	u32 i;

	for (i = 0; i < old->loop_stack_cnt; i++)
		if (!trip_index_safe(&old->loop_stack[i], &cur->loop_stack[i]))
			return false;
	return true;
}

/* compare two verifier states
 *
 * The state that gets to an insn doesn't have to be looked at when there is
 * a state at that insn that is more conservative in registers and in the
 * stack: if the program is fine with the old state it's fine with the current
 * one.
 * Example:
 *          old                     current
 * (slot1=INV slot2=MISC) == (slot1=MISC slot2=MISC)
 * (slot1=MISC slot2=MISC) != (slot1=INV slot2=MISC)
 *
 * Similarly with registers: the type in the old state is invalid whereas
 * the type in the current state is meaningful.
 */
static bool func_states_equal(struct bpf_verifier_env *env, struct bpf_func_state *old,
			      struct bpf_func_state *cur, u32 insn_idx)
{
	u16 live_regs = env->insn_aux_data[insn_idx].live_regs_before;
	u16 i;

	if (old->callback_depth > cur->callback_depth ||
	    (!old->no_stack_arg_load && cur->no_stack_arg_load) ||
	    !loop_stack_safe(old, cur))
		return false;

	for (i = 0; i < MAX_BPF_REG; i++)
		if ((live_regs & BIT(i)) && !regsafe(env, &old->regs[i], &cur->regs[i]))
			return false;

	/* outgoing stack args are a part of the state and must agree */
	for (i = 0; i < old->out_stack_arg_cnt; i++)
		if (!regsafe(env, &old->stack_arg_regs[i], bpf_stack_arg(cur, old, i)))
			return false;

	return stacksafe(env, old, cur);
}

/* @old describes all that @cur describes. They have the same join_key. */
bool bpf_state_subsumes(struct bpf_verifier_env *env, const struct bpf_verifier_state *old,
			const struct bpf_verifier_state *cur)
{
	int i;

	env->pkt_pair_cnt = 0;

	/* Verification state from speculative execution simulation
	 * must never stand for a non-speculative execution one.
	 */
	if (old->speculative && !cur->speculative)
		return false;

	for (i = 0; i <= old->curframe; i++)
		if (!func_states_equal(env, old->frame[i], cur->frame[i],
				       bpf_frame_insn_idx(old, i)))
			return false;

	return bpf_equations_subsume(env, old, cur);
}
