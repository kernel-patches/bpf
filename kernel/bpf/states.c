// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/cnum.h>
#include <linux/filter.h>

/* check %cur's range satisfies %old's */
static bool range_within(const struct bpf_reg_state *old,
			 const struct bpf_reg_state *cur)
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
			 * saved spilled_ptr metadata so partial fills keep
			 * rejecting as non-scalar register fills.
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
	return 0;
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
		      struct bpf_func_state *cur, struct bpf_idmap *idmap)
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

		spi = i / BPF_REG_SIZE;
		old_slot = bpf_stack_slot(old, spi);
		old_type = old_slot->slot_type[im];
		cur_slot = i < cur->allocated_stack ? bpf_stack_slot(cur, spi) : NULL;

		if (old_type == STACK_INVALID || old_type == STACK_POISON)
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
				if (!regsafe(env, old_reg, cur_reg, idmap))
					return false;
				i += (im == 0 ? BPF_REG_SIZE - 1 : 3);
				continue;
			}
		}

		/* if old state was safe with misc data in the stack
		 * it will be safe with zero-initialized stack.
		 * The opposite is not true
		 */
		if (old_type == STACK_MISC && cur_slot->slot_type[im] == STACK_ZERO)
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
			if (!regsafe(env, &old_slot->spilled_ptr, &cur_slot->spilled_ptr, idmap))
				return false;
			break;
		case STACK_DYNPTR:
			old_reg = &old_slot->spilled_ptr;
			cur_reg = &cur_slot->spilled_ptr;
			if (old_reg->dynptr.type != cur_reg->dynptr.type ||
			    old_reg->dynptr.first_slot != cur_reg->dynptr.first_slot ||
			    !check_ids(old_reg->id, cur_reg->id, idmap) ||
			    !check_ids(old_reg->parent_id, cur_reg->parent_id, idmap))
				return false;
			break;
		case STACK_ITER:
			old_reg = &old_slot->spilled_ptr;
			cur_reg = &cur_slot->spilled_ptr;
			if (old_reg->type != cur_reg->type ||
			    old_reg->iter.btf != cur_reg->iter.btf ||
			    old_reg->iter.btf_id != cur_reg->iter.btf_id ||
			    old_reg->iter.state != cur_reg->iter.state ||
			    old_reg->iter.loops != cur_reg->iter.loops ||
			    !check_ids(old_reg->id, cur_reg->id, idmap))
				return false;
			break;
		case STACK_IRQ_FLAG:
			old_reg = &old_slot->spilled_ptr;
			cur_reg = &cur_slot->spilled_ptr;
			if (!check_ids(old_reg->id, cur_reg->id, idmap) ||
			    old_reg->irq.kfunc_class != cur_reg->irq.kfunc_class)
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

	if (old->callback_depth > cur->callback_depth)
		return false;

	if (!old->no_stack_arg_load && cur->no_stack_arg_load)
		return false;

	if (memcmp(&old->callback_ret_range, &cur->callback_ret_range,
		   sizeof(old->callback_ret_range)))
		return false;

	if (old->in_rcu_callback_fn != cur->in_rcu_callback_fn)
		return false;

	/* what the frame did to what its callers hold is a part of what it tells them */
	if (old->entry_refs != cur->entry_refs ||
	    old->entry_rcu_locks != cur->entry_rcu_locks ||
	    old->entry_preempt_locks != cur->entry_preempt_locks)
		return false;

	if (!check_ids(old->frame_id, cur->frame_id, &env->idmap_scratch))
		return false;

	for (i = 0; i < MAX_BPF_REG; i++)
		if (((1 << i) & live_regs) &&
		    !regsafe(env, &old->regs[i], &cur->regs[i], &env->idmap_scratch))
			return false;

	if (!stacksafe(env, old, cur, &env->idmap_scratch))
		return false;

	if (!stack_arg_safe(env, old, cur, &env->idmap_scratch))
		return false;

	if (!loop_stack_safe(env, old, cur))
		return false;

	return true;
}

/* Everything that @cur describes is described by @old. */
bool bpf_state_subsumes(struct bpf_verifier_env *env, struct bpf_verifier_state *old,
			struct bpf_verifier_state *cur)
{
	u32 insn_idx;
	int i;

	if (old->curframe != cur->curframe)
		return false;

	reset_idmap_scratch(env);

	/* Verification state from speculative execution simulation
	 * must never stand for a non-speculative execution one.
	 */
	if (old->speculative && !cur->speculative)
		return false;

	if (old->callers_unknown != cur->callers_unknown)
		return false;

	if (old->in_sleepable != cur->in_sleepable)
		return false;

	if (old->unwound != cur->unwound || old->changed_pkt_data != cur->changed_pkt_data)
		return false;

	if (!refsafe(old, cur, &env->idmap_scratch))
		return false;

	/* for states to be equal callsites have to be the same
	 * and all frame states need to be equivalent
	 */
	for (i = 0; i <= old->curframe; i++) {
		insn_idx = bpf_frame_insn_idx(old, i);
		if (old->frame[i]->callsite != cur->frame[i]->callsite)
			return false;
		if (!func_states_equal(env, old->frame[i], cur->frame[i], insn_idx))
			return false;
	}

	return true;
}
