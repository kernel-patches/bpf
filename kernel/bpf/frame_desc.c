// SPDX-License-Identifier: GPL-2.0-only
/*
 * Frame descriptors: where the frames of a program that may throw keep the
 * handles of the kernel resources they hold, for bpf_throw() to release, see
 * unwind.c.
 *
 * A frame is unwound at a site: the call it has not returned from,
 * bpf_throw() or the call of a subprog that may throw. The main pass visits a
 * site with every state a frame can be in there, and records what the frame
 * keeps where on each visit: the iterators and saved IRQ flags it holds,
 * which are on its stack, the slots a reference it holds is spilled in and
 * the registers that hold it, and how many RCU read and preemption disabled
 * sections it is in. What every visit finds in the same place goes into the
 * descriptor of the site, and costs the program nothing.
 *
 * The unwinder has the registers of a frame where bpf_throw() has a native
 * entry that captures those of the throw site, see bpf_arch_throw_entry(): R6
 * to R9 of every frame, which are callee-saved and recovered from where the
 * frames above saved them, and R0 to R5 of the frame that throws.
 *
 * What the visits of some site do not agree on is written down when it is
 * acquired, in a hidden stack slot. Nothing is inferred about where the
 * program keeps it. The handle is the pointer a call returns, the address of
 * the lock, the iterator or the saved IRQ flags a call takes, the record or
 * the reader of a dynptr. Every call that acquires such a resource has a slot
 * of its own in the frame that runs it. The handle goes into the slot around
 * the call, and the call that releases the resource clears the slot when it
 * holds the handle the call takes. The sections a frame enters have no handle
 * and are counted in a slot per kind. The slots of a subprog are listed in
 * its own descriptor.
 *
 * What no frame holds at any site needs neither.
 *
 * A slot belongs to one frame and holds one handle, so a program that throws
 * keeps to what that can express:
 *
 *  - A frame releases what it acquired itself. A callee cannot reach the
 *    slot of its caller, so it may not release what its caller holds.
 *  - A frame that returns holds nothing but a reference it returns in R0,
 *    which the call acquires for the caller like the call of a kfunc that
 *    returns one, and is in the sections it was called in.
 *  - A slot holds one handle, so a frame that holds two resources of one
 *    acquiring call at once can have no slot for them.
 *
 * What can have no slot loads when its sites describe it or no throw finds
 * it held, and is refused otherwise.
 *
 * The main pass records every call that acquires or releases, which
 * acquisition a release may be of, and the visits of the sites. What needs a
 * slot is decided after the pass: the slots are reserved, the instructions
 * that keep them emitted and the descriptors built then.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/kallsyms.h>
#include <linux/sort.h>

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/* Intern a resource class; descriptors refer to it by index. */
static int resource_intern(struct bpf_verifier_env *env, const struct bpf_resource *res)
{
	struct bpf_resource *tab;
	u32 i, cnt = env->resource_cnt;

	for (i = 0; i < cnt; i++)
		if (!memcmp(&env->resources[i], res, sizeof(*res)))
			return i;
	if (cnt >= U16_MAX)
		return -E2BIG;
	tab = kvrealloc(env->resources, array_size(cnt + 1, sizeof(*tab)), GFP_KERNEL_ACCOUNT);
	if (!tab)
		return -ENOMEM;
	tab[cnt] = *res;
	env->resources = tab;
	env->resource_cnt = cnt + 1;
	return cnt;
}

/*
 * Resolve the destructor of a referenced kernel object through the BTF
 * destructor registry, and check that the program could have called the
 * matching release kfunc itself: that is the context in which running the
 * destructor is legal. A class interned for the type already has it resolved.
 */
static int resource_registry(struct bpf_verifier_env *env, struct btf *btf, u32 btf_id,
			     struct bpf_resource *res, const char *what, bool report)
{
	const char *name = btf_name_by_offset(btf, btf_type_by_id(btf, btf_id)->name_off);
	struct btf *dtor_btf = btf;
	const struct btf_id_dtor_kfunc *dtor = btf_find_dtor(&dtor_btf, btf_id);
	const struct btf_type *t;
	u32 i, *flags;

	for (i = 0; i < env->resource_cnt; i++) {
		const struct bpf_resource *r = &env->resources[i];

		if (r->kind == res->kind && r->btf == btf && r->btf_id == btf_id) {
			res->dtor = r->dtor;
			res->sleeps = r->sleeps;
			return 0;
		}
	}
	if (!dtor || !(dtor->flags & BPF_DTOR_CLEANUP)) {
		if (report)
			verbose(env, "frame_desc: no cleanup destructor registered for %s %s\n", what,
				name);
		return -EOPNOTSUPP;
	}
	flags = btf_kfunc_flags(dtor_btf, dtor->release_btf_id, env->prog);
	if (!flags || !btf_kfunc_is_allowed(dtor_btf, dtor->release_btf_id, env->prog)) {
		if (report)
			verbose(env, "frame_desc: release kfunc of %s %s is not callable by this program\n",
				what, name);
		return -EOPNOTSUPP;
	}
	res->sleeps = *flags & KF_SLEEPABLE;
	t = btf_type_by_id(dtor_btf, dtor->kfunc_btf_id);
	res->dtor = t ? (void *)kallsyms_lookup_name(btf_name_by_offset(dtor_btf, t->name_off)) :
			NULL;
	if (!res->dtor) {
		if (report)
			verbose(env, "frame_desc: cannot resolve the destructor of %s %s\n", what, name);
		return -EINVAL;
	}
	return 0;
}

static bool helper_ok(struct bpf_verifier_env *env, enum bpf_func_id func_id)
{
	return env->ops->get_func_proto && env->ops->get_func_proto(func_id, env->prog);
}

/*
 * Does @reg point to one of the socket structs of vmlinux BTF? A referenced
 * one is the cast of an acquired socket by a helper such as
 * bpf_skc_to_tcp_sock(), which carries the socket's reference under the
 * struct's type.
 */
static bool reg_is_sock_btf(const struct bpf_reg_state *reg)
{
#ifdef CONFIG_NET
	int i;

	if (!btf_is_vmlinux(reg->btf))
		return false;
	for (i = 0; i < MAX_BTF_SOCK_TYPE; i++)
		if (reg->btf_id == btf_sock_ids[i])
			return true;
#endif
	return false;
}

/*
 * Classify the reference a register holds, @report why it cannot be. A
 * reference of a type that no destructor is registered for, or whose release
 * kfunc the program may not call, has no class: the frames keep no handle of
 * it, and a throw may not be reached while it is held.
 */
static int resource_describe(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			     struct bpf_resource *resp, bool report)
{
	u32 flags = type_flag(reg->type) & ~PTR_MAYBE_NULL;
	struct bpf_resource res;
	int ret;

	memset(&res, 0, sizeof(res));
	switch (base_type(reg->type)) {
	case PTR_TO_BTF_ID:
		if (flags & MEM_ALLOC) {
			if (flags & ~(MEM_ALLOC | MEM_PERCPU))
				goto unsupported;
			res.kind = flags & MEM_PERCPU ? BPF_RESOURCE_PERCPU_OBJ : BPF_RESOURCE_OBJ;
			res.meta = btf_find_struct_meta(reg->btf, reg->btf_id);
			/* where the program may not drop the object, the unwinder may not either */
			if (res.meta && bpf_nmi_unsafe_prog(env) &&
			    btf_record_has_nmi_unsafe_fields(res.meta->record))
				goto unsupported;
			/* the types without fields to destroy are freed alike: one class */
			break;
		}
		if (flags & ~PTR_TRUSTED)
			goto unsupported;
		res.btf = reg->btf;
		res.btf_id = reg->btf_id;
		/* A socket cast to one of its structs is still what bpf_sk_release() takes. */
		if (reg_is_sock_btf(reg) && helper_ok(env, BPF_FUNC_sk_release)) {
			res.kind = BPF_RESOURCE_SOCK;
			break;
		}
		res.kind = BPF_RESOURCE_KPTR;
		ret = resource_registry(env, reg->btf, reg->btf_id, &res, "object", report);
		if (ret)
			return ret;
		break;
	case PTR_TO_SOCKET:
	case PTR_TO_SOCK_COMMON:
	case PTR_TO_TCP_SOCK:
		if (flags || !helper_ok(env, BPF_FUNC_sk_release))
			goto unsupported;
		res.kind = BPF_RESOURCE_SOCK;
		break;
	case PTR_TO_MEM:
		if (flags != MEM_RINGBUF || !helper_ok(env, BPF_FUNC_ringbuf_discard))
			goto unsupported;
		res.kind = BPF_RESOURCE_RINGBUF;
		break;
	default:
		goto unsupported;
	}
	*resp = res;
	return 0;
unsupported:
	if (report)
		verbose(env, "frame_desc: cannot release a reference of type %s\n",
			reg_type_str(env, reg->type));
	return -EOPNOTSUPP;
}

/*
 * The class of the iterator in @reg, the first slot of an iterator. An
 * RCU-protected iterator is destroyed before the sections of its frame end,
 * unless its destructor sleeps: that runs after every section, which is
 * the only place the program could have called it.
 */
static int resource_of_iter(struct bpf_verifier_env *env, const struct bpf_reg_state *reg)
{
	struct bpf_resource res;
	int ret;

	/* nothing may release it once its RCU protection ended */
	if (reg->type & PTR_UNTRUSTED)
		return -EOPNOTSUPP;
	memset(&res, 0, sizeof(res));
	res.kind = BPF_RESOURCE_ITER;
	res.btf = reg->iter.btf;
	res.btf_id = reg->iter.btf_id;
	ret = resource_registry(env, reg->iter.btf, reg->iter.btf_id, &res, "iterator", false);
	if (ret)
		return ret;
	res.rcu = (reg->type & MEM_RCU) && !res.sleeps;
	return resource_intern(env, &res);
}

/*
 * Does @reg point into the object of reference @id, @off bytes in: the node
 * of a list or a tree is popped and pushed that way, and the object it is
 * in is released.
 */
static bool reg_ref_off(const struct bpf_reg_state *reg, int id, s16 *off)
{
#ifdef CONFIG_NET
	/*
	 * bpf_skc_to_mptcp_sock() gives its result the id of the subflow it
	 * was passed, and the result is the socket of the connection.
	 */
	if (base_type(reg->type) == PTR_TO_BTF_ID && btf_is_vmlinux(reg->btf) &&
	    reg->btf_id == btf_sock_ids[BTF_SOCK_TYPE_MPTCP])
		return false;
#endif
	if (reg->type == SCALAR_VALUE || reg->type == NOT_INIT || reg->id != id ||
	    !tnum_is_const(reg->var_off) || reg->var_off.value != (u64)(s16)reg->var_off.value)
		return false;
	*off = reg->var_off.value;
	return true;
}

/*
 * Does @reg, a register of frame @f of @st or one spilled in its stack, point
 * to what the frame holds a reference to? A site names such a place, see
 * ref_locations().
 *
 * The program may have read the pointer for the last time while the frame
 * holds the resource still, at the latest in front of a bpf_throw(), which
 * nothing follows. A state forgets what is dead, see
 * bpf_clean_verifier_state(), and no site could name the place then. So such
 * a place is kept: it stays in the state, and a state stands for another only
 * when both have the same in it. What is dead otherwise is forgotten as it
 * was.
 */
bool bpf_frame_desc_keeps(const struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			  int f, const struct bpf_reg_state *reg)
{
	s16 off;
	int i;

	if (!env->describe_frames || reg->type == NOT_INIT || reg->type == SCALAR_VALUE || !reg->id)
		return false;
	/* a frame above may hold it for now and give it back, see bpf_frame_desc_record_exit() */
	for (i = 0; i < st->acquired_refs; i++)
		if (st->refs[i].frameno >= f && st->refs[i].acq && st->refs[i].id &&
		    reg_ref_off(reg, st->refs[i].id, &off))
			return true;
	return false;
}

/* The registers of frame @f of @st that are kept, see bpf_frame_desc_keeps(). */
u16 bpf_frame_desc_kept_regs(const struct bpf_verifier_env *env, const struct bpf_verifier_state *st,
			     int f)
{
	u16 kept = 0;
	int i;

	if (!env->describe_regs)
		return 0;
	/* the registers a site names: R6 to R9, and all but R1 of the frame that throws */
	for (i = BPF_REG_0; i < BPF_REG_FP; i++) {
		if (i == BPF_REG_1 || (i < BPF_REG_6 && f != st->curframe))
			continue;
		if (bpf_frame_desc_keeps(env, st, f, &st->frame[f]->regs[i]))
			kept |= BIT(i);
	}
	return kept;
}

/*
 * Is @slot the stack object of reference @id: the first slot of an iterator,
 * of a ringbuf dynptr, which tracks the record's reference as its parent,
 * or saved IRQ flags?
 */
static bool stack_slot_is_object(const struct bpf_stack_state *slot, int id)
{
	const struct bpf_reg_state *reg = &slot->spilled_ptr;

	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_DYNPTR:
		return reg->dynptr.first_slot && reg->parent_id == id &&
		       (reg->dynptr.type == BPF_DYNPTR_TYPE_RINGBUF ||
			reg->dynptr.type == BPF_DYNPTR_TYPE_FILE);
	case STACK_ITER:
	case STACK_IRQ_FLAG:
		return reg->id == id;
	default:
		return false;
	}
}

/*
 * The frame and slot of the stack object of reference @ref, if it is one:
 * the object may be in the stack of another frame, created through a
 * pointer to it.
 */
static bool stack_object_find(const struct bpf_verifier_state *st,
			      const struct bpf_reference_state *ref, int *frameno, int *spi)
{
	int f, k;

	for (f = st->curframe; f >= 0; f--) {
		const struct bpf_func_state *frame = st->frame[f];

		for (k = 0; k < bpf_stack_nr_slots(frame); k++) {
			if (!stack_slot_is_object(bpf_stack_slot(frame, k), ref->id))
				continue;
			*frameno = f;
			*spi = k;
			return true;
		}
	}
	return false;
}

/* The class of the sections of @kind, 0 RCU read and 1 preemption disabled. */
static int resource_of_section(struct bpf_verifier_env *env, u8 kind)
{
	struct bpf_resource res;

	memset(&res, 0, sizeof(res));
	res.kind = kind ? BPF_RESOURCE_PREEMPT : BPF_RESOURCE_RCU;
	return resource_intern(env, &res);
}

static int resource_of_kind(struct bpf_verifier_env *env, u8 kind)
{
	struct bpf_resource res;

	memset(&res, 0, sizeof(res));
	res.kind = kind;
	return resource_intern(env, &res);
}

/*
 * The class of the lock that the current insn takes through @reg, a pointer
 * to it. A lock in the only element of an array map, which every global
 * variable is, is at a fixed address: its class says where, and a site needs
 * no place for it. That is so for a map the program refers to itself only:
 * what stands for the inner maps of a map has no values. Any other lock is
 * @off bytes into what the pointer is into, a map value or an object: a site
 * finds it through a pointer to that which the frame keeps, unless the offset
 * is too large for a site to tell, see BPF_RES_F_NO_PTR.
 */
static int resource_of_lock(struct bpf_verifier_env *env, const struct bpf_reference_state *ref,
			    const struct bpf_reg_state *reg, s16 *off, u8 *flags)
{
	struct bpf_resource res;
	const struct bpf_map *map;
	u64 base;
	u32 i;

	memset(&res, 0, sizeof(res));
	res.kind = ref->type == REF_TYPE_LOCK ? BPF_RESOURCE_SPIN_LOCK : BPF_RESOURCE_RES_LOCK;
	if (!reg || !tnum_is_const(reg->var_off) ||
	    reg->var_off.value != (u64)(s16)reg->var_off.value) {
		*flags |= BPF_RES_F_NO_PTR;
		return resource_intern(env, &res);
	}
	*off = reg->var_off.value;
	map = reg->type == PTR_TO_MAP_VALUE ? reg->map_ptr : NULL;
	for (i = 0; map && i < env->used_map_cnt; i++)
		if (env->used_maps[i] == map)
			break;
	if (map && i < env->used_map_cnt && map->map_type == BPF_MAP_TYPE_ARRAY &&
	    map->ops->map_direct_value_addr && !map->ops->map_direct_value_addr(map, &base, *off))
		res.addr = (void *)(long)(base + *off);
	return resource_intern(env, &res);
}

/* The offset from R10 of the stack slot @spi of a frame. */
static s16 spi_off(int spi)
{
	return -(spi + 1) * BPF_REG_SIZE;
}

/*
 * The class of the resource refs[@idx] the current insn acquires, and how the
 * insn has its handle: in R@regno @after the call, the pointer the call
 * returns, which may point @adj bytes into the object, or in the register in
 * front of it, the pointer the call takes to a lock or to a stack object. The
 * handle of a dynptr is the record or the reader, the first word of the
 * dynptr at @obj_off, so that a clone releases it as well as the dynptr it was
 * created in. -EOPNOTSUPP for a resource the unwinder cannot release, -EXDEV
 * for a stack object in the stack of another frame.
 */
static int acquired_class(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			  const struct bpf_reference_state *ref, int regno, bool after, u8 *flags,
			  s16 *adj, s16 *obj_off)
{
	const struct bpf_func_state *frame = st->frame[st->curframe];
	/* a handle that is in no register can only be found by the sites */
	bool in_reg = regno >= BPF_REG_0 && regno <= BPF_REG_5;
	const struct bpf_stack_state *slot;
	struct bpf_resource res;
	struct bpf_reg_state reg;
	int objframe, spi, ret;

	*adj = 0;
	*obj_off = 0;
	if (after) {
		if (!in_reg)
			return -EOPNOTSUPP;
		reg = frame->regs[regno];
		if (!reg_ref_off(&reg, ref->id, adj))
			*adj = 0;
		reg.var_off = tnum_const(0);
		ret = resource_describe(env, &reg, &res, false);
		return ret ? -EOPNOTSUPP : resource_intern(env, &res);
	}
	*flags |= BPF_RES_F_ARG;
	if (ref->type & REF_TYPE_LOCK_MASK)
		return resource_of_lock(env, ref, in_reg ? &frame->regs[regno] : NULL, adj, flags);
	if (!stack_object_find(st, ref, &objframe, &spi))
		return -EOPNOTSUPP;
	if (objframe != st->curframe)
		return -EXDEV;
	slot = bpf_stack_slot(st->frame[objframe], spi);
	switch (slot->slot_type[BPF_REG_SIZE - 1]) {
	case STACK_DYNPTR:
		*flags |= BPF_RES_F_DEREF;
		*obj_off = spi_off(spi);
		return resource_of_kind(env, slot->spilled_ptr.dynptr.type == BPF_DYNPTR_TYPE_FILE ?
					     BPF_RESOURCE_DYNPTR_FILE : BPF_RESOURCE_RINGBUF);
	case STACK_IRQ_FLAG:
		return resource_of_kind(env, BPF_RESOURCE_IRQ_FLAG);
	default:
		ret = resource_of_iter(env, &slot->spilled_ptr);
		return ret < 0 ? -EOPNOTSUPP : ret;
	}
}

/*
 * The acquisition of insn @insn through R@reg, of a resource of class @res.
 * An insn that acquires in different ways on different paths has an
 * acquisition for each: the insns that keep a slot are emitted once per insn,
 * so none of them may need a slot then, see bpf_frame_desc_resolve(). Returns
 * its index.
 */
static int acq_add(struct bpf_verifier_env *env, u32 insn, u16 res, u8 reg, u8 flags, s16 adj,
		   s16 obj_off)
{
	u32 i, cnt = env->res_acq_cnt;
	struct bpf_res_acq *a;

	for (i = 0; i < cnt; i++) {
		a = &env->res_acqs[i];
		if (a->insn == insn && a->reg == reg && a->res == res && a->flags == flags &&
		    a->adj == adj && a->obj_off == obj_off)
			return i;
	}
	if (cnt >= U16_MAX - 1)
		return -E2BIG;
	a = kvrealloc(env->res_acqs, array_size(cnt + 1, sizeof(*a)), GFP_KERNEL_ACCOUNT);
	if (!a)
		return -ENOMEM;
	a[cnt] = (struct bpf_res_acq) { .insn = insn, .res = res, .reg = reg, .flags = flags,
					.adj = adj, .obj_off = obj_off };
	env->res_acqs = a;
	env->res_acq_cnt = cnt + 1;
	return cnt;
}

/*
 * refs[@idx] is what acquisition @acq acquired, held by the frame that owns
 * it. The slot of an acquisition holds one handle: a frame that holds two of
 * what it acquired at once is fine as long as the acquisition gets no slot,
 * see bpf_frame_desc_resolve().
 */
static int ref_set_acq(struct bpf_verifier_env *env, struct bpf_verifier_state *st, int idx,
		       int acq)
{
	struct bpf_reference_state *ref = &st->refs[idx];
	int i;

	for (i = 0; i < st->acquired_refs; i++) {
		if (i == idx || st->refs[i].acq != acq + 1 || st->refs[i].frameno != ref->frameno)
			continue;
		env->res_acqs[acq].multi = true;
		break;
	}
	ref->res = env->res_acqs[acq].res + 1;
	ref->acq = acq + 1;
	return 0;
}

/*
 * Record that the current insn acquires the resource refs[@idx], whose handle
 * is in R@regno @after the insn, the pointer a call returns, or in front of
 * it, the pointer to a stack object or to a lock the call takes. A call that
 * @may_fail, a resilient lock, has acquired it only when it returns 0. A
 * resource the unwinder cannot release gets no slot, and a throw may not be
 * reached while it is held, see bpf_reference_state::res.
 */
int bpf_frame_desc_record_acquire(struct bpf_verifier_env *env, int idx, int regno, bool after,
				  bool may_fail)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_reference_state *ref = &st->refs[idx];
	u8 flags = may_fail ? BPF_RES_F_MAY_FAIL : 0;
	s16 adj, obj_off;
	int res, acq;

	ref->res = 0;
	ref->acq = 0;
	if (!env->describe_frames || st->speculative)
		return 0;
	res = acquired_class(env, st, ref, regno, after, &flags, &adj, &obj_off);
	if (res == -EOPNOTSUPP) {
		/* the insns of another visit must not take this for a resource of theirs */
		env->insn_aux_data[env->insn_idx].res_none = true;
		return 0;
	}
	if (res == -EXDEV) {
		verbose(env, "frame_desc: insn %d creates an object in the stack of another frame, which is not supported in a program that throws\n",
			env->insn_idx);
		return -EINVAL;
	}
	if (res < 0)
		return res;
	/* no insns can put it into a slot then: R10 stands for no register */
	if (regno < BPF_REG_0 || regno > BPF_REG_5)
		regno = BPF_REG_FP;
	acq = acq_add(env, env->insn_idx, res, regno, flags, adj, obj_off);
	return acq < 0 ? acq : ref_set_acq(env, st, idx, acq);
}

/*
 * The current insn is a call that acquires nothing on this visit and leaves
 * @r0. It may acquire what R0 carries on another visit, as a lookup does in a
 * map of sockets and not in another map: the insns that keep the slot of that
 * would take this R0 for the handle, see bpf_frame_desc_resolve().
 */
void bpf_frame_desc_record_none(struct bpf_verifier_env *env, const struct bpf_reg_state *r0)
{
	if (!env->describe_frames || env->cur_state->speculative)
		return;
	if (r0->type != SCALAR_VALUE || !tnum_equals_const(r0->var_off, 0))
		env->insn_aux_data[env->insn_idx].res_none_r0 = true;
}

/*
 * Did some visit of insn @idx acquire nothing a slot can hold where
 * acquisition @a has a resource? An R0 that is no resource matters to an
 * acquisition whose handle is R0: one that takes its handle in an argument,
 * a lock for one, stores the argument.
 */
static bool acquires_sometimes(const struct bpf_verifier_env *env, u32 idx,
			       const struct bpf_res_acq *a)
{
	const struct bpf_insn_aux_data *aux = &env->insn_aux_data[idx];

	return aux->res_none || (aux->res_none_r0 && !(a->flags & BPF_RES_F_ARG));
}

/*
 * The kernel holds a reference for the __ref argument @argno of a struct_ops
 * program, refs[@idx], and the program releases it or hands it back: the main
 * program holds it from its first insn. When it needs a slot, the entry of the
 * program fills the slot from the context. An argument of a type the unwinder
 * cannot release is not recorded, like any such reference.
 */
int bpf_frame_desc_record_ctx_arg(struct bpf_verifier_env *env, int idx, int argno)
{
	const struct bpf_ctx_arg_aux *info = &env->prog->aux->ctx_arg_info[argno];
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_reference_state *ref = &st->refs[idx];
	struct bpf_reg_state reg = {};
	struct bpf_resource res;
	int ret;

	ref->res = 0;
	ref->acq = 0;
	if (!env->describe_frames)
		return 0;
	reg.type = info->reg_type & ~PTR_MAYBE_NULL;
	reg.btf = info->btf;
	reg.btf_id = info->btf_id;
	if (resource_describe(env, &reg, &res, false))
		return 0;
	ret = resource_intern(env, &res);
	if (ret < 0)
		return ret;
	ret = acq_add(env, argno, ret, BPF_REG_1, BPF_RES_F_CTX, 0, info->offset);
	return ret < 0 ? ret : ref_set_acq(env, st, idx, ret);
}

/*
 * The call @insn releases through R@reg what acquisition @acq acquired: its
 * handle leaves the slot of the acquisition in front of the call, when it has
 * one. @bad says why no insns can do that here. The insns compare the
 * argument the same way whatever it releases, so releases of one argument
 * that differ in how they take the handle are bad as well. That matters for
 * an acquisition that has a slot only, see bpf_frame_desc_resolve().
 */
static int rel_add(struct bpf_verifier_env *env, u32 insn, u16 acq, u8 reg, u8 flags, s16 adj,
		   u8 bad)
{
	u32 i, cnt = env->res_rel_cnt;
	struct bpf_res_rel *r, *same = NULL;

	for (i = 0; i < cnt; i++) {
		r = &env->res_rels[i];
		if (r->insn != insn || r->reg != reg)
			continue;
		if (r->flags != flags || r->adj != adj) {
			if (!r->bad)
				r->bad = BPF_RES_REL_DIFFER;
			if (!bad)
				bad = BPF_RES_REL_DIFFER;
		} else if (r->acq == acq) {
			same = r;
		}
	}
	if (same) {
		if (!same->bad)
			same->bad = bad;
		return 0;
	}
	r = kvrealloc(env->res_rels, array_size(cnt + 1, sizeof(*r)), GFP_KERNEL_ACCOUNT);
	if (!r)
		return -ENOMEM;
	r[cnt] = (struct bpf_res_rel) { .insn = insn, .acq = acq, .reg = reg, .flags = flags,
					.adj = adj, .bad = bad };
	env->res_rels = r;
	env->res_rel_cnt = cnt + 1;
	return 0;
}

/*
 * Record that the current insn releases the resource refs[@idx], before it
 * is released: its handle, in the argument the call releases, see
 * bpf_verifier_env::release_regno, leaves the slot of its acquisition in
 * front of the call. A frame releases what it acquired itself: nothing tells
 * a callee where the slot of its caller is.
 */
int bpf_frame_desc_record_release(struct bpf_verifier_env *env, int idx)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_reference_state *ref = &st->refs[idx];
	const struct bpf_func_state *frame = st->frame[st->curframe];
	u32 i, insn = env->insn_idx;
	int regno = env->release_regno;
	const struct bpf_res_acq *acq;
	u8 flags = 0, bad = 0;
	s16 adj = 0;

	if (!env->describe_frames || st->speculative)
		return 0;
	/* the lock would be unlocked in memory that may be gone by then */
	for (i = 0; ref->type == REF_TYPE_PTR && i < st->acquired_refs; i++) {
		if (!(st->refs[i].type & REF_TYPE_LOCK_MASK) || st->refs[i].id != ref->id)
			continue;
		verbose(env, "frame_desc: insn %d releases an object whose lock is held, which is not supported in a program that throws\n",
			insn);
		return -EINVAL;
	}
	if (!ref->res)
		return 0;
	if (ref->frameno != st->curframe) {
		verbose(env, "frame_desc: insn %d releases what another frame holds, which is not supported in a program that throws\n",
			insn);
		return -EINVAL;
	}
	acq = &env->res_acqs[ref->acq - 1];
	/* what insns could not compare with a slot matters when there is a slot only */
	if (regno < BPF_REG_1 || regno > BPF_REG_5) {
		regno = BPF_REG_FP;
		bad = BPF_RES_REL_NO_REG;
	} else if (acq->flags & BPF_RES_F_DEREF) {
		flags = BPF_RES_F_DEREF;
	} else if (!(acq->flags & BPF_RES_F_ARG) &&
		   !reg_ref_off(&frame->regs[regno], ref->id, &adj)) {
		bad = BPF_RES_REL_NOT_PTR;
	}
	return rel_add(env, insn, ref->acq - 1, regno, flags, adj, bad);
}

/* The current insn enters (@delta 1) or leaves (-1) a section of @kind: counted by its frame. */
int bpf_frame_desc_record_section(struct bpf_verifier_env *env, u8 kind, s8 delta)
{
	struct bpf_verifier_state *st = env->cur_state;
	struct bpf_section_insn *si;
	u32 i, cnt = env->section_insn_cnt;

	if (!env->describe_frames || st->speculative)
		return 0;
	for (i = 0; i < cnt; i++)
		if (env->section_insns[i].insn == env->insn_idx)
			return 0;
	si = kvrealloc(env->section_insns, array_size(cnt + 1, sizeof(*si)), GFP_KERNEL_ACCOUNT);
	if (!si)
		return -ENOMEM;
	si[cnt] = (struct bpf_section_insn) { .insn = env->insn_idx, .kind = kind, .delta = delta };
	env->section_insns = si;
	env->section_insn_cnt = cnt + 1;
	return 0;
}

/*
 * The current frame returns to its caller. Its slots and its counts of
 * sections go with the frame, and nothing moves them to the frame it returns
 * to, so it returns holding nothing but a reference in R0, which the call
 * acquires for the caller, see bpf_frame_desc_record_return(), and in as many
 * sections as it was called in. The entry counts of the sections are lowered
 * as the frame leaves its callers' sections, see release_context_state(),
 * which counts those apart.
 */
int bpf_frame_desc_record_exit(struct bpf_verifier_env *env)
{
	struct bpf_verifier_state *st = env->cur_state;
	const struct bpf_func_state *frame = st->frame[st->curframe];
	int i, held = 0;
	s16 adj;

	if (!env->describe_frames || st->speculative)
		return 0;
	if (st->active_rcu_locks != frame->entry_rcu_locks || frame->rcu_released_below ||
	    st->active_preempt_locks != frame->entry_preempt_locks || frame->preempt_released_below) {
		verbose(env, "frame_desc: a subprog returns in other sections than it was called in at insn %d, which is not supported in a program that throws\n",
			env->insn_idx);
		return -EINVAL;
	}
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];

		if (!ref->res || ref->frameno != st->curframe)
			continue;
		if (ref->type == REF_TYPE_PTR && !(env->res_acqs[ref->acq - 1].flags & BPF_RES_F_ARG) &&
		    reg_ref_off(&frame->regs[BPF_REG_0], ref->id, &adj) && !held++)
			continue;
		verbose(env, "frame_desc: a subprog returns holding what R0 does not carry at insn %d, which is not supported in a program that throws\n",
			env->insn_idx);
		return -EINVAL;
	}
	return 0;
}

/*
 * A subprog called at insn @callsite returned to the current frame of @st
 * with @r0. The reference refs[@idx] it returned holding is the caller's
 * from here on, acquired by the call like the reference a kfunc returns; with
 * @idx < 0 it returned holding nothing, and what it left in R0 must not be
 * taken for a reference by the insns another visit has follow the call.
 */
int bpf_frame_desc_record_return(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
				 int idx, int callsite, const struct bpf_reg_state *r0)
{
	struct bpf_reference_state *ref;
	s16 adj = 0;
	int acq;

	if (!env->describe_frames || st->speculative)
		return 0;
	ref = idx < 0 ? NULL : &st->refs[idx];
	if (!ref || !ref->res) {
		if (r0->type != SCALAR_VALUE || !tnum_equals_const(r0->var_off, 0))
			env->insn_aux_data[callsite].res_none = true;
		return 0;
	}
	if (!reg_ref_off(r0, ref->id, &adj)) {
		verbose(env, "frame_desc: the subprog called at insn %d returns holding what R0 does not carry, which is not supported in a program that throws\n",
			callsite);
		return -EINVAL;
	}
	acq = acq_add(env, callsite, ref->res - 1, BPF_REG_0, 0, adj, 0);
	return acq < 0 ? acq : ref_set_acq(env, st, idx, acq);
}

/*
 * How many sections of @kind frame @f of @st is in: those entered since it
 * was called, less those of its callers it left. A frame is entered with the
 * sections its callers are in, which entry_*_locks counts, less the ones the
 * frame or its callees have left since, which *_released_below counts.
 */
static int frame_sections(const struct bpf_verifier_state *st, int f, int kind)
{
	const struct bpf_func_state *frame = st->frame[f], *callee;
	u32 entry, now;

	entry = kind ? frame->entry_preempt_locks + frame->preempt_released_below :
		       frame->entry_rcu_locks + frame->rcu_released_below;
	if (f == st->curframe) {
		now = kind ? st->active_preempt_locks : st->active_rcu_locks;
	} else {
		callee = st->frame[f + 1];
		now = kind ? callee->entry_preempt_locks + callee->preempt_released_below :
			     callee->entry_rcu_locks + callee->rcu_released_below;
	}
	return (int)now - (int)entry;
}

/*
 * The registers the unwinder can read of a frame: R6 to R9 are callee-saved,
 * so it has them for a frame that is in a call as well. The others it has for
 * the frame that calls bpf_throw() only; R1 is the cookie there.
 */
static const u8 site_regs[] = {
	BPF_REG_6, BPF_REG_7, BPF_REG_8, BPF_REG_9,
	BPF_REG_0, BPF_REG_2, BPF_REG_3, BPF_REG_4, BPF_REG_5,
};

/*
 * The places of frame @f of @st that hold the handle of @ref, which the frame
 * owns, in @loc: the stack object the reference is of, or the slots of the
 * stack a pointer to the object is spilled in and the registers that hold
 * one, see site_regs; @throws when the frame calls bpf_throw(). A lock at a
 * fixed address needs no place. Any other lock is found like an object,
 * through a pointer to what it is in, which has the id of the lock. The slots
 * a spill is removed from again, see bpf_remove_fastcall_spills_fills(), hold
 * nothing at run time.
 */
static void ref_locations(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, int f,
			  const struct bpf_reference_state *ref, bool throws,
			  struct bpf_res_loc *loc)
{
	const struct bpf_res_acq *acq = &env->res_acqs[ref->acq - 1];
	const struct bpf_func_state *frame = st->frame[f];
	s16 adj, lim = env->subprog_info[frame->subprogno].fastcall_stack_end;
	bool lock = ref->type & REF_TYPE_LOCK_MASK, ptr;
	const struct bpf_stack_state *slot;
	int k;

	memset(loc->at, 0, sizeof(loc->at));
	loc->cnt = 0;
	loc->obj = false;
	loc->fixed = lock && env->resources[acq->res].addr;
	if (loc->fixed) {
		loc->cnt = 1;
		return;
	}
	/* a pointer the frame keeps: to the object, or to what a lock with an id is in */
	ptr = lock ? ref->id && !(acq->flags & BPF_RES_F_NO_PTR) :
		     ref->type == REF_TYPE_PTR && !(acq->flags & BPF_RES_F_ARG);
	for (k = 0; k < bpf_stack_nr_slots(frame) && loc->cnt < BPF_RES_LOC_MAX; k++) {
		slot = bpf_stack_slot(frame, k);
		adj = 0;
		if (spi_off(k) < lim)
			break;
		if (!lock && stack_slot_is_object(slot, ref->id)) {
			/* the handle of a dynptr is its first word, as when it was created */
			if (slot->slot_type[BPF_REG_SIZE - 1] != STACK_DYNPTR) {
				loc->obj = true;
				loc->cnt = 0;
			}
		} else if (!ptr || !bpf_is_spilled_reg(slot) ||
			   !reg_ref_off(&slot->spilled_ptr, ref->id, &adj)) {
			continue;
		}
		loc->at[loc->cnt].off = spi_off(k);
		/* the acquisition of a lock has how far the lock is into what it is in */
		loc->at[loc->cnt++].adj = lock ? adj - acq->adj : adj;
		if (loc->obj)
			return;
	}
	if (!env->describe_regs || !ptr)
		return;
	for (k = 0; k < (throws ? ARRAY_SIZE(site_regs) : 4) && loc->cnt < BPF_RES_LOC_MAX; k++) {
		if (!reg_ref_off(&frame->regs[site_regs[k]], ref->id, &adj))
			continue;
		loc->at[loc->cnt].off = site_regs[k];
		loc->at[loc->cnt].reg = true;
		loc->at[loc->cnt++].adj = lock ? adj - acq->adj : adj;
	}
}

/*
 * A throw may find frame @f of @st at the call @insn. Record what the frame
 * keeps where there, for the descriptor of the site: the visits of a site
 * have to agree on it, since the site has one descriptor.
 */
static int site_visit(struct bpf_verifier_env *env, const struct bpf_verifier_state *st, int f,
		      u32 insn)
{
	bool throws = f == st->curframe && bpf_is_throw_kfunc(&env->prog->insnsi[insn]);
	struct bpf_res_loc cur, *loc;
	struct bpf_res_site *site;
	u32 i, j, k, n, s;

	for (s = 0; s < env->res_site_cnt; s++)
		if (env->res_sites[s].insn == insn)
			break;
	if (s == env->res_site_cnt) {
		site = kvrealloc(env->res_sites, array_size(s + 1, sizeof(*site)), GFP_KERNEL_ACCOUNT);
		if (!site)
			return -ENOMEM;
		env->res_sites = site;
		site[s] = (struct bpf_res_site) { .insn = insn };
		env->res_site_cnt = s + 1;
	}
	site = &env->res_sites[s];
	for (k = 0; k < ARRAY_SIZE(site->sections); k++) {
		int cnt = frame_sections(st, f, k);

		if (!site->visits)
			site->sections[k] = cnt;
		else if (site->sections[k] != cnt)
			site->sections_vary[k] = true;
	}
	site->visits++;
	for (i = 0; i < st->acquired_refs; i++) {
		const struct bpf_reference_state *ref = &st->refs[i];

		if (ref->frameno != f || !ref->acq)
			continue;
		env->res_acqs[ref->acq - 1].held = true;
		ref_locations(env, st, f, ref, throws, &cur);
		for (j = 0; j < env->res_loc_cnt; j++)
			if (env->res_locs[j].site == s && env->res_locs[j].acq == ref->acq - 1)
				break;
		if (j == env->res_loc_cnt) {
			loc = kvrealloc(env->res_locs, array_size(j + 1, sizeof(*loc)), GFP_KERNEL_ACCOUNT);
			if (!loc)
				return -ENOMEM;
			env->res_locs = loc;
			cur.site = s;
			cur.acq = ref->acq - 1;
			cur.visits = 1;
			loc[j] = cur;
			env->res_loc_cnt = j + 1;
			continue;
		}
		/* the places this visit finds the handle in as well */
		loc = &env->res_locs[j];
		loc->visits++;
		for (k = 0, n = 0; k < loc->cnt; k++) {
			for (j = 0; j < cur.cnt; j++)
				if (cur.at[j].off == loc->at[k].off && cur.at[j].adj == loc->at[k].adj &&
				    cur.at[j].reg == loc->at[k].reg)
					break;
			if (j < cur.cnt && cur.obj == loc->obj && cur.fixed == loc->fixed)
				loc->at[n++] = loc->at[k];
		}
		loc->cnt = n;
	}
	return 0;
}

/*
 * A throw may find the frames of @st where they are: the current one at
 * @insn_idx, bpf_throw() or the call of a subprog that may throw, and each of
 * its callers at the call it has not returned from. The frames that called a
 * function verified on its own were recorded when they called it. The
 * registers of the frame that calls bpf_throw() have to be those it calls it
 * with: the state is the one in front of the call.
 */
int bpf_frame_desc_record_site(struct bpf_verifier_env *env, struct bpf_verifier_state *st,
			       int insn_idx)
{
	int f, err;

	if (!env->describe_frames || st->speculative)
		return 0;
	for (f = st->curframe; f >= 0; f--) {
		err = site_visit(env, st, f, f == st->curframe ? insn_idx : st->frame[f + 1]->callsite);
		if (err)
			return err;
	}
	return 0;
}

/*
 * A round of the main pass is dropped, see do_check_all(): what its paths
 * recorded goes with it.
 */
void bpf_frame_desc_reset(struct bpf_verifier_env *env)
{
	u32 i;

	env->res_acq_cnt = 0;
	env->res_rel_cnt = 0;
	env->section_insn_cnt = 0;
	env->res_site_cnt = 0;
	env->res_loc_cnt = 0;
	for (i = 0; i < env->prog->len; i++) {
		env->insn_aux_data[i].res_none = false;
		env->insn_aux_data[i].res_none_r0 = false;
	}
}

void bpf_frame_desc_env_free(struct bpf_verifier_env *env)
{
	kvfree(env->res_acqs);
	kvfree(env->res_rels);
	kvfree(env->section_insns);
	kvfree(env->res_sites);
	kvfree(env->res_locs);
	kvfree(env->resources);
	env->res_acqs = NULL;
	env->res_rels = NULL;
	env->section_insns = NULL;
	env->res_sites = NULL;
	env->res_locs = NULL;
	env->resources = NULL;
}

/*
 * The pass named the insns of the program it verified. The insns of a patch
 * all name the insn they replaced, and its aux data went to the last of them,
 * see patch_list_adj_aux(): map every insn of them to that one, the call
 * itself when insns were put in front of it. Returns NULL without memory.
 */
static u32 *insns_of_pass(struct bpf_verifier_env *env, u32 *orig_len)
{
	u32 i, len = env->prog->len, n = 0, *new_of;

	/* a hidden subprog was appended to the last insn, and its insns name that one */
	if (env->hidden_subprog_cnt)
		len = env->subprog_info[env->subprog_cnt - 1].start;
	for (i = 0; i < len; i++)
		n = max(n, env->insn_aux_data[i].orig_idx + 1);
	new_of = kvcalloc(n, sizeof(*new_of), GFP_KERNEL_ACCOUNT);
	if (!new_of)
		return NULL;
	for (i = 0; i < len; i++)
		new_of[env->insn_aux_data[i].orig_idx] = i;
	*orig_len = n;
	return new_of;
}

/* The subprog an acquisition is in: the main program for an argument of the context. */
static int acq_subprog(struct bpf_verifier_env *env, const struct bpf_res_acq *a, const u32 *new_of)
{
	if (a->flags & BPF_RES_F_CTX)
		return 0;
	return bpf_find_containing_subprog(env, new_of[a->insn]) - env->subprog_info;
}

/* An upper bound of the insns put around one call for one acquisition or release. */
#define RES_INSNS_MAX	6

/* In front of a call that takes the handle in an argument: the handle goes into the slot. */
static int emit_acquire_before(struct bpf_insn *buf, const struct bpf_res_acq *a)
{
	int cnt = 0;

	if ((a->flags & (BPF_RES_F_ARG | BPF_RES_F_DEREF)) == BPF_RES_F_ARG)
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, a->reg, a->off);
	return cnt;
}

/*
 * After a call that acquires: the pointer it returned goes into the slot, as
 * a pointer to the object, and so does the record or the reader of the
 * dynptr it created; NULL when it acquired nothing. A call that may fail has
 * acquired what it took only when it returned 0.
 */
static int emit_acquire_after(struct bpf_insn *buf, const struct bpf_res_acq *a)
{
	int cnt = 0;

	if (a->flags & BPF_RES_F_DEREF) {
		buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, a->obj_off);
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, a->off);
	} else if (a->flags & BPF_RES_F_ARG) {
		if (a->flags & BPF_RES_F_MAY_FAIL) {
			buf[cnt++] = BPF_JMP32_IMM(BPF_JEQ, BPF_REG_0, 0, 1);
			buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, a->off, 0);
		}
	} else if (a->adj) {
		buf[cnt++] = BPF_MOV64_REG(BPF_REG_AX, BPF_REG_0);
		buf[cnt++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_AX, 0, 1);
		buf[cnt++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_AX, a->adj);
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, a->off);
	} else {
		buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_0, a->off);
	}
	return cnt;
}

/*
 * Acquisition @acq needs a slot. Can the insns that keep it be emitted? They
 * are emitted once per insn, so the insn has to acquire in one way, with the
 * handle in a register, and every call that releases what it acquired has to
 * take the handle in one way that insns can compare with the slot.
 */
static int slot_can_be_kept(struct bpf_verifier_env *env, u32 acq)
{
	const struct bpf_res_acq *a = &env->res_acqs[acq], *b;
	const struct bpf_res_rel *r;
	u32 i;

	for (i = 0; i < env->res_acq_cnt; i++) {
		b = &env->res_acqs[i];
		if (i == acq || b->insn != a->insn || b->reg != a->reg ||
		    (a->flags ^ b->flags) & BPF_RES_F_CTX)
			continue;
		verbose(env, "frame_desc: insn %d acquires resources of different types on different paths\n",
			a->insn);
		return -EINVAL;
	}
	if (a->reg == BPF_REG_FP) {
		verbose(env, "frame_desc: insn %d takes the handle of a resource in no register\n",
			a->insn);
		return -EINVAL;
	}
	for (i = 0; i < env->res_rel_cnt; i++) {
		r = &env->res_rels[i];
		if (r->acq != acq || !r->bad)
			continue;
		if (r->bad == BPF_RES_REL_NO_REG)
			verbose(env, "frame_desc: insn %d releases a resource whose handle is in no argument register\n",
				r->insn);
		else if (r->bad == BPF_RES_REL_NOT_PTR)
			verbose(env, "frame_desc: insn %d releases a resource R%d does not point to\n",
				r->insn, r->reg);
		else
			verbose(env, "frame_desc: insn %d takes the handle of what it releases differently on different paths\n",
				r->insn);
		return -EINVAL;
	}
	return 0;
}

/*
 * Decide what needs a hidden slot, once the pass has seen every frame, and
 * reserve it.
 *
 * A frame is unwound at a site, and the site has a descriptor for what every
 * visit of it found in the same place of the frame's stack. So an
 * acquisition needs no slot when no site finds a frame holding what it
 * acquired, and none when every site that does finds the handle in a place
 * all its visits agree on, on every visit. The others get a slot in the
 * frame of the subprog they are in. Likewise a subprog counts its sections
 * of a kind in a slot only when the visits of one of its sites differ in how
 * many the frame is in.
 *
 * The subprogs are numbered as they are now and looked up again whenever
 * they are needed, since removing a dead one renumbers them.
 */
int bpf_frame_desc_resolve(struct bpf_verifier_env *env)
{
	u32 i, k, orig_len, *new_of;
	int ret = 0;

	if (!env->res_acq_cnt && !env->section_insn_cnt)
		return 0;
	new_of = insns_of_pass(env, &orig_len);
	if (!new_of)
		return -ENOMEM;
	for (i = 0; i < env->res_loc_cnt; i++) {
		const struct bpf_res_loc *loc = &env->res_locs[i];

		if (!loc->cnt || loc->visits != env->res_sites[loc->site].visits)
			env->res_acqs[loc->acq].slot = true;
	}
	/*
	 * A register that a site names holds the handle from where the program
	 * read it for the last time: the program is done with it, but nothing
	 * that is inserted later may use it, see bpf_do_misc_fixups().
	 */
	for (i = 0; i < env->res_loc_cnt; i++) {
		const struct bpf_res_loc *loc = &env->res_locs[i];

		for (k = 0; !env->res_acqs[loc->acq].slot && k < loc->cnt; k++)
			if (loc->at[k].reg)
				env->frame_desc_regs |= BIT(loc->at[k].off);
	}
	for (i = 0; i < env->res_acq_cnt && !ret; i++) {
		struct bpf_res_acq *a = &env->res_acqs[i];

		if (!(a->flags & BPF_RES_F_CTX) &&
		    verifier_bug_if(a->insn >= orig_len, env, "resource at insn %d", a->insn)) {
			ret = -EFAULT;
			break;
		}
		if (!a->slot)
			continue;
		ret = slot_can_be_kept(env, i);
		if (ret)
			break;
		if (a->multi) {
			verbose(env, "frame_desc: a frame holds two resources of insn %d at once, which is not supported in a program that throws\n",
				a->insn);
			ret = -EINVAL;
			break;
		}
		/* some visit of the insn has nothing a slot can hold where this one has */
		if (!(a->flags & BPF_RES_F_CTX) && acquires_sometimes(env, new_of[a->insn], a)) {
			verbose(env, "frame_desc: insn %d acquires a resource on some paths only, or one of a type that cannot be released\n",
				a->insn);
			ret = -EINVAL;
			break;
		}
		ret = bpf_reserve_stack_slots(env, acq_subprog(env, a, new_of), 1, &a->off);
		env->frame_desc_slots++;
	}
	for (i = 0; i < env->res_site_cnt && !ret; i++) {
		const struct bpf_res_site *site = &env->res_sites[i];
		struct bpf_subprog_info *sub;

		if (verifier_bug_if(site->insn >= orig_len, env, "site at insn %d", site->insn)) {
			ret = -EFAULT;
			break;
		}
		sub = bpf_find_containing_subprog(env, new_of[site->insn]);
		for (k = 0; k < ARRAY_SIZE(sub->section_off) && !ret; k++) {
			if (!site->sections_vary[k] || sub->section_off[k])
				continue;
			ret = bpf_reserve_stack_slots(env, sub - env->subprog_info, 1, &sub->section_off[k]);
			env->frame_desc_slots++;
		}
	}
	kvfree(new_of);
	return ret;
}

/* What is kept at an insn of the current image, in the order it is emitted in. */
enum {
	ITEM_SECTION,
	ITEM_RELEASE,
	ITEM_ACQUIRE,
};

struct res_item {
	u32 idx;	/* insn of the current image */
	u32 rec;	/* which section insn, release or acquisition */
	u8 kind;
	u8 reg;		/* ITEM_RELEASE: the argument the call releases */
};

static int item_cmp(const void *a, const void *b)
{
	const struct res_item *x = a, *y = b;

	if (x->idx != y->idx)
		return x->idx < y->idx ? -1 : 1;
	if (x->kind != y->kind)
		return x->kind - y->kind;
	if (x->reg != y->reg)
		return x->reg - y->reg;
	return x->rec < y->rec ? -1 : x->rec > y->rec;
}

/*
 * In front of a call that releases what one of the acquisitions of the @n
 * items from @it acquired, in one argument: the slot that holds the handle
 * the call takes is cleared, one slot, since two references to one object
 * have equal handles in a slot each. No slot is touched when the call takes
 * NULL or what another acquisition acquired. R0 is free in front of a call.
 */
static int emit_release(struct bpf_verifier_env *env, struct bpf_insn *buf,
			const struct res_item *it, int n)
{
	const struct bpf_res_rel *r = &env->res_rels[it->rec];
	int i, cnt = 0, reg = r->reg, per = r->adj ? 5 : 4;

	if (r->flags & BPF_RES_F_DEREF) {
		buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, r->reg, 0);
		reg = BPF_REG_0;
	}
	for (i = 0; i < n; i++) {
		s16 off = env->res_acqs[env->res_rels[it[i].rec].acq].off;
		bool last = i == n - 1;

		buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
		if (r->adj)
			buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, r->adj);
		buf[cnt++] = BPF_JMP_REG(BPF_JNE, BPF_REG_AX, reg, last ? 1 : 2);
		buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, off, 0);
		/* past the slots that follow: the last one has no jump */
		if (!last)
			buf[cnt++] = BPF_JMP_A((n - 1 - i) * per - 1);
	}
	return cnt;
}

/*
 * The insns around the call @n items from @it are kept at: in @buf, those in
 * front of the call, the call, and those that follow it. Returns how many
 * follow it, and in @before how many come in front.
 */
static int emit_items(struct bpf_verifier_env *env, const struct res_item *it, int n,
		      struct bpf_insn *buf, int *before)
{
	const struct bpf_subprog_info *sub = bpf_find_containing_subprog(env, it->idx);
	int i, k, cnt = 0, after;

	for (i = 0; i < n; i++) {
		const struct bpf_section_insn *si;
		s16 off;

		switch (it[i].kind) {
		case ITEM_SECTION:
			si = &env->section_insns[it[i].rec];
			off = sub->section_off[si->kind];
			buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_FP, off);
			buf[cnt++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_AX, si->delta);
			buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, off);
			break;
		case ITEM_RELEASE:
			/* the acquisitions one argument may release what was acquired by */
			for (k = i + 1; k < n && it[k].kind == ITEM_RELEASE && it[k].reg == it[i].reg; k++)
				;
			cnt += emit_release(env, buf + cnt, &it[i], k - i);
			i = k - 1;
			break;
		case ITEM_ACQUIRE:
			cnt += emit_acquire_before(buf + cnt, &env->res_acqs[it[i].rec]);
			break;
		}
	}
	*before = cnt;
	buf[cnt++] = env->prog->insnsi[it->idx];
	after = cnt;
	for (i = 0; i < n; i++)
		if (it[i].kind == ITEM_ACQUIRE)
			cnt += emit_acquire_after(buf + cnt, &env->res_acqs[it[i].rec]);
	return cnt - after;
}

/*
 * At the entry of each subprog: its slots and counts start out empty, and
 * the main program takes the references the kernel passed it that it keeps
 * in a slot from the context, which R1 points at. The insns go in front of
 * the first one, which a jump to it skips.
 */
static int emit_entries(struct bpf_verifier_env *env)
{
	u32 i, k, orig_len, *new_of;
	struct bpf_insn *buf;
	int s, cnt, ret = 0;

	new_of = insns_of_pass(env, &orig_len);
	buf = kvcalloc(2 * (env->res_acq_cnt + 2), sizeof(*buf), GFP_KERNEL_ACCOUNT);
	if (!new_of || !buf) {
		ret = -ENOMEM;
		goto out;
	}
	for (s = 0; s < env->subprog_cnt && !ret; s++) {
		const struct bpf_subprog_info *sub = &env->subprog_info[s];

		cnt = 0;
		for (i = 0; i < env->res_acq_cnt; i++) {
			const struct bpf_res_acq *a = &env->res_acqs[i];

			if (!a->slot || acq_subprog(env, a, new_of) != s)
				continue;
			if (a->flags & BPF_RES_F_CTX) {
				buf[cnt++] = BPF_LDX_MEM(BPF_DW, BPF_REG_AX, BPF_REG_1, a->obj_off);
				buf[cnt++] = BPF_STX_MEM(BPF_DW, BPF_REG_FP, BPF_REG_AX, a->off);
			} else {
				buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, a->off, 0);
			}
		}
		for (k = 0; k < ARRAY_SIZE(sub->section_off); k++)
			if (sub->section_off[k])
				buf[cnt++] = BPF_ST_MEM(BPF_DW, BPF_REG_FP, sub->section_off[k], 0);
		if (!cnt)
			continue;
		ret = bpf_patch_list_insert(env, sub->start, buf, cnt);
		env->frame_desc_insns += cnt;
	}
	ret = ret ?: bpf_patch_list_commit(env);
out:
	kvfree(buf);
	kvfree(new_of);
	return ret;
}

/*
 * Keep the slots and the counts there are up to date, through the patch list. What goes
 * in front of a call is patched in with the call, so that the jumps to it
 * land on it; what follows it is inserted in front of the next insn, which a
 * jump to that insn skips, as it skips the call.
 */
int bpf_frame_desc_emit(struct bpf_verifier_env *env)
{
	u32 i, k, n = 0, len = env->prog->len, orig_len, *new_of, max = 0;
	struct bpf_insn *buf = NULL, *insn;
	struct res_item *items = NULL;
	int ret = 0, before, after;

	if (!env->res_acq_cnt && !env->section_insn_cnt)
		return 0;
	new_of = insns_of_pass(env, &orig_len);
	items = kvcalloc(env->res_acq_cnt + env->res_rel_cnt + env->section_insn_cnt,
			 sizeof(*items), GFP_KERNEL_ACCOUNT);
	if (!new_of || !items) {
		ret = -ENOMEM;
		goto out;
	}
	/* what has no slot is kept by nothing */
	for (i = 0; i < env->section_insn_cnt; i++) {
		const struct bpf_section_insn *si = &env->section_insns[i];

		if (bpf_find_containing_subprog(env, new_of[si->insn])->section_off[si->kind])
			items[n++] = (struct res_item) { new_of[si->insn], i, ITEM_SECTION };
	}
	for (i = 0; i < env->res_rel_cnt; i++)
		if (env->res_acqs[env->res_rels[i].acq].slot)
			items[n++] = (struct res_item) { new_of[env->res_rels[i].insn], i, ITEM_RELEASE,
							 env->res_rels[i].reg };
	for (i = 0; i < env->res_acq_cnt; i++)
		if (env->res_acqs[i].slot && !(env->res_acqs[i].flags & BPF_RES_F_CTX))
			items[n++] = (struct res_item) { new_of[env->res_acqs[i].insn], i, ITEM_ACQUIRE };
	sort(items, n, sizeof(*items), item_cmp, NULL);
	for (i = 0; i < n; i = k) {
		for (k = i; k < n && items[k].idx == items[i].idx; k++)
			;
		max = max(max, k - i);
	}
	buf = kvcalloc(max * RES_INSNS_MAX + 1, sizeof(*buf), GFP_KERNEL_ACCOUNT);
	if (!buf) {
		ret = -ENOMEM;
		goto out;
	}
	for (i = 0; i < n && !ret; i = k) {
		u32 idx = items[i].idx;

		for (k = i; k < n && items[k].idx == idx; k++)
			;
		if (verifier_bug_if(idx >= len || env->prog->insnsi[idx].code != (BPF_JMP | BPF_CALL),
				    env, "resource kept at insn %d, not a call", idx)) {
			ret = -EFAULT;
			break;
		}
		after = emit_items(env, &items[i], k - i, buf, &before);
		/* the call of a subprog in front of it does not move with the call */
		ret = bpf_adj_moved_insn(&buf[before], before);
		if (ret)
			break;
		/*
		 * A callee that unwound returns right after the call and goes where
		 * the unwind_goto says: nothing may come between the two.
		 */
		if (after && idx + 1 < len && bpf_is_unwind_goto(&env->prog->insnsi[idx + 1])) {
			verbose(env, "frame_desc: the call at insn %d acquires a resource and may unwind, which is not supported in a program that throws\n",
				idx);
			ret = -EINVAL;
			break;
		}
		if (before) {
			insn = bpf_patch_list_add(env, idx, buf, before + 1);
			ret = PTR_ERR_OR_ZERO(insn);
		}
		if (!ret && after)
			ret = bpf_patch_list_insert(env, idx + 1, buf + before + 1, after);
		env->frame_desc_insns += before + after;
	}
	ret = ret ?: bpf_patch_list_commit(env);
	ret = ret ?: emit_entries(env);
out:
	kvfree(buf);
	kvfree(items);
	kvfree(new_of);
	return ret;
}

/* A stack object may use a referenced object the frame holds as well: it goes first. */
static bool resource_goes_first(const struct bpf_resource *res)
{
	return res->kind == BPF_RESOURCE_ITER || res->kind == BPF_RESOURCE_DYNPTR_FILE;
}

/* Add @d to the pool of the program, or free it when the pool has it: its index plus one. */
static int pool_add(struct bpf_verifier_env *env, struct bpf_frame_desc *d)
{
	struct bpf_frame_desc_pool *pool = env->frame_desc_pool;
	u32 i;

	for (i = 0; i < pool->cnt; i++) {
		if (pool->desc[i]->size != d->size || memcmp(pool->desc[i], d, d->size))
			continue;
		kvfree(d);
		return i + 1;
	}
	pool = kvrealloc(pool, struct_size(pool, desc, pool->cnt + 1), GFP_KERNEL_ACCOUNT);
	if (!pool) {
		kvfree(d);
		return -ENOMEM;
	}
	env->frame_desc_pool = pool;
	pool->desc[pool->cnt] = d;
	env->frame_desc_bytes += d->size;
	return ++pool->cnt;
}

/*
 * The descriptor of a subprog that has slots: the slot of each acquisition in
 * it that has one, which holds the handle of what the acquisition acquired or
 * NULL, and the counts of its sections.
 */
static int build_slots(struct bpf_verifier_env *env, int s, const u32 *new_of)
{
	struct bpf_subprog_info *sub = &env->subprog_info[s];
	struct bpf_frame_desc *d;
	u32 i, k, n = 0;
	int res;

	for (i = 0; i < env->res_acq_cnt; i++)
		n += env->res_acqs[i].slot && acq_subprog(env, &env->res_acqs[i], new_of) == s;
	for (k = 0; k < ARRAY_SIZE(sub->section_off); k++)
		n += !!sub->section_off[k];
	if (!n)
		return 0;
	d = kvzalloc(struct_size(d, ent, n), GFP_KERNEL_ACCOUNT);
	if (!d)
		return -ENOMEM;
	d->size = struct_size(d, ent, n);
	for (i = 0; i < env->res_acq_cnt; i++) {
		const struct bpf_res_acq *a = &env->res_acqs[i];

		if (!a->slot || acq_subprog(env, a, new_of) != s)
			continue;
		d->ent[d->nent++] = (struct bpf_frame_desc_entry) {
			.res = a->res, .off = a->off,
			.flags = resource_goes_first(&env->resources[a->res]) ? BPF_FRAME_ENT_FIRST : 0,
		};
	}
	for (k = 0; k < ARRAY_SIZE(sub->section_off); k++) {
		if (!sub->section_off[k])
			continue;
		res = resource_of_section(env, k);
		if (res < 0) {
			kvfree(d);
			return res;
		}
		d->ent[d->nent++] = (struct bpf_frame_desc_entry) {
			.res = res, .off = sub->section_off[k], .flags = BPF_FRAME_ENT_COUNTER,
		};
	}
	res = pool_add(env, d);
	if (res < 0)
		return res;
	sub->frame_desc = res;
	return 0;
}

/*
 * The descriptor of site @idx: where the frame at the site keeps, in its own
 * stack or in a register, what it holds that has no slot, and how many
 * sections it is in when its subprog does not count them. A site that has
 * nothing to say has none.
 */
static int build_site(struct bpf_verifier_env *env, u32 idx, const u32 *new_of)
{
	struct bpf_res_site *site = &env->res_sites[idx];
	const struct bpf_subprog_info *sub = bpf_find_containing_subprog(env, new_of[site->insn]);
	struct bpf_frame_desc *d;
	u32 i, k, n = 0;
	int res;

	for (i = 0; i < env->res_loc_cnt; i++)
		n += env->res_locs[i].site == idx && !env->res_acqs[env->res_locs[i].acq].slot;
	for (k = 0; k < ARRAY_SIZE(sub->section_off); k++)
		n += !sub->section_off[k] && site->sections[k];
	if (!n)
		return 0;
	d = kvzalloc(struct_size(d, ent, n), GFP_KERNEL_ACCOUNT);
	if (!d)
		return -ENOMEM;
	d->size = struct_size(d, ent, n);
	for (i = 0; i < env->res_loc_cnt; i++) {
		const struct bpf_res_loc *loc = &env->res_locs[i];
		const struct bpf_res_acq *a = &env->res_acqs[loc->acq];
		u16 flags = loc->obj ? BPF_FRAME_ENT_OBJ : loc->fixed ? BPF_FRAME_ENT_FIXED : 0;

		if (loc->site != idx || a->slot)
			continue;
		if (resource_goes_first(&env->resources[a->res]))
			flags |= BPF_FRAME_ENT_FIRST;
		if (loc->at[0].reg)
			flags |= BPF_FRAME_ENT_REG;
		d->ent[d->nent++] = (struct bpf_frame_desc_entry) {
			.res = a->res, .off = loc->at[0].off, .adj = loc->at[0].adj, .flags = flags,
		};
	}
	for (k = 0; k < ARRAY_SIZE(sub->section_off); k++) {
		if (sub->section_off[k] || !site->sections[k])
			continue;
		res = resource_of_section(env, k);
		if (res < 0) {
			kvfree(d);
			return res;
		}
		d->ent[d->nent++] = (struct bpf_frame_desc_entry) {
			.res = res, .count = site->sections[k], .flags = BPF_FRAME_ENT_COUNT,
		};
	}
	res = pool_add(env, d);
	if (res < 0)
		return res;
	site->desc = res;
	env->frame_desc_sites++;
	return 0;
}

/*
 * The frame descriptors of the program: one for every subprog that has
 * slots, and one for every site that says what the frame at it keeps in its
 * own stack. The unwinder releases what a frame holds in the order of the
 * entries, within a phase, but for the iterators and the readers of file
 * dynptrs: they come before the references, which they may be iterating over
 * or reading. Identical descriptors share a body in the pool of the program,
 * which takes the resource classes over.
 */
int bpf_frame_desc_build(struct bpf_verifier_env *env)
{
	struct bpf_frame_desc_pool *pool;
	u32 i, orig_len, *new_of;
	int ret = -ENOMEM;

	if (!env->res_acq_cnt && !env->section_insn_cnt)
		return 0;
	new_of = insns_of_pass(env, &orig_len);
	pool = kvzalloc(struct_size(pool, desc, 0), GFP_KERNEL_ACCOUNT);
	if (!new_of || !pool) {
		kvfree(pool);
		goto out;
	}
	env->frame_desc_pool = pool;
	for (i = 0, ret = 0; i < env->subprog_cnt && !ret; i++)
		ret = build_slots(env, i, new_of);
	for (i = 0; i < env->res_site_cnt && !ret; i++)
		ret = build_site(env, i, new_of);
	if (ret)
		goto out;
	pool = env->frame_desc_pool;
	pool->resources = env->resources;
	pool->resource_cnt = env->resource_cnt;
	env->frame_desc_bytes += env->resource_cnt * sizeof(*env->resources);
	env->resources = NULL;
out:
	kvfree(new_of);
	return ret;
}

static int site_cmp(const void *a, const void *b)
{
	const struct bpf_frame_desc_site *x = a, *y = b;

	return x->off < y->off ? -1 : x->off > y->off;
}

/*
 * The sites of @subprog that have a descriptor, for its JITed function, or
 * NULL when it has none: each by the index of its call in the function, until
 * the JIT has put the call somewhere, see bpf_prog_fill_frame_desc_sites().
 * The insns of now are not those the pass named the sites by, and the insns
 * put around a call name the call as well.
 */
struct bpf_frame_desc_sites *bpf_frame_desc_sites(struct bpf_verifier_env *env, int subprog)
{
	const struct bpf_subprog_info *sub = &env->subprog_info[subprog];
	struct bpf_frame_desc_sites *tab;
	u32 i, idx, n = 0, orig_len, *new_of;

	for (i = 0; i < env->res_site_cnt; i++)
		n += !!env->res_sites[i].desc;
	if (!n)
		return NULL;
	new_of = insns_of_pass(env, &orig_len);
	tab = kvzalloc(struct_size(tab, site, n), GFP_KERNEL_ACCOUNT);
	if (!new_of || !tab) {
		kvfree(new_of);
		kvfree(tab);
		return ERR_PTR(-ENOMEM);
	}
	for (i = 0; i < env->res_site_cnt; i++) {
		const struct bpf_res_site *site = &env->res_sites[i];
		const struct bpf_insn *insn;

		if (!site->desc)
			continue;
		idx = site->insn < orig_len ? new_of[site->insn] : 0;
		for (;; idx--) {
			insn = &env->prog->insnsi[idx];
			if (env->insn_aux_data[idx].orig_idx != site->insn) {
				idx = env->prog->len;
				break;
			}
			if ((BPF_CLASS(insn->code) == BPF_JMP && BPF_OP(insn->code) == BPF_CALL) || !idx)
				break;
		}
		insn = idx < env->prog->len ? &env->prog->insnsi[idx] : NULL;
		if (verifier_bug_if(!insn || BPF_CLASS(insn->code) != BPF_JMP ||
				    BPF_OP(insn->code) != BPF_CALL, env,
				    "site at insn %d is not a call", site->insn)) {
			kvfree(new_of);
			kvfree(tab);
			return ERR_PTR(-EFAULT);
		}
		if (idx < sub->start || idx >= (sub + 1)->start)
			continue;
		tab->site[tab->cnt++] = (struct bpf_frame_desc_site) {
			.off = idx - sub->start, .desc = site->desc - 1,
		};
	}
	kvfree(new_of);
	if (!tab->cnt) {
		kvfree(tab);
		return NULL;
	}
	sort(tab->site, tab->cnt, sizeof(tab->site[0]), site_cmp, NULL);
	return tab;
}
