// SPDX-License-Identifier: GPL-2.0-only
/*
 * Releasing what the frames of a BPF program hold when bpf_throw() discards
 * them. Before the exception callback takes over, the frames from the throw
 * up to the main program are walked once per phase of the release order, and
 * each frame releases what its frame descriptor says it holds of that phase,
 * see frame_desc.c.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/irqflags.h>

void bpf_frame_desc_pool_free(struct bpf_frame_desc_pool *pool)
{
	u32 i;

	if (!pool)
		return;
	for (i = 0; i < pool->cnt; i++)
		kvfree(pool->desc[i]);
	kvfree(pool->resources);
	kvfree(pool);
}

static bool resource_is_lock(u8 kind)
{
	return kind == BPF_RESOURCE_SPIN_LOCK || kind == BPF_RESOURCE_RES_LOCK;
}

static bool resource_is_section(u8 kind)
{
	return kind == BPF_RESOURCE_RCU || kind == BPF_RESOURCE_PREEMPT;
}

/*
 * Release one resource by its handle, at run time: the pointer to an object,
 * the address of a stack object or of a lock, or nothing for a section. Not
 * inlined so that every release of an unwind can be observed by attaching to
 * this function.
 */
noinline void bpf_unwind_release(const struct bpf_resource *res, void *handle)
{
	/* A destructor that needs RCU protection gets it here, whatever the frames held. */
	if (res->rcu)
		rcu_read_lock();
	switch (res->kind) {
	case BPF_RESOURCE_OBJ:
		bpf_obj_drop_impl(handle, res->meta);
		break;
	case BPF_RESOURCE_PERCPU_OBJ:
		bpf_percpu_obj_drop_impl(handle, res->meta);
		break;
	case BPF_RESOURCE_KPTR:
	case BPF_RESOURCE_ITER:
		res->dtor(handle);
		break;
#ifdef CONFIG_NET
	case BPF_RESOURCE_SOCK:
		bpf_sk_release_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
#endif
	case BPF_RESOURCE_RINGBUF:
		bpf_ringbuf_discard_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
	case BPF_RESOURCE_DYNPTR_FILE:
		bpf_dynptr_file_free(handle);
		break;
	case BPF_RESOURCE_SPIN_LOCK:
		bpf_spin_unlock_proto.func((u64)(long)handle, 0, 0, 0, 0);
		break;
	case BPF_RESOURCE_RES_LOCK:
		bpf_res_spin_unlock(handle);
		break;
	case BPF_RESOURCE_IRQ_FLAG:
		bpf_local_irq_restore(handle);
		break;
	case BPF_RESOURCE_RCU:
		bpf_rcu_read_unlock();
		break;
	case BPF_RESOURCE_PREEMPT:
		bpf_preempt_enable();
		break;
	default:
		WARN_ON_ONCE(1);
	}
	if (res->rcu)
		rcu_read_unlock();
}

/* The sections of a frame are counted, per kind. */
enum {
	BPF_UNWIND_SECTION_RCU,
	BPF_UNWIND_SECTION_PREEMPT,
	BPF_UNWIND_NR_SECTIONS,
};

static int section_index(u8 kind)
{
	return kind == BPF_RESOURCE_RCU ? BPF_UNWIND_SECTION_RCU : BPF_UNWIND_SECTION_PREEMPT;
}

/*
 * The release order. Objects never run under a lock or with IRQs disabled by
 * any frame, and a sleeping destructor runs after every section is left; an
 * RCU-protected object is destroyed before the sections end.
 */
enum {
	BPF_UNWIND_PHASE_LOCKS,		/* locks and IRQ flags */
	BPF_UNWIND_PHASE_RCU_OBJS,	/* objects whose destructor needs RCU protection */
	BPF_UNWIND_PHASE_SECTIONS,	/* RCU and preemption sections */
	BPF_UNWIND_PHASE_OBJS,		/* everything else */
	BPF_UNWIND_NR_PHASES,
};

static int release_phase(const struct bpf_resource *res)
{
	if (resource_is_lock(res->kind) || res->kind == BPF_RESOURCE_IRQ_FLAG)
		return BPF_UNWIND_PHASE_LOCKS;
	if (resource_is_section(res->kind))
		return BPF_UNWIND_PHASE_SECTIONS;
	return res->rcu ? BPF_UNWIND_PHASE_RCU_OBJS : BPF_UNWIND_PHASE_OBJS;
}

struct bpf_unwind_ctx {
	int phase;	/* BPF_UNWIND_PHASE_*: what this walk releases */
	int cnt;	/* BPF frames passed */
	/* The sections the frames hold, per kind, summed by the first walk. */
	const struct bpf_resource *section[BPF_UNWIND_NR_SECTIONS];
	s64 nr_sections[BPF_UNWIND_NR_SECTIONS];
};

/*
 * The R10 of a frame of the function @fn whose native frame pointer is @bp: a
 * fixed distance from it, or, with a private stack, this CPU's private frame.
 */
static u64 bpf_unwind_fp(const struct bpf_prog_aux *fn, u64 bp)
{
	if (fn->priv_stack_ptr)
		return (u64)(long)this_cpu_ptr(fn->priv_stack_ptr) + fn->priv_frame_off;
	return bp + fn->frame_fp_off;
}

/*
 * Release what the slots of the frame of @prog hold of the phase of this
 * walk; @bp is its native frame pointer. The first walk sums the frame's
 * counts of sections for their phase, and releases the locks and IRQ flags
 * in two passes: the flags a frame saved with interrupts enabled, of which
 * it can have one at most, since every later save found them disabled, are
 * restored last, after the locks and the other flags in whatever order the
 * frame took them.
 */
static void bpf_unwind_release_frame(struct bpf_unwind_ctx *ctx, const struct bpf_prog *prog, u64 bp)
{
	const struct bpf_prog_aux *fn = bpf_prog_frame_aux(prog);
	const struct bpf_frame_desc_pool *pool = fn->frame_desc_pool;
	int passes = ctx->phase == BPF_UNWIND_PHASE_LOCKS ? 2 : 1, pass, s;
	const struct bpf_frame_desc *d;
	bool late;
	u64 fp;
	u32 i;

	if (!fn->frame_desc)
		return;
	d = pool->desc[fn->frame_desc - 1];
	fp = bpf_unwind_fp(fn, bp);
	for (pass = 0; pass < passes; pass++) {
		for (i = 0; i < d->nent; i++) {
			const struct bpf_frame_desc_entry *ent = &d->ent[i];
			const struct bpf_resource *res = &pool->resources[ent->res];
			u64 *slot = (u64 *)(long)(fp + ent->off);
			void *handle = (void *)(long)*slot;

			if (ent->flags & BPF_FRAME_ENT_COUNTER) {
				if (ctx->phase != BPF_UNWIND_PHASE_LOCKS || pass)
					continue;
				s = section_index(res->kind);
				ctx->section[s] = res;
				ctx->nr_sections[s] += (s64)*slot;
				continue;
			}
			if (!handle || release_phase(res) != ctx->phase)
				continue;
			late = res->kind == BPF_RESOURCE_IRQ_FLAG &&
			       !arch_irqs_disabled_flags(*(unsigned long *)handle);
			if (passes == 2 && late != (pass == 1))
				continue;
			bpf_unwind_release(res, handle);
		}
	}
}

static bool bpf_unwind_walker(void *cookie, u64 ip, u64 sp, u64 bp)
{
	struct bpf_unwind_ctx *ctx = cookie;
	struct bpf_prog *prog;

	/*
	 * The RCU read lock is held to safely traverse the latch tree, but we
	 * don't need its protection when accessing the prog, since it has an
	 * active stack frame on the current stack trace, and won't disappear.
	 */
	rcu_read_lock();
	prog = bpf_prog_ksym_find(ip);
	rcu_read_unlock();
	/* the frames of bpf_throw() and of the unwinder come first */
	if (!prog)
		return !ctx->cnt;
	ctx->cnt++;
	bpf_unwind_release_frame(ctx, prog, bp);
	/* the main program is where the exception callback takes over */
	return bpf_is_subprog(prog);
}

/*
 * Release what the frames between bpf_throw() and the main program hold, the
 * main program's included, in four phases: locks and IRQ flags,
 * RCU-protected objects, sections, then the other objects. Each phase but
 * the sections' is a walk over the frames, innermost first, that releases
 * each frame's entries of the phase in the order of its descriptor; the
 * frames are released as the walk passes them, so their number is not
 * bounded. The sections need no walk of their own: the first one summed
 * their counts, and sections of one kind are all the same.
 */
void bpf_unwind_release_frames(void)
{
	struct bpf_unwind_ctx ctx = {};
	int s;

	for (ctx.phase = 0; ctx.phase < BPF_UNWIND_NR_PHASES; ctx.phase++) {
		if (ctx.phase != BPF_UNWIND_PHASE_SECTIONS) {
			ctx.cnt = 0;
			arch_bpf_stack_walk(bpf_unwind_walker, &ctx);
			continue;
		}
		for (s = 0; s < BPF_UNWIND_NR_SECTIONS; s++) {
			WARN_ONCE(ctx.nr_sections[s] < 0, "bpf: %lld sections to leave\n",
				  ctx.nr_sections[s]);
			while (ctx.nr_sections[s]-- > 0)
				bpf_unwind_release(ctx.section[s], NULL);
		}
	}
}
