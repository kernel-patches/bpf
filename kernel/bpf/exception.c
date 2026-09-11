// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include "exception.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

/* The one exception kfunc this file has to recognise. bpf_throw() is not
 * among them: the verifier proper has its own reason to know that one, and
 * bpf_is_throw_kfunc() already answers for it.
 */
enum exc_kfunc {
	EXC_KF_bpf_unwind_resume,
};

BTF_ID_LIST(exc_kfunc_list)
BTF_ID(func, bpf_unwind_resume)

/* Is @insn a call to the exception kfunc @kf? */
static bool insn_is_exc_kfunc(const struct bpf_insn *insn, int kf)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == exc_kfunc_list[kf];
}

/* ---- Exception cleanup analysis -------------------------------------------
 *
 * The compiler emits a .bpf_cleanup table (validated by check_cleanup_info())
 * saying that if an exception unwinds out of a call in the range
 * [begin, end), the frame resumes at a landing pad to run its cleanup code --
 * a Rust destructor, say -- instead of being discarded.
 *
 * The kernel consumes that table at run time, not at load time: bpf_throw()
 * walks the BPF call stack and, for each frame whose current call a record
 * covers, runs that record's landing pad before popping the frame. Later
 * patches build that walk, and the one the verifier does over the same thing.
 *
 * The work is split in two by what it needs from control flow.
 *
 * bpf_prepare_cleanup_exceptions() runs before bpf_check_cfg() and does only
 * what the CFG itself depends on: it refuses a program the kernel could not
 * dispatch pads for at all, and paints each covered call site with the pad it
 * unwinds to. Landing pads are unreachable in the compiler's CFG, and that
 * mark is the edge bpf_cleanup_pad_of_call() hands bpf_check_cfg() to stop
 * them being reported as dead code.
 *
 * bpf_check_cleanup_exceptions() runs after it, and refuses the shapes the
 * walk could not handle. Everything it needs is control flow, so it reads
 * what bpf_check_cfg() already worked out rather than working it out again:
 *
 *  - which subprograms an exception may unwind out of, which is exactly
 *    subprog_info.might_throw, closed over the call graph by
 *    merge_callee_effects() as the CFG walk pops each callee;
 *  - what each instruction can reach (reach[]) -- a resume, a plain exit, an
 *    indirect jump, a throw -- which is how a cleanup pad is told from a
 *    catch pad, since the table records no such distinction and reading
 *    forward from a pad does not work: LLVM sinks cold EH blocks and merges
 *    a function's resume paths, so a pad routinely ends in a jump and what
 *    lies linearly after it belongs to something else;
 *  - which instructions are pad bodies (in_pad[]), which is where a pad that
 *    can raise a second exception gets caught.
 *
 * The refusals, all of them shapes with no correct answer rather than shapes
 * merely unimplemented:
 *
 *  - a program that also installs a bpf_exception_cb();
 *  - a subprogram that may unwind while also being used as a helper callback
 *    (bpf_loop() and friends), where the helper rather than generated code
 *    decides what a nonzero return means;
 *  - a landing pad that reaches both a resume and a plain exit, or neither,
 *    or an indirect jump -- nothing can say what it is;
 *  - a landing pad that can raise a second exception, directly or through a
 *    call;
 *  - a catch pad, which stops the unwinding and carries on in its frame.
 *    bpf_throw() calls a pad as a subroutine on its own stack, so it has no
 *    way to hand a frame back its own execution. Not supported yet rather
 *    than wrong in principle.
 *
 * Everything here is intentionally linear in the program size, because a pass
 * that runs on untrusted input before any complexity limit applies must not be
 * quadratic in it. The analyses are worklist driven, and the most any walk
 * spends per instruction is a binary search over the subprogram table.
 */

/* What an instruction does to intra-subprog control flow. */
enum cleanup_insn_kind {
	CLEANUP_INSN_PLAIN,	/* falls through */
	CLEANUP_INSN_JUMP,	/* unconditional jump */
	CLEANUP_INSN_COND,	/* falls through and branches */
	CLEANUP_INSN_EXIT,
	CLEANUP_INSN_THROW,	/* call bpf_throw: no fall-through */
	CLEANUP_INSN_RESUME,	/* call bpf_unwind_resume: likewise */
	CLEANUP_INSN_CALL,	/* call to another subprog */
	CLEANUP_INSN_GOTOX,	/* indirect jump: successors not known here */
};

/* What each instruction can reach, computed once by cleanup_reachability(). */
#define CLEANUP_REACH_RESUME	BIT(0)	/* a bpf_unwind_resume() call */
#define CLEANUP_REACH_EXIT	BIT(1)	/* a plain BPF_EXIT */
#define CLEANUP_REACH_UNKNOWN	BIT(2)	/* an indirect jump */
#define CLEANUP_REACH_THROW	BIT(3)	/* a bpf_throw() call */

/* Scratch shared by the analyses, sized once so no walker has to allocate. */
struct cleanup_ctx {
	struct bpf_verifier_env *env;
	bool *is_callback;	/* per subprog: reachable as a helper callback */
	bool *in_pad;		/* per insn: runs only while unwinding */
	u8 *reach;		/* per insn: CLEANUP_REACH_* mask */
	u32 *stack;		/* per insn: DFS stack */
	void *scratch;		/* the one allocation all of the above live in */
};

/* One scratch array to carve out of a shared block. */
struct cleanup_carve {
	void **dst;
	size_t n, sz;
};

/* Hand out @cnt scratch arrays from a single allocation.
 *
 * The pass needs a handful of these and they all live exactly as long as it
 * does, so one block and one free is both less code and less to get wrong on
 * an error path. The table is the only place a size is written down, which is
 * what keeps the sizing loop and the carving loop from drifting apart.
 */
static void *cleanup_alloc(const struct cleanup_carve *tab, u32 cnt)
{
	size_t total = 0;
	char *block, *p;
	u32 i;

	for (i = 0; i < cnt; i++)
		total += round_up(tab[i].n * tab[i].sz, 8);

	block = kvzalloc(total, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!block)
		return NULL;

	for (i = 0, p = block; i < cnt; i++) {
		*tab[i].dst = p;
		p += round_up(tab[i].n * tab[i].sz, 8);
	}
	return block;
}

/* Index of the subprog containing instruction @off, or -1 if out of range. */
static int cleanup_subprog_of(struct bpf_verifier_env *env, u32 off)
{
	struct bpf_subprog_info *info = bpf_find_containing_subprog(env, off);

	return info ? info - env->subprog_info : -1;
}

/* Which subprogram the instruction at hand belongs to, for a pass that walks
 * the program in order. Initialise with CLEANUP_WALK_INIT and call
 * cleanup_walk_to() for each index in turn: the boundary is carried along
 * rather than looked up, so a linear pass stays linear instead of paying a
 * binary search per instruction.
 */
struct cleanup_walk {
	u32 start, end;		/* [start, end) of the current subprogram */
	int sub;		/* its index */
};

#define CLEANUP_WALK_INIT { .sub = -1 }

static void cleanup_walk_to(struct bpf_verifier_env *env, struct cleanup_walk *w, u32 i)
{
	while (i >= w->end) {
		w->sub++;
		w->start = env->subprog_info[w->sub].start;
		w->end = env->subprog_info[w->sub + 1].start;
	}
}

/* Classify @i for the intra-subprog walkers below: @next is the fall-through
 * and @target the branch target, either -1 when there is none. A throw and a
 * resume are terminators: a throw never continues into what follows it, and a
 * resume hands control back to the bpf_throw() walker.
 */
static enum cleanup_insn_kind cleanup_classify(struct bpf_verifier_env *env, u32 i,
					       int *next, int *target)
{
	struct bpf_insn *insn = &env->prog->insnsi[i];
	u8 class = BPF_CLASS(insn->code);

	*next = i + 1;
	*target = -1;

	if (insn->code == (BPF_LD | BPF_IMM | BPF_DW)) {
		*next = i + 2;
		return CLEANUP_INSN_PLAIN;
	}
	if (class != BPF_JMP && class != BPF_JMP32)
		return CLEANUP_INSN_PLAIN;

	switch (BPF_OP(insn->code)) {
	case BPF_EXIT:
		*next = -1;
		return CLEANUP_INSN_EXIT;
	case BPF_JA:
		/* Both forms are terminators: neither falls through. */
		*next = -1;
		/*
		 * An indirect jump is spelled in the opcode, not in src_reg --
		 * which BPF_JA|BPF_X requires to be zero, its target being
		 * dst_reg. Same test bpf_check_cfg() makes. Where it can go is
		 * not known until the jump tables are built, so it has no
		 * successors here and cleanup_reachability() marks it unknown.
		 */
		if (BPF_SRC(insn->code) == BPF_X)
			return CLEANUP_INSN_GOTOX;
		*target = class == BPF_JMP32 ? i + insn->imm + 1 : i + insn->off + 1;
		return CLEANUP_INSN_JUMP;
	case BPF_CALL:
		if (bpf_is_throw_kfunc(insn)) {
			*next = -1;
			return CLEANUP_INSN_THROW;
		}
		if (insn_is_exc_kfunc(insn, EXC_KF_bpf_unwind_resume)) {
			*next = -1;
			return CLEANUP_INSN_RESUME;
		}
		return bpf_pseudo_call(insn) ? CLEANUP_INSN_CALL : CLEANUP_INSN_PLAIN;
	default:
		/* Conditional jump, including BPF_JCOND. */
		*target = i + insn->off + 1;
		return CLEANUP_INSN_COND;
	}
}

/*
 * Mark every bpf_throw() call site.
 *
 * The JIT has to spill the throwing frame's callee-saved registers there, and
 * by the time it runs it can no longer recognise the call: insn->imm will have
 * been resolved from the kfunc's BTF id to a call offset. The mark rides along
 * through every bpf_patch_insn_data() between here and there.
 */
static void cleanup_mark_throw_sites(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++)
		if (bpf_is_throw_kfunc(&env->prog->insnsi[i]))
			env->insn_aux_data[i].cleanup_throw_site = true;
}

/*
 * Which subprograms a helper may invoke as a callback.
 *
 * A callback is named by a BPF_PSEUDO_FUNC ld_imm64 rather than reached by a
 * call, so it takes its own scan; subprog_info.is_cb says the same thing but
 * push_callback_call() only sets it once do_check() is under way, which is too
 * late to refuse anything.
 */
static int cleanup_find_callbacks(struct cleanup_ctx *ctx)
{
	struct bpf_verifier_env *env = ctx->env;
	struct bpf_insn *insns = env->prog->insnsi;
	u32 i, len = env->prog->len;

	for (i = 0; i + 1 < len; i++) {
		int callee;

		if (!bpf_pseudo_func(&insns[i]))
			continue;
		/* Same PC-relative encoding a pseudo call uses. */
		callee = bpf_find_subprog(env, i + insns[i].imm + 1);
		if (verifier_bug_if(callee < 0, env,
				    "insn %u names %d, which is not a subprog entry",
				    i, i + insns[i].imm + 1))
			return -EFAULT;
		ctx->is_callback[callee] = true;
	}
	return 0;
}

/* Intra-subprog successors of @i, or -1 each when absent. */
static enum cleanup_insn_kind cleanup_succ(struct bpf_verifier_env *env, u32 i,
					   u32 start, u32 end, int *next, int *target)
{
	enum cleanup_insn_kind kind = cleanup_classify(env, i, next, target);

	if (*next < (int)start || *next >= (int)end)
		*next = -1;
	if (*target < (int)start || *target >= (int)end)
		*target = -1;
	return kind;
}

/* Compute, for every instruction, what it can reach along intra-subprog edges:
 * a bpf_unwind_resume(), a plain exit, or an indirect jump whose targets are
 * not known this early. cleanup_pad_is_catch() reads the answer off this.
 *
 * One backward walk over a predecessor index does the whole program. Walking
 * forward from each landing pad instead would be quadratic, and a program is
 * free to name as many landing pads as it has instructions.
 */
static int cleanup_reachability(struct cleanup_ctx *ctx)
{
	struct bpf_verifier_env *env = ctx->env;
	u32 len = env->prog->len;
	struct cleanup_walk w = CLEANUP_WALK_INIT;
	u32 *pred_off = NULL, *pred = NULL;
	bool *queued = NULL;
	u32 i, sp = 0, nedge = 0;
	int ret = -ENOMEM;
	void *scratch;
	const struct cleanup_carve tab[] = {
		{ (void **)&pred_off, (size_t)len + 2, sizeof(*pred_off) },
		{ (void **)&pred,     2 * (size_t)len, sizeof(*pred) },
		{ (void **)&queued,   len,             sizeof(*queued) },
	};

	/* Freed on the way out rather than held for the whole pass: the
	 * predecessor index is the largest thing here by some way.
	 */
	scratch = cleanup_alloc(tab, ARRAY_SIZE(tab));
	if (!scratch)
		return -ENOMEM;

	/* Count predecessors, seed the sources, and remember the edges. */
	for (i = 0; i < len; i++) {
		enum cleanup_insn_kind kind;
		int next, target;

		cleanup_walk_to(env, &w, i);
		kind = cleanup_succ(env, i, w.start, w.end, &next, &target);

		if (kind == CLEANUP_INSN_RESUME)
			ctx->reach[i] |= CLEANUP_REACH_RESUME;
		else if (kind == CLEANUP_INSN_EXIT)
			ctx->reach[i] |= CLEANUP_REACH_EXIT;
		else if (kind == CLEANUP_INSN_GOTOX)
			ctx->reach[i] |= CLEANUP_REACH_UNKNOWN;
		else if (kind == CLEANUP_INSN_THROW)
			ctx->reach[i] |= CLEANUP_REACH_THROW;

		if (next >= 0) {
			pred_off[next + 1]++;
			nedge++;
		}
		if (target >= 0) {
			pred_off[target + 1]++;
			nedge++;
		}
	}
	if (verifier_bug_if(nedge > 2 * len, env,
			    "%u edges counted for %u insns, at most 2 per insn expected",
			    nedge, len)) {
		ret = -EFAULT;
		goto out;
	}

	for (i = 0; i < len; i++)
		pred_off[i + 1] += pred_off[i];

	w = (struct cleanup_walk)CLEANUP_WALK_INIT;
	for (i = 0; i < len; i++) {
		int next, target;

		cleanup_walk_to(env, &w, i);
		/* The kind is not wanted here, only the edges: the terminators
		 * were classified in the counting pass above.
		 */
		cleanup_succ(env, i, w.start, w.end, &next, &target);
		if (next >= 0)
			pred[pred_off[next]++] = i;
		if (target >= 0)
			pred[pred_off[target]++] = i;

		/* Seed the walk while we are here: the worklist is
		 * independent of the index being built.
		 */
		if (ctx->reach[i]) {
			queued[i] = true;
			ctx->stack[sp++] = i;
		}
	}
	/* pred_off[] was consumed as a cursor; shift it back into place. */
	for (i = len; i > 0; i--)
		pred_off[i] = pred_off[i - 1];
	pred_off[0] = 0;

	/* Each instruction re-enters the worklist at most once per bit it
	 * gains, so this is linear in the number of edges.
	 */
	while (sp) {
		u32 j = ctx->stack[--sp];
		u8 flags = ctx->reach[j];
		u32 e;

		queued[j] = false;
		for (e = pred_off[j]; e < pred_off[j + 1]; e++) {
			u32 p = pred[e];

			if ((ctx->reach[p] | flags) == ctx->reach[p])
				continue;
			ctx->reach[p] |= flags;
			if (!queued[p]) {
				queued[p] = true;
				ctx->stack[sp++] = p;
			}
		}
	}
	ret = 0;
out:
	kvfree(scratch);
	return ret;
}

/* Does landing pad @pad stop the unwinding (a catch pad, reaching a plain
 * exit) or resume it (a cleanup pad, reaching bpf_unwind_resume)?
 *
 * The answer comes from control flow, not from the instruction stream. LLVM
 * sinks cold EH blocks and merges the resume paths of a function, so a pad
 * routinely ends in a jump to a shared block and what lies linearly after it
 * belongs to something else entirely. Guessing wrong here is silent: taking a
 * cleanup pad for a catch pad pops the exception and the unwinding stops
 * halfway.
 *
 * Returns true for a catch pad, false for a cleanup pad, or a negative errno
 * if the pad is ambiguous.
 */
static int cleanup_pad_is_catch(struct cleanup_ctx *ctx, u32 pad)
{
	u8 reach = ctx->reach[pad];

	if (reach & CLEANUP_REACH_UNKNOWN) {
		verbose(ctx->env, "cleanup landing pad %u reaches an indirect jump\n", pad);
		return -EINVAL;
	}
	if (reach & CLEANUP_REACH_THROW) {
		verbose(ctx->env,
			"cleanup landing pad %u can throw while an exception is in flight\n",
			pad);
		return -EINVAL;
	}
	if (!(reach & CLEANUP_REACH_RESUME) == !(reach & CLEANUP_REACH_EXIT)) {
		verbose(ctx->env, "cleanup landing pad %u %s\n", pad,
			(reach & CLEANUP_REACH_RESUME) ?
			"reaches both bpf_unwind_resume() and a plain exit" :
			"reaches neither bpf_unwind_resume() nor an exit");
		return -EINVAL;
	}
	return !!(reach & CLEANUP_REACH_EXIT);
}

/* Mark the body of every cleanup landing pad: the instructions that only ever
 * run with an exception already in flight. Refuse, while walking them, a pad
 * that can raise a second exception.
 *
 * Nothing may throw from inside a pad. cleanup_pad_is_catch() already refuses
 * a pad that reaches a bpf_throw() itself; this adds the case it cannot see,
 * a pad that calls a subprogram which throws. subprog_info.might_throw says
 * exactly which those are.
 *
 * There is simply nowhere to put the inner exception: the walker is partway
 * through delivering the outer one and there is no nest to hold a second.
 *
 * It costs nothing a compiler could emit. A panic inside Rust drop glue has
 * to abort -- a destructor may not unwind while unwinding -- so rustc lowers
 * every call in a cleanup block through a terminate landing pad, which is
 * "landingpad ... filter" on the Itanium ABI, and BPFAsmPrinter refuses that
 * outright with "BPF does not support exception filters yet". The shape never
 * reaches the kernel. Only hand-written assembly can produce it.
 *
 * Catch pads are not walked. A catch pad stops the unwinding, so the code
 * after it is ordinary code again and a call there can throw like any other.
 */
static int cleanup_mark_pad_bodies(struct cleanup_ctx *ctx)
{
	struct bpf_verifier_env *env = ctx->env;
	u32 i, sp = 0;
	int ret;

	/*
	 * The pads, read off the call sites rather than off the table: the
	 * table's offsets named instructions in the program as it was loaded,
	 * and bpf_check_cfg() has since swept what could not run. Every pad
	 * that still has a call site has a mark, and one that does not is no
	 * longer reachable by an unwind.
	 */
	for (i = 0; i < env->prog->len; i++) {
		u32 pad = env->insn_aux_data[i].cleanup_pad;

		if (!pad)
			continue;
		pad--;
		if (ctx->in_pad[pad])
			continue;

		ret = cleanup_pad_is_catch(ctx, pad);
		if (ret < 0)
			return ret;
		if (ret) {
			/*
			 * A catch pad stops the unwinding and carries on in
			 * its frame. bpf_throw() calls a pad as a subroutine,
			 * on its own stack, so the frame's epilogue -- which
			 * is how a catch pad ends -- would pop callee-saved
			 * registers from the wrong place and return somewhere
			 * it was never called from. Resuming a frame for real
			 * is the machinery this design exists to avoid, so the
			 * shape is refused until something implements it.
			 */
			verbose(env,
				"catch landing pad %u is not supported yet, only cleanup pads that resume\n",
				pad);
			return -EOPNOTSUPP;
		}
		ctx->in_pad[pad] = true;
		ctx->stack[sp++] = pad;
	}

	while (sp) {
		u32 j = ctx->stack[--sp];
		enum cleanup_insn_kind kind;
		int next, target, sub;
		u32 start, end;

		sub = cleanup_subprog_of(env, j);
		if (verifier_bug_if(sub < 0, env, "pad body insn %u is in no subprog", j))
			return -EFAULT;
		start = env->subprog_info[sub].start;
		end = env->subprog_info[sub + 1].start;
		kind = cleanup_succ(env, j, start, end, &next, &target);

		if (kind == CLEANUP_INSN_CALL) {
			int callee = cleanup_subprog_of(env, j + env->prog->insnsi[j].imm + 1);

			if (verifier_bug_if(callee < 0, env,
					    "call at insn %u targets %d, which is in no subprog",
					    j, j + env->prog->insnsi[j].imm + 1))
				return -EFAULT;
			if (env->subprog_info[callee].might_throw) {
				verbose(env,
					"cleanup landing pad calls subprog %d at insn %u, which can throw while an exception is in flight\n",
					callee, j);
				return -EINVAL;
			}
		}

		if (next >= 0 && !ctx->in_pad[next]) {
			ctx->in_pad[next] = true;
			ctx->stack[sp++] = next;
		}
		if (target >= 0 && !ctx->in_pad[target]) {
			ctx->in_pad[target] = true;
			ctx->stack[sp++] = target;
		}
	}
	return 0;
}

/*
 * Mark every covered call site with the landing pad it unwinds to, so that
 * bpf_cleanup_pad_of_call() can answer without the table and the answer keeps
 * up with the program as later passes reshape it.
 *
 * Only a call is marked: a bpf2bpf call or a bpf_throw(), the two an exception
 * can unwind out of. A record's range may span other instructions, but no
 * return address ever points into them.
 */
static void cleanup_paint_pads(struct bpf_verifier_env *env)
{
	u32 i, j;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		struct bpf_cleanup_info *rec = &env->cleanup_info[i];

		for (j = rec->begin_off; j < rec->end_off; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];

			if (insn->code != (BPF_JMP | BPF_CALL))
				continue;
			if (!bpf_pseudo_call(insn) && !bpf_is_throw_kfunc(insn))
				continue;
			env->insn_aux_data[j].cleanup_pad = rec->landing_pad_off + 1;
		}
	}
}

/*
 * Everything a program carrying an exception cleanup table needs settled
 * before bpf_check_cfg() runs.
 *
 * The refusals here are the ones that need no control flow to see, and the
 * marks are what the CFG walk itself reads: bpf_cleanup_pad_of_call() turns
 * each painted call site into the edge that makes its landing pad reachable.
 */
int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env)
{
	if (!env->cleanup_info_cnt)
		return 0;

	/*
	 * Dispatching to a landing pad needs a JIT that can hand control to
	 * one and a frame walker to find them with.
	 */
	if (!bpf_jit_supports_cleanup_pads() || !env->prog->jit_requested) {
		verbose(env,
			"exception cleanup needs a JIT that can dispatch landing pads\n");
		return -EOPNOTSUPP;
	}
	/*
	 * jit_requested only says the JIT was asked for. If it then fails,
	 * bpf_fixup_call_args() would quietly fall back to the interpreter,
	 * which has no way to run a landing pad and would execute the resume
	 * the compiler left behind as an ordinary call. Make a failed JIT a
	 * failed load instead.
	 */
	env->prog->jit_required = 1;

	if (env->exception_callback_subprog) {
		verbose(env,
			"exception cleanup table cannot be combined with an exception callback\n");
		return -EINVAL;
	}

	cleanup_mark_throw_sites(env);

	/*
	 * Hand the table over to insn_aux_data. From here on nothing reads
	 * env->cleanup_info: the association between a call site and its pad
	 * travels with the instruction, so every later pass that inserts or
	 * removes code keeps it in step, and a call that goes away takes its
	 * pad with it.
	 */
	cleanup_paint_pads(env);
	return 0;
}

/*
 * Refuse the exception cleanup shapes bpf_throw() could not dispatch.
 *
 * Runs after bpf_check_cfg(), which is what turns the painted call sites into
 * real edges, resolves the indirect jumps, sweeps what cannot run, and leaves
 * subprog_info.might_throw saying which subprograms an exception can leave.
 */
int bpf_check_cleanup_exceptions(struct bpf_verifier_env *env)
{
	u32 nsub = env->subprog_cnt;
	u32 i, len = env->prog->len;
	struct cleanup_ctx ctx = { .env = env };
	int ret;

	if (!env->cleanup_info_cnt)
		return 0;

	{
		const struct cleanup_carve tab[] = {
			{ (void **)&ctx.is_callback, nsub, sizeof(*ctx.is_callback) },
			{ (void **)&ctx.in_pad, len, sizeof(*ctx.in_pad) },
			{ (void **)&ctx.reach, len, sizeof(*ctx.reach) },
			{ (void **)&ctx.stack, len, sizeof(*ctx.stack) },
		};

		ctx.scratch = cleanup_alloc(tab, ARRAY_SIZE(tab));
		if (!ctx.scratch)
			return -ENOMEM;
	}

	ret = cleanup_find_callbacks(&ctx);
	if (ret)
		goto out;

	ret = cleanup_reachability(&ctx);
	if (ret)
		goto out;

	for (i = 0; i < nsub; i++) {
		if (!env->subprog_info[i].might_throw)
			continue;
		if (ctx.is_callback[i]) {
			verbose(env, "subprog %u may unwind and is used as a callback\n", i);
			ret = -EINVAL;
			goto out;
		}
	}

	ret = cleanup_mark_pad_bodies(&ctx);
out:
	kvfree(ctx.scratch);
	return ret;
}

/*
 * Is @insn the bpf_unwind_resume() that ends an exception cleanup landing pad?
 *
 * This is how everything downstream recognises a resume: the CFG walkers and
 * do_check(), which need it to be a terminator, and both JITs, which emit a
 * bare return for it -- the frame is not being returned to, the bpf_throw()
 * walker called the pad and is waiting for it, so running the frame's epilogue
 * would be wrong.
 *
 * The answer stays available for as long as anyone asks it. insn->imm holds
 * the BTF id of a kfunc call until bpf_fixup_kfunc_call() resolves it to a
 * call offset, and do_misc_fixups() deliberately leaves a resume alone -- it
 * is never really called -- so this one is never resolved. That is what lets
 * the JIT ask the same question the verifier did, with no marker in the
 * instruction and no value burned in the src_reg space uapi shares with
 * userspace.
 */
bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return insn_is_exc_kfunc(insn, EXC_KF_bpf_unwind_resume);
}

/*
 * The landing pad the call at @idx can also transfer to, or -1.
 *
 * bpf_check_cleanup_exceptions() painted this onto the call site itself, so
 * the answer needs no table and no search, and it stays correct however much
 * later passes insert or remove around it.
 *
 * The CFG walkers use it so the pads are reachable, which is what gets them
 * verified and keeps bpf_check_cfg() from calling them dead code; unwind_step()
 * uses it to walk the unwind.
 */
int bpf_cleanup_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}

/* ---- Runtime cleanup pad dispatch -----------------------------------------
 *
 * The other way to consume the same .bpf_cleanup table. Instead of rewriting
 * the program at load time, leave it alone and let bpf_throw() walk the BPF
 * call stack: for each frame, look its return address up in that (sub)program's
 * native cleanup table, and if a record covers it, run the landing pad.
 *
 * The pad is run as a subroutine of the walker, not jumped to. It executes
 * with the unwinding frame's frame pointer and BPF callee-saved registers, so
 * everything it reads is that frame's, but on the current stack far below it,
 * so nothing it calls can disturb the frame it is cleaning up after. It ends
 * in the bare return the JIT emits for its bpf_unwind_resume(), which hands
 * control back here rather than to the frame's caller.
 *
 * Restoring the frame's r6-r9 is what makes this work at all, and it is only
 * possible because the callee that is about to be discarded spilled them in
 * its own prologue. bpf_cleanup_force_spill() makes that spill unconditional
 * and of a known shape for every subprogram of a program that carries a
 * cleanup table, so the walker can find them without per-frame metadata.
 */

/* Should this (sub)program's prologue spill every BPF callee-saved register?
 *
 * True for every subprogram of a program that carries a cleanup table --
 * including one with no records of its own, and one that never throws. The
 * spill in a frame holds its *caller's* registers, and that is what the walker
 * restores before running the caller's pad, so a subprogram that merely sits
 * on the stack during an unwind still has to provide it.
 *
 * The exception callback is the one exception. bpf_throw() calls it only once
 * the walk has finished, so no pad ever belongs to it and nothing reads a
 * spill it made -- and its prologue is the one that reuses the throwing
 * frame rather than building its own, which the forced spill has no business
 * reshaping.
 */
bool bpf_cleanup_force_spill(const struct bpf_prog *prog)
{
	return prog->aux->has_cleanup_table && !prog->aux->exception_cb;
}

/*
 * The cleanup record covering the return address @ip in @prog, or NULL.
 * @ip is one instruction past a call, so the range test is (begin, end].
 */
const struct bpf_cleanup_pad *bpf_cleanup_pad_for_ip(const struct bpf_prog *prog, u64 ip)
{
	const struct bpf_prog_aux *aux = prog->aux;
	u32 l = 0, r = aux->nr_cleanup_pads;

	while (l < r) {
		u32 m = l + (r - l) / 2;
		const struct bpf_cleanup_pad *rec = &aux->cleanup_pads[m];

		if (ip <= rec->begin)
			r = m;
		else if (ip > rec->end)
			l = m + 1;
		else
			return rec;
	}
	return NULL;
}

static int cmp_u32(const void *a, const void *b)
{
	u32 x = *(const u32 *)a, y = *(const u32 *)b;

	return x < y ? -1 : x > y;
}

/*
 * Attach @recs, the cleanup records of this (sub)program with offsets already
 * made relative to it, and reserve the native table the JIT will fill in.
 * Doing the allocation here rather than in the JIT keeps the JIT side
 * infallible, which matters because by the time it runs the image is already
 * finalised and there is no clean way to fail.
 *
 * Takes ownership of @recs, whether or not it succeeds, so that the caller
 * can hand it over and be done with it.
 */
int bpf_cleanup_attach_info(struct bpf_prog_aux *aux, struct bpf_cleanup_info *recs, u32 cnt)
{
	struct bpf_cleanup_pad *pads;
	u32 i, n_at, *at;

	if (!cnt) {
		kvfree(recs);
		return 0;
	}

	pads = kvcalloc(cnt, sizeof(*pads), GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!pads) {
		kvfree(recs);
		return -ENOMEM;
	}

	/*
	 * The pads on their own, sorted and deduplicated. A JIT emitting an
	 * indirect-branch landing marker at each one walks the program in
	 * order and asks per instruction, so this has to be searchable
	 * without scanning the whole table each time.
	 */
	at = kvmalloc_array(cnt, sizeof(*at), GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!at) {
		kvfree(pads);
		kvfree(recs);
		return -ENOMEM;
	}
	for (i = 0; i < cnt; i++)
		at[i] = recs[i].landing_pad_off;
	sort(at, cnt, sizeof(*at), cmp_u32, NULL);
	for (i = 0, n_at = 0; i < cnt; i++)
		if (!n_at || at[n_at - 1] != at[i])
			at[n_at++] = at[i];

	aux->cleanup_pad_at = at;
	aux->nr_cleanup_pad_at = n_at;
	aux->cleanup_info = recs;
	aux->nr_cleanup_info = cnt;
	aux->cleanup_pads = pads;
	/*
	 * Withheld until the JIT has filled the table in. The count doubles as
	 * "these addresses are real", and bpf_run_cleanup_pad() tests it
	 * first, so a (sub)program whose JIT never ran reads as having no pads
	 * rather than as having @cnt of them.
	 */
	aux->nr_cleanup_pads = 0;
	return 0;
}

/*
 * Turn this (sub)program's cleanup records into the native address ranges the
 * walker searches. Called by the JIT once the image is final; @addrs maps a
 * BPF instruction index to the first byte of its jitted form. A JIT may run
 * this more than once for the same program (the extra pass over a program
 * split into subprograms), which simply recomputes the same answers.
 */
void bpf_cleanup_fill_native_pads(struct bpf_prog *prog, u32 *addrs, void *image)
{
	struct bpf_prog_aux *aux = prog->aux;
	u32 i, n = aux->nr_cleanup_info;

	if (!n || !aux->cleanup_pads)
		return;

	for (i = 0; i < n; i++) {
		const struct bpf_cleanup_info *rec = &aux->cleanup_info[i];

		if (WARN_ON_ONCE(rec->begin_off > prog->len ||
				 rec->end_off > prog->len ||
				 rec->landing_pad_off > prog->len))
			return;
		aux->cleanup_pads[i].begin = (u64)(long)image + addrs[rec->begin_off];
		aux->cleanup_pads[i].end = (u64)(long)image + addrs[rec->end_off];
		aux->cleanup_pads[i].pad = (u64)(long)image + addrs[rec->landing_pad_off];
	}
	aux->nr_cleanup_pads = n;
}

void bpf_cleanup_free_info(struct bpf_prog_aux *aux)
{
	aux->nr_cleanup_pads = 0;
	kvfree(aux->cleanup_pads);
	aux->cleanup_pads = NULL;
	kvfree(aux->cleanup_info);
	aux->cleanup_info = NULL;
	aux->nr_cleanup_info = 0;
	kvfree(aux->cleanup_pad_at);
	aux->cleanup_pad_at = NULL;
	aux->nr_cleanup_pad_at = 0;
	kvfree(aux->cleanup_throw_at);
	aux->cleanup_throw_at = NULL;
	aux->nr_cleanup_throw_at = 0;
}

/*
 * Does instruction @idx begin an exception cleanup landing pad? A JIT asks
 * this per instruction so that it can emit whatever its architecture requires
 * of an indirect-branch target -- endbr64 on x86-64, "bti j" on arm64 --
 * since bpf_throw() reaches a pad by indirect branch and a pad is not a
 * function entry.
 */
bool bpf_cleanup_insn_is_pad(const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_prog_aux *aux = prog->aux;
	u32 l = 0, r = aux->nr_cleanup_pad_at;

	while (l < r) {
		u32 m = l + (r - l) / 2;

		if (idx < aux->cleanup_pad_at[m])
			r = m;
		else if (idx > aux->cleanup_pad_at[m])
			l = m + 1;
		else
			return true;
	}
	return false;
}

/*
 * Does instruction @idx call bpf_throw()? A JIT asks this per instruction so
 * that it can spill the throwing frame's BPF callee-saved registers before the
 * call: that frame has no BPF callee to have spilled them and never runs its
 * own epilogue, so this is the only copy the walker will find.
 *
 * It has to be asked of the table rather than of the instruction, because
 * do_misc_fixups() has resolved insn->imm from the kfunc's BTF id to an offset
 * from __bpf_call_base by the time a JIT runs, so bpf_is_throw_kfunc() no
 * longer recognises the call.
 */
bool bpf_cleanup_insn_is_throw(const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_prog_aux *aux = prog->aux;
	u32 l = 0, r = aux->nr_cleanup_throw_at;

	while (l < r) {
		u32 m = l + (r - l) / 2;

		if (idx < aux->cleanup_throw_at[m])
			r = m;
		else if (idx > aux->cleanup_throw_at[m])
			l = m + 1;
		else
			return true;
	}
	return false;
}
