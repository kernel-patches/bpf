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

enum exc_kfunc {
	EXC_KF_bpf_unwind_resume,
};

BTF_ID_LIST(exc_kfunc_list)
BTF_ID(func, bpf_unwind_resume)

static bool insn_is_exc_kfunc(const struct bpf_insn *insn, int kf)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == exc_kfunc_list[kf];
}

/* What an instruction does to intra-subprog control flow. */
enum cleanup_insn_kind {
	CLEANUP_INSN_PLAIN,	/* the next insn runs */
	CLEANUP_INSN_JUMP,	/* unconditional jump */
	CLEANUP_INSN_COND,	/* the next insn runs, or the branch target */
	CLEANUP_INSN_EXIT,
	CLEANUP_INSN_THROW,	/* call bpf_throw: nothing after it runs */
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
	u8 *reach;		/* per insn: CLEANUP_REACH_* mask */
	u32 *stack;		/* per insn: DFS stack */
	void *scratch;		/* the one allocation all of the above live in */
};

static bool in_pad(struct bpf_verifier_env *env, u32 i)
{
	return env->insn_aux_data[i].in_cleanup_pad;
}

/* One scratch array for cleanup_alloc() to hand out. */
struct cleanup_alloc_req {
	void **dst;
	size_t n, sz;
};

static void *cleanup_alloc(const struct cleanup_alloc_req *tab, u32 cnt)
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

static int cleanup_subprog_of(struct bpf_verifier_env *env, u32 off)
{
	struct bpf_subprog_info *info = bpf_find_containing_subprog(env, off);

	return info ? info - env->subprog_info : -1;
}

/* The subprogram a linear pass is currently in. */
struct cleanup_cursor {
	u32 start, end;		/* [start, end) of the current subprogram */
	int sub;		/* its index */
};

#define CLEANUP_CURSOR_INIT { .sub = -1 }

static void cleanup_cursor_to(struct bpf_verifier_env *env, struct cleanup_cursor *c, u32 i)
{
	while (i >= c->end) {
		c->sub++;
		c->start = env->subprog_info[c->sub].start;
		c->end = env->subprog_info[c->sub + 1].start;
	}
}

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
		*next = -1;
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

static void cleanup_mark_kfunc_sites(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		struct bpf_insn *insn = &env->prog->insnsi[i];

		if (bpf_is_throw_kfunc(insn))
			env->insn_aux_data[i].cleanup_throw_site = true;
		else if (insn_is_exc_kfunc(insn, EXC_KF_bpf_unwind_resume))
			env->insn_aux_data[i].cleanup_resume_site = true;
	}
}

int bpf_cleanup_check_callback(struct bpf_verifier_env *env, int subprog)
{
	if (!env->cleanup_info_cnt || !env->subprog_info[subprog].might_throw)
		return 0;

	verbose(env, "subprog %d may unwind and is used as a callback\n", subprog);
	return -EINVAL;
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

static void cleanup_add_pred(u32 *head, u32 *link, u32 to, u32 e)
{
	link[e] = head[to];
	head[to] = e + 1;
}

/* What every instruction can reach along intra-subprog edges, for
 * cleanup_pad_is_catch(). One backward walk over a predecessor index, rather
 * than a forward walk from each landing pad, which would be quadratic.
 */
static int cleanup_reachability(struct cleanup_ctx *ctx)
{
	struct bpf_verifier_env *env = ctx->env;
	u32 len = env->prog->len;
	struct cleanup_cursor c = CLEANUP_CURSOR_INIT;
	u32 *head = NULL, *link = NULL;
	bool *queued = NULL;
	u32 i, sp = 0;
	void *scratch;
	const struct cleanup_alloc_req tab[] = {
		{ (void **)&head,   len,             sizeof(*head) },
		{ (void **)&link,   2 * (size_t)len, sizeof(*link) },
		{ (void **)&queued, len,             sizeof(*queued) },
	};

	scratch = cleanup_alloc(tab, ARRAY_SIZE(tab));
	if (!scratch)
		return -ENOMEM;

	/* Index the predecessors, and seed the walk at the terminators. */
	for (i = 0; i < len; i++) {
		enum cleanup_insn_kind kind;
		int next, target;

		cleanup_cursor_to(env, &c, i);
		kind = cleanup_succ(env, i, c.start, c.end, &next, &target);

		if (kind == CLEANUP_INSN_RESUME)
			ctx->reach[i] |= CLEANUP_REACH_RESUME;
		else if (kind == CLEANUP_INSN_EXIT)
			ctx->reach[i] |= CLEANUP_REACH_EXIT;
		else if (kind == CLEANUP_INSN_GOTOX)
			ctx->reach[i] |= CLEANUP_REACH_UNKNOWN;
		else if (kind == CLEANUP_INSN_THROW)
			ctx->reach[i] |= CLEANUP_REACH_THROW;

		if (next >= 0)
			cleanup_add_pred(head, link, next, 2 * i);
		if (target >= 0)
			cleanup_add_pred(head, link, target, 2 * i + 1);

		if (ctx->reach[i]) {
			queued[i] = true;
			ctx->stack[sp++] = i;
		}
	}

	/* Each instruction re-enters the worklist at most once per bit it
	 * gains, so this is linear in the number of edges.
	 */
	while (sp) {
		u32 j = ctx->stack[--sp];
		u8 flags = ctx->reach[j];
		u32 e;

		queued[j] = false;
		for (e = head[j]; e; e = link[e - 1]) {
			u32 p = (e - 1) / 2;

			if ((ctx->reach[p] | flags) == ctx->reach[p])
				continue;
			ctx->reach[p] |= flags;
			if (!queued[p]) {
				queued[p] = true;
				ctx->stack[sp++] = p;
			}
		}
	}
	kvfree(scratch);
	return 0;
}

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

static int cleanup_check_pad_insn(struct bpf_verifier_env *env, u32 i)
{
	struct bpf_insn *insn = &env->prog->insnsi[i];

	if (bpf_helper_call(insn) && insn->imm == BPF_FUNC_tail_call) {
		verbose(env,
			"bpf_tail_call() at insn %u is in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	/* A failed BPF_LD_[ABS|IND] leaves the frame through its epilogue. */
	if (BPF_CLASS(insn->code) == BPF_LD &&
	    (BPF_MODE(insn->code) == BPF_ABS || BPF_MODE(insn->code) == BPF_IND)) {
		verbose(env,
			"BPF_LD_[ABS|IND] at insn %u is in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	/* Stack arguments are not supported. */
	if (is_stack_arg_st(insn) || is_stack_arg_stx(insn)) {
		verbose(env,
			"insn %u passes an on-stack call argument in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	/* Likewise, stack arguments are not supported. */
	if (bpf_pseudo_kfunc_call(insn)) {
		struct bpf_call_summary cs;

		if (bpf_get_call_summary(env, insn, &cs) &&
		    cs.arg_slot_cnt > MAX_BPF_FUNC_REG_ARGS) {
			verbose(env,
				"insn %u passes an on-stack call argument in an exception cleanup landing pad\n",
				i);
			return -EINVAL;
		}
	}
	return 0;
}

static int cleanup_mark_pad_bodies(struct cleanup_ctx *ctx)
{
	struct bpf_verifier_env *env = ctx->env;
	u32 i, sp = 0;
	int ret;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		u32 pad = env->cleanup_info[i].landing_pad_off;

		if (in_pad(env, pad))
			continue;

		ret = cleanup_pad_is_catch(ctx, pad);
		if (ret < 0)
			return ret;
		if (ret) {
			verbose(env,
				"catch landing pad %u is not supported yet, only cleanup pads that resume\n",
				pad);
			return -EOPNOTSUPP;
		}
		env->insn_aux_data[pad].in_cleanup_pad = true;
		ctx->stack[sp++] = pad;
	}

	while (sp) {
		u32 j = ctx->stack[--sp];
		enum cleanup_insn_kind kind;
		int next, target, sub;
		u32 start, end;

		ret = cleanup_check_pad_insn(env, j);
		if (ret)
			return ret;

		sub = cleanup_subprog_of(env, j);
		start = env->subprog_info[sub].start;
		end = env->subprog_info[sub + 1].start;
		kind = cleanup_succ(env, j, start, end, &next, &target);

		if (kind == CLEANUP_INSN_CALL) {
			int callee = cleanup_subprog_of(env, j + env->prog->insnsi[j].imm + 1);

			if (env->subprog_info[callee].might_throw) {
				verbose(env,
					"cleanup landing pad calls subprog %d at insn %u, which can throw while an exception is in flight\n",
					callee, j);
				return -EINVAL;
			}
		}

		if (next >= 0 && !in_pad(env, next)) {
			env->insn_aux_data[next].in_cleanup_pad = true;
			ctx->stack[sp++] = next;
		}
		if (target >= 0 && !in_pad(env, target)) {
			env->insn_aux_data[target].in_cleanup_pad = true;
			ctx->stack[sp++] = target;
		}
	}
	return 0;
}

static int cleanup_check_resumes(struct cleanup_ctx *ctx)
{
	struct bpf_verifier_env *env = ctx->env;
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		if (!insn_is_exc_kfunc(&env->prog->insnsi[i], EXC_KF_bpf_unwind_resume))
			continue;
		if (in_pad(env, i))
			continue;
		verbose(env,
			"bpf_unwind_resume() at insn %u is not in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	return 0;
}

static void cleanup_mark_call_sites(struct bpf_verifier_env *env)
{
	u32 i, j;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		struct bpf_cleanup_info *rec = &env->cleanup_info[i];

		for (j = rec->begin_off; j < rec->end_off; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];

			if (!bpf_pseudo_call(insn) && !bpf_is_throw_kfunc(insn))
				continue;
			env->insn_aux_data[j].cleanup_pad = rec->landing_pad_off + 1;
		}
	}
}

int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env)
{
	if (!env->cleanup_info_cnt)
		return 0;

	if (bpf_prog_is_offloaded(env->prog->aux)) {
		verbose(env,
			"exception cleanup is not supported for offloaded programs\n");
		return -EINVAL;
	}

	if (!bpf_jit_supports_cleanup_pads() || !env->prog->jit_requested) {
		verbose(env,
			"exception cleanup needs a JIT that can dispatch landing pads\n");
		return -EOPNOTSUPP;
	}
	env->prog->jit_required = 1;

	if (env->exception_callback_subprog) {
		verbose(env,
			"exception cleanup table cannot be combined with an exception callback\n");
		return -EINVAL;
	}

	cleanup_mark_kfunc_sites(env);
	cleanup_mark_call_sites(env);
	return 0;
}

int bpf_check_cleanup_exceptions(struct bpf_verifier_env *env)
{
	u32 len = env->prog->len;
	struct cleanup_ctx ctx = { .env = env };
	const struct cleanup_alloc_req tab[] = {
		{ (void **)&ctx.reach, len, sizeof(*ctx.reach) },
		{ (void **)&ctx.stack, len, sizeof(*ctx.stack) },
	};
	int ret;

	if (!env->cleanup_info_cnt)
		return 0;

	ctx.scratch = cleanup_alloc(tab, ARRAY_SIZE(tab));
	if (!ctx.scratch)
		return -ENOMEM;

	ret = cleanup_reachability(&ctx);
	if (ret)
		goto out;

	ret = cleanup_mark_pad_bodies(&ctx);
	if (ret)
		goto out;

	ret = cleanup_check_resumes(&ctx);
out:
	kvfree(ctx.scratch);
	return ret;
}

bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return insn_is_exc_kfunc(insn, EXC_KF_bpf_unwind_resume);
}

int bpf_cleanup_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}
