// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bitmap.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bsearch.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include "exception.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

BTF_ID_LIST_SINGLE(bpf_unwind_id, func, bpf_unwind)
BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

int bpf_exc_check_callback(struct bpf_verifier_env *env, int subprog)
{
	/*
	 * An unwind out of a callback stops at the helper's own frame, which
	 * is C and has no landing pad, so the helper would carry on as though
	 * nothing had happened. Refuse it, the way a throw out of one is.
	 */
	if (!env->subprog_info[subprog].might_unwind &&
	    (!env->cleanup_info_cnt || !env->subprog_info[subprog].might_throw))
		return 0;

	verbose(env, "subprog %d may unwind and is used as a callback\n", subprog);
	return -EINVAL;
}

static void mark_call_sites(struct bpf_verifier_env *env)
{
	u32 i, j;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		struct bpf_cleanup_info *rec = &env->cleanup_info[i];

		for (j = rec->begin_off; j < rec->end_off; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];

			if (!bpf_pseudo_call(insn) && !bpf_is_unwind_kfunc(insn))
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

	mark_call_sites(env);
	return 0;
}

bool bpf_is_unwind_kfunc(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == bpf_unwind_id[0];
}

bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == bpf_unwind_resume_id[0];
}

/*
 * A cleanup pad ends in bpf_unwind_resume(): the frame returns, and the return
 * address bpf_unwind() wrote carries the unwind to the next pad. A catch pad
 * does not -- it rejoins the function, which keeps running -- so the unwind
 * must stop at that frame, before it rewrites the return addresses above it.
 * Tell the two apart by what the pad can reach.
 */
static int classify_pad(struct bpf_verifier_env *env, u32 pad)
{
	bool saw_resume = false, saw_exit = false;
	u32 sp = 0, *stack;
	bool *seen;
	int ret = 0;

	seen = kvcalloc(env->prog->len, sizeof(*seen), GFP_KERNEL_ACCOUNT);
	stack = kvcalloc(env->prog->len, sizeof(*stack), GFP_KERNEL_ACCOUNT);
	if (!seen || !stack) {
		ret = -ENOMEM;
		goto out;
	}

	stack[sp++] = pad;
	seen[pad] = true;
	while (sp) {
		u32 t = stack[--sp];
		struct bpf_insn *insn = &env->prog->insnsi[t];
		struct bpf_iarray *succ;
		bool abnormal;
		u32 i;

		if (bpf_is_unwind_resume_kfunc(insn)) {
			saw_resume = true;
			continue;
		}
		if (insn->code == (BPF_JMP | BPF_EXIT)) {
			saw_exit = true;
			continue;
		}
		/*
		 * A BPF_LD_[ABS|IND] and a tail call each carry a hidden edge
		 * to their subprogram's exit. That is a failed load or a
		 * missing tail call target leaving early, not the pad
		 * rejoining the function, so it says nothing about whether
		 * the pad resumes -- follow only the fall-through.
		 */
		abnormal = (BPF_CLASS(insn->code) == BPF_LD &&
			    (BPF_MODE(insn->code) == BPF_ABS ||
			     BPF_MODE(insn->code) == BPF_IND)) ||
			   (bpf_helper_call(insn) && insn->imm == BPF_FUNC_tail_call);

		succ = bpf_insn_successors(env, t);
		if (IS_ERR(succ)) {
			ret = PTR_ERR(succ);
			goto out;
		}
		for (i = 0; i < succ->cnt; i++) {
			u32 w = succ->items[i];

			if (abnormal && w != t + 1)
				continue;
			if (w >= env->prog->len || seen[w])
				continue;
			seen[w] = true;
			stack[sp++] = w;
		}
	}

	if (saw_exit) {
		verbose(env,
			"landing pad at insn %u can return without resuming: a catch pad is not supported yet, only cleanup pads that resume\n",
			pad);
		ret = -EOPNOTSUPP;
		goto out;
	}
	if (!saw_resume) {
		verbose(env, "landing pad at insn %u neither resumes nor returns\n", pad);
		ret = -EINVAL;
		goto out;
	}
out:
	kvfree(stack);
	kvfree(seen);
	return ret;
}

int bpf_exc_classify_pads(struct bpf_verifier_env *env)
{
	u32 i;
	int err;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		err = classify_pad(env, env->cleanup_info[i].landing_pad_off);
		if (err)
			return err;
	}
	return 0;
}

int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}

const struct bpf_cleanup_range *bpf_exc_pad_for_ip(const struct bpf_prog *prog, u64 ip)
{
	const struct bpf_exception_info *exc = prog->aux->exc;
	u32 l = 0, r = exc ? exc->nr_ranges : 0;

	while (l < r) {
		u32 m = l + (r - l) / 2;
		const struct bpf_cleanup_range *rec = &exc->ranges[m];

		if (ip <= rec->begin)
			r = m;
		else if (ip > rec->end)
			l = m + 1;
		else
			return rec;
	}
	return NULL;
}

int bpf_exc_alloc_info(struct bpf_prog_aux *aux)
{
	if (aux->exc)
		return 0;
	aux->exc = kzalloc_obj(struct bpf_exception_info, GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	return aux->exc ? 0 : -ENOMEM;
}

int bpf_exc_attach_info(struct bpf_prog_aux *aux, struct bpf_cleanup_info *recs, u32 cnt)
{
	struct bpf_exception_info *exc = aux->exc;
	struct bpf_cleanup_range *ranges;

	ranges = kvcalloc(cnt, sizeof(*ranges), GFP_KERNEL_ACCOUNT | __GFP_NOWARN);
	if (!ranges) {
		kvfree(recs);
		return -ENOMEM;
	}

	exc->info = recs;
	exc->nr_info = cnt;
	exc->ranges = ranges;
	/* Withheld until the JIT has filled the table in. */
	exc->nr_ranges = 0;
	return 0;
}

void bpf_exc_fill_native_ranges(struct bpf_prog *prog, u32 *addrs, void *image)
{
	struct bpf_exception_info *exc = prog->aux->exc;
	u32 i, n;

	if (!exc || !exc->nr_info || !exc->ranges)
		return;

	n = exc->nr_info;
	for (i = 0; i < n; i++) {
		const struct bpf_cleanup_info *rec = &exc->info[i];

		if (WARN_ON_ONCE(rec->begin_off >= prog->len ||
				 rec->end_off > prog->len ||
				 rec->landing_pad_off >= prog->len))
			return;
		exc->ranges[i].begin = (u64)(long)image + addrs[rec->begin_off];
		exc->ranges[i].end = (u64)(long)image + addrs[rec->end_off];
		exc->ranges[i].pad = (u64)(long)image + addrs[rec->landing_pad_off];
	}
	exc->nr_ranges = n;
}

void bpf_exc_free_info(struct bpf_prog_aux *aux)
{
	struct bpf_exception_info *exc = aux->exc;

	if (!exc)
		return;
	kvfree(exc->ranges);
	kvfree(exc->info);
	kfree(exc);
	aux->exc = NULL;
}

static const struct bpf_insn_aux_data *subprog_insn_aux(const struct bpf_verifier_env *env,
							const struct bpf_prog *prog, u32 idx)
{
	if (!env || !prog->aux->exc)
		return NULL;
	return &env->insn_aux_data[idx + prog->aux->subprog_start];
}

bool bpf_exc_insn_is_pad(const struct bpf_verifier_env *env,
			 const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_insn_aux_data *aux = subprog_insn_aux(env, prog, idx);

	return aux && aux->cleanup_pad_head;
}
