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

BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

static void mark_kfunc_sites(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		struct bpf_insn *insn = &env->prog->insnsi[i];

		if (bpf_is_throw_kfunc(insn))
			env->insn_aux_data[i].throw_call = true;
		else if (bpf_is_unwind_resume_kfunc(insn))
			env->insn_aux_data[i].resume_call = true;
	}
}

int bpf_exc_check_callback(struct bpf_verifier_env *env, int subprog)
{
	if (!env->cleanup_info_cnt || !env->subprog_info[subprog].might_throw)
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

	mark_kfunc_sites(env);
	mark_call_sites(env);
	return 0;
}

int bpf_exc_check_insn(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	struct bpf_verifier_state *state = env->cur_state;
	struct bpf_insn_aux_data *aux;
	u32 i = env->insn_idx;
	bool in_pad;

	aux = &env->insn_aux_data[i];
	in_pad = state->unwinding && state->curframe == state->unwind_frameno;

	if (in_pad ? aux->outside_cleanup_pad : aux->in_cleanup_pad) {
		verbose(env,
			"insn %u runs both inside and outside an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	if (in_pad)
		aux->in_cleanup_pad = true;
	else
		aux->outside_cleanup_pad = true;

	if (!state->unwinding)
		return 0;

	if (bpf_is_throw_kfunc(insn)) {
		verbose(env,
			"bpf_throw() at insn %u throws while an exception is in flight\n",
			i);
		return -EINVAL;
	}
	if (bpf_pseudo_call(insn)) {
		int subprog = bpf_find_subprog(env, i + insn->imm + 1);

		if (subprog >= 0 && bpf_subprog_is_global(env, subprog) &&
		    env->subprog_info[subprog].might_throw) {
			verbose(env,
				"insn %u calls global subprog %d, which can throw while an exception is in flight\n",
				i, subprog);
			return -EINVAL;
		}
	}

	if (!in_pad)
		return 0;

	if (insn->code == (BPF_JMP | BPF_EXIT)) {
		verbose(env,
			"exit at insn %u ends an exception cleanup landing pad: a catch pad is not supported yet, only cleanup pads that resume\n",
			i);
		return -EOPNOTSUPP;
	}
	if (bpf_helper_call(insn) && insn->imm == BPF_FUNC_tail_call) {
		verbose(env,
			"bpf_tail_call() at insn %u is in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	if (insn->code == (BPF_JMP | BPF_JA | BPF_X) ||
	    insn->code == (BPF_JMP32 | BPF_JA | BPF_X)) {
		verbose(env,
			"indirect jump at insn %u is in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	/* A BPF_LD_[ABS|IND] can leave the frame through its epilogue. */
	if (BPF_CLASS(insn->code) == BPF_LD &&
	    (BPF_MODE(insn->code) == BPF_ABS || BPF_MODE(insn->code) == BPF_IND)) {
		verbose(env,
			"BPF_LD_[ABS|IND] at insn %u is in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	if (is_stack_arg_st(insn) || is_stack_arg_stx(insn)) {
		verbose(env,
			"insn %u stages an on-stack call argument in an exception cleanup landing pad\n",
			i);
		return -EINVAL;
	}
	if (bpf_pseudo_kfunc_call(insn)) {
		struct bpf_call_summary cs;

		if (bpf_get_call_summary(env, insn, &cs) &&
		    cs.arg_slot_cnt > MAX_BPF_FUNC_REG_ARGS) {
			verbose(env,
				"insn %u calls a kfunc with an on-stack argument in an exception cleanup landing pad\n",
				i);
			return -EINVAL;
		}
	}
	return 0;
}

bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return bpf_pseudo_kfunc_call(insn) && insn->off == 0 &&
	       insn->imm == bpf_unwind_resume_id[0];
}

int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}

/*
 * Every subprogram of a cleanup-carrying program spills the BPF callee-saved
 * registers, even one that never throws: a frame's spill holds its caller's
 * registers, and that is what the walker restores before running the caller's
 * pad. The exception callback does not, because it reuses the boundary frame
 * rather than building one of its own.
 */
bool bpf_exc_force_spill(const struct bpf_prog *prog)
{
	return prog->aux->exc && !prog->aux->exception_cb;
}

bool bpf_exc_needs_throw_spill(const struct bpf_prog *prog)
{
	return bpf_exc_force_spill(prog) && prog->aux->exc->has_throw;
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

bool bpf_exc_insn_is_throw(const struct bpf_verifier_env *env,
			       const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_insn_aux_data *aux = subprog_insn_aux(env, prog, idx);

	return aux && aux->throw_call;
}

bool bpf_exc_insn_is_resume(const struct bpf_verifier_env *env,
				const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_insn_aux_data *aux = subprog_insn_aux(env, prog, idx);

	return aux && aux->resume_call;
}

bool bpf_exc_insn_in_pad(const struct bpf_verifier_env *env,
			     const struct bpf_prog *prog, u32 idx)
{
	const struct bpf_insn_aux_data *aux = subprog_insn_aux(env, prog, idx);

	return aux && aux->in_cleanup_pad;
}
