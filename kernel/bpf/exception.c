// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include "exception.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

BTF_ID_LIST_SINGLE(bpf_unwind_id, func, bpf_unwind)
BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

int bpf_exc_check_callback(struct bpf_verifier_env *env, int subprog)
{
	if (!env->subprog_info[subprog].might_unwind)
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

/* Is an unwind in flight: is this frame a landing pad, or below one? */
static bool unwinding(const struct bpf_verifier_state *state)
{
	u32 i;

	for (i = 0; i <= state->curframe; i++)
		if (state->frame[i]->in_pad)
			return true;
	return false;
}

int bpf_exc_check_insn(struct bpf_verifier_env *env, struct bpf_insn *insn)
{
	bool in_pad = cur_func(env)->in_pad;
	struct bpf_insn_aux_data *aux;
	u32 i = env->insn_idx;
	const char *why = NULL;

	if (unwinding(env->cur_state)) {
		if (bpf_is_unwind_kfunc(insn)) {
			verbose(env, "insn %u starts a second unwind while one is in flight\n", i);
			return -EINVAL;
		}
		if (bpf_pseudo_call(insn)) {
			int subprog = bpf_find_subprog(env, i + insn->imm + 1);

			if (subprog >= 0 && bpf_subprog_is_global(env, subprog) &&
			    env->subprog_info[subprog].might_unwind) {
				verbose(env,
					"insn %u calls global subprog %d, which can unwind while an unwind is in flight\n",
					i, subprog);
				return -EINVAL;
			}
		}
	}

	aux = &env->insn_aux_data[i];

	if (in_pad ? aux->outside_cleanup_pad : aux->in_cleanup_pad) {
		verbose(env, "insn %u runs both inside and outside a landing pad\n", i);
		return -EINVAL;
	}
	if (in_pad)
		aux->in_cleanup_pad = true;
	else
		aux->outside_cleanup_pad = true;

	if (!in_pad)
		return 0;

	if (insn->code == (BPF_JMP | BPF_EXIT)) {
		verbose(env,
			"exit at insn %u ends a landing pad: a catch pad is not supported yet, only cleanup pads that resume\n",
			i);
		return -EOPNOTSUPP;
	}
	if (bpf_helper_call(insn) && insn->imm == BPF_FUNC_tail_call)
		why = "is a tail call, which replaces the frame";
	else if (BPF_CLASS(insn->code) == BPF_LD &&
		 (BPF_MODE(insn->code) == BPF_ABS || BPF_MODE(insn->code) == BPF_IND))
		why = "is a BPF_LD_[ABS|IND], which can leave through the epilogue";
	else if (insn->code == (BPF_JMP | BPF_JA | BPF_X) ||
		 insn->code == (BPF_JMP32 | BPF_JA | BPF_X))
		why = "is an indirect jump";

	if (!why)
		return 0;

	verbose(env, "insn %u %s, and is in a landing pad\n", i, why);
	return -EINVAL;
}

int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}

/*
 * The record covering @ip, which is a return address: the call it belongs to
 * is the instruction before it, so a range matches on begin < ip <= end.
 */
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
