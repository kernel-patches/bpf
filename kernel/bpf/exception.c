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

static void cleanup_mark_throw_sites(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++)
		if (bpf_is_throw_kfunc(&env->prog->insnsi[i]))
			env->insn_aux_data[i].cleanup_throw_site = true;
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

	cleanup_mark_throw_sites(env);
	cleanup_mark_call_sites(env);
	return 0;
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
