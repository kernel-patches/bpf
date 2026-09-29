// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include "exception.h"

#define verbose(env, fmt, args...) bpf_verifier_log_write(env, fmt, ##args)

BTF_ID_LIST_SINGLE(bpf_unwind_id, func, bpf_unwind)
BTF_ID_LIST_SINGLE(bpf_unwind_resume_id, func, bpf_unwind_resume)

static int reject_throw(struct bpf_verifier_env *env)
{
	u32 i;

	for (i = 0; i < env->prog->len; i++) {
		if (!bpf_is_throw_kfunc(&env->prog->insnsi[i]))
			continue;
		verbose(env,
			"exception cleanup table cannot be combined with bpf_throw at insn %u\n",
			i);
		return -EINVAL;
	}
	return 0;
}

static int mark_call_sites(struct bpf_verifier_env *env)
{
	u32 i, j;

	for (i = 0; i < env->cleanup_info_cnt; i++) {
		struct bpf_cleanup_info *rec = &env->cleanup_info[i];

		for (j = rec->begin_off; j < rec->end_off; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];

			if (!bpf_pseudo_call(insn) && !bpf_is_callx(insn) &&
			    !bpf_is_unwind_kfunc(insn))
				continue;
			env->insn_aux_data[j].cleanup_pad = rec->landing_pad_off + 1;
		}
	}
	return 0;
}

int bpf_exc_check_prog(struct bpf_verifier_env *env)
{
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
	if (env->ops->gen_epilogue) {
		verbose(env,
			"exception cleanup is not supported for a program with an epilogue\n");
		return -EOPNOTSUPP;
	}
	env->prog->jit_required = 1;
	return 0;
}

int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env)
{
	int err;

	if (!env->cleanup_info_cnt)
		return 0;

	err = bpf_exc_check_prog(env);
	if (err)
		return err;

	if (env->exception_callback_subprog) {
		verbose(env,
			"exception cleanup table cannot be combined with an exception callback\n");
		return -EINVAL;
	}

	err = reject_throw(env);
	if (err)
		return err;

	return mark_call_sites(env);
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

int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}
