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

bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn)
{
	return insn_is_exc_kfunc(insn, EXC_KF_bpf_unwind_resume);
}

int bpf_cleanup_pad_of_call(struct bpf_verifier_env *env, u32 idx)
{
	u32 pad = env->insn_aux_data[idx].cleanup_pad;

	return pad ? (int)pad - 1 : -1;
}
