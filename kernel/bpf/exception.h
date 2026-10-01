/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __BPF_EXCEPTION_H
#define __BPF_EXCEPTION_H

#include <linux/bpfptr.h>
#include <linux/types.h>

union bpf_attr;
struct bpf_verifier_env;
struct bpf_verifier_state;
struct bpf_func_state;
struct bpf_insn;

int bpf_exc_check_info(struct bpf_verifier_env *env, const union bpf_attr *attr,
		       bpfptr_t uattr);
int bpf_exc_prepare(struct bpf_verifier_env *env);
int bpf_exc_check_prog(struct bpf_verifier_env *env);
bool bpf_prog_may_unwind(const struct bpf_verifier_env *env);
void bpf_exc_record_frame_entry(const struct bpf_verifier_state *state,
				struct bpf_func_state *frame, u32 id_gen);
int bpf_exc_check_frame_balance(struct bpf_verifier_env *env, const char *prefix);
int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx);
bool bpf_is_unwind_kfunc(const struct bpf_insn *insn);
bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn);
int bpf_exc_check_callback(struct bpf_verifier_env *env, int subprog);
int bpf_exc_check_insn(struct bpf_verifier_env *env, struct bpf_insn *insn);

#endif /* __BPF_EXCEPTION_H */
