/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef _LINUX_BPF_EXCEPTION_H
#define _LINUX_BPF_EXCEPTION_H

#include <linux/types.h>

struct bpf_verifier_env;
struct bpf_verifier_state;
struct bpf_func_state;
struct bpf_insn;

int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env);
int bpf_exc_check_prog(struct bpf_verifier_env *env);
bool bpf_prog_may_unwind(const struct bpf_verifier_env *env);
void bpf_exc_record_frame_entry(const struct bpf_verifier_state *state,
				struct bpf_func_state *frame, u32 id_gen);
int bpf_exc_check_frame_balance(struct bpf_verifier_env *env, const char *prefix);
int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx);
int bpf_exc_check_callback(struct bpf_verifier_env *env, int subprog);
int bpf_exc_check_insn(struct bpf_verifier_env *env, struct bpf_insn *insn);

#endif /* _LINUX_BPF_EXCEPTION_H */
