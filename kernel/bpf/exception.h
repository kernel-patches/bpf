/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef __BPF_EXCEPTION_H
#define __BPF_EXCEPTION_H

#include <linux/bpfptr.h>
#include <linux/types.h>

union bpf_attr;
struct bpf_verifier_env;
struct bpf_insn;
struct bpf_cleanup_info;
struct bpf_cleanup_range;
struct bpf_prog;
struct bpf_prog_aux;

int bpf_exc_check_info(struct bpf_verifier_env *env, const union bpf_attr *attr,
		       bpfptr_t uattr);
void bpf_exc_mark_call_sites(struct bpf_verifier_env *env);
int bpf_exc_check_prog(struct bpf_verifier_env *env);
bool bpf_prog_may_unwind(const struct bpf_verifier_env *env);
int bpf_exc_pad_of_call(struct bpf_verifier_env *env, u32 idx);
bool bpf_is_unwind_kfunc(const struct bpf_insn *insn);
bool bpf_is_unwind_resume_kfunc(const struct bpf_insn *insn);
int bpf_exc_check_callback(struct bpf_verifier_env *env, int subprog);
int bpf_exc_check_insn(struct bpf_verifier_env *env, struct bpf_insn *insn);
int bpf_exc_attach_info(struct bpf_prog_aux *aux, struct bpf_cleanup_info *recs, u32 cnt);
const struct bpf_cleanup_range *bpf_exc_pad_for_ip(const struct bpf_prog *prog, u64 ip);

#endif /* __BPF_EXCEPTION_H */
