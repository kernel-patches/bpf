/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef _LINUX_BPF_EXCEPTION_H
#define _LINUX_BPF_EXCEPTION_H

#include <linux/types.h>

struct bpf_cleanup_info;
struct bpf_cleanup_range;
struct bpf_prog;
struct bpf_prog_aux;
struct bpf_verifier_env;

int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env);
int bpf_check_cleanup_exceptions(struct bpf_verifier_env *env);
int bpf_cleanup_check_callback(struct bpf_verifier_env *env, int subprog);
int bpf_cleanup_pad_of_call(struct bpf_verifier_env *env, u32 idx);
int bpf_cleanup_alloc_info(struct bpf_prog_aux *aux);
int bpf_cleanup_attach_info(struct bpf_prog_aux *aux, struct bpf_cleanup_info *recs, u32 cnt);
const struct bpf_cleanup_range *bpf_cleanup_pad_for_ip(const struct bpf_prog *prog, u64 ip);

#endif /* _LINUX_BPF_EXCEPTION_H */
