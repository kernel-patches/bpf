/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */
#ifndef _LINUX_BPF_EXCEPTION_H
#define _LINUX_BPF_EXCEPTION_H

#include <linux/types.h>

struct bpf_verifier_env;

int bpf_prepare_cleanup_exceptions(struct bpf_verifier_env *env);
int bpf_check_cleanup_exceptions(struct bpf_verifier_env *env);
int bpf_cleanup_check_callback(struct bpf_verifier_env *env, int subprog);
int bpf_cleanup_pad_of_call(struct bpf_verifier_env *env, u32 idx);

#endif /* _LINUX_BPF_EXCEPTION_H */
