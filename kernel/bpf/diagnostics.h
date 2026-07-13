/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/compiler_attributes.h>
#include <linux/types.h>

struct bpf_verifier_env;

bool bpf_diag_enabled(const struct bpf_verifier_env *env);
int bpf_diag_init(struct bpf_verifier_env *env);
char *bpf_diag_scratch_buf(struct bpf_verifier_env *env, unsigned int slot, size_t *size);
const char *bpf_diag_scratch_strcpy(struct bpf_verifier_env *env, unsigned int slot,
				    const char *str);
const char *bpf_diag_scratch_printf(struct bpf_verifier_env *env, unsigned int slot,
				    const char *fmt, ...) __printf(3, 4);
void bpf_diag_free(struct bpf_verifier_env *env);
void bpf_diag_report_header(struct bpf_verifier_env *env, const char *category,
			    const char *problem);
void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx, const char *label,
			    const char *fmt, ...) __printf(4, 5);

#endif /* __BPF_DIAGNOSTICS_H */
