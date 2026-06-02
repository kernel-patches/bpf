// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/compiler_attributes.h>
#include <linux/types.h>

enum bpf_diag_category {
	BPF_DIAG_CATEGORY_MEMORY_SAFETY,
	BPF_DIAG_CATEGORY_REGISTER_TYPE_SAFETY,
	BPF_DIAG_CATEGORY_CALL_TYPE_SAFETY,
	BPF_DIAG_CATEGORY_RESOURCE_LIFETIME_SAFETY,
	BPF_DIAG_CATEGORY_EXECUTION_CONTEXT_SAFETY,
	BPF_DIAG_CATEGORY_PROGRAM_STRUCTURE,
	BPF_DIAG_CATEGORY_POLICY,
	BPF_DIAG_CATEGORY_VERIFIER_LIMIT,
	BPF_DIAG_CATEGORY_VERIFIER_INTERNAL_ERROR,
};

struct bpf_verifier_env;

void bpf_diag_report_header(struct bpf_verifier_env *env,
			    enum bpf_diag_category category,
			    const char *problem);
void bpf_diag_report_reason(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);
void bpf_diag_report_section(struct bpf_verifier_env *env, const char *title);
void bpf_diag_report_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);
void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx,
			    char marker, const char *fmt, ...)
	__printf(4, 5);

#endif /* __BPF_DIAGNOSTICS_H */
