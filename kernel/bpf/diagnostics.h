// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/compiler_attributes.h>

struct bpf_verifier_env;

void bpf_diag_report_header(struct bpf_verifier_env *env,
			    const char *category, const char *problem);
void bpf_diag_report_reason(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);
void bpf_diag_report_section(struct bpf_verifier_env *env, const char *title);
void bpf_diag_report_suggestion(struct bpf_verifier_env *env, const char *fmt, ...)
	__printf(2, 3);

#endif /* __BPF_DIAGNOSTICS_H */
