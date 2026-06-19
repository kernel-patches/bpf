/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/compiler_attributes.h>
#include <linux/types.h>

struct bpf_verifier_env;

struct bpf_diag_history_event {
	u32 insn_idx;
	u8 kind;
	union {
		struct {
			bool cond_true;
		} branch;
	};
};

enum bpf_diag_history_kind {
	BPF_DIAG_HISTORY_BRANCH,
};

bool bpf_diag_enabled(const struct bpf_verifier_env *env);
char *bpf_diag_scratch_buf(struct bpf_verifier_env *env,
			   unsigned int slot, size_t *size);
const char *bpf_diag_scratch_strcpy(struct bpf_verifier_env *env,
				    unsigned int slot,
				    const char *str);
const char *bpf_diag_scratch_printf(struct bpf_verifier_env *env,
				    unsigned int slot,
				    const char *fmt, ...)
	__printf(3, 4);
u64 bpf_diag_event_log_pos(struct bpf_verifier_env *env);
void bpf_diag_event_log_reset(struct bpf_verifier_env *env, u64 pos);
void bpf_diag_free(struct bpf_verifier_env *env);
void bpf_diag_report_header(struct bpf_verifier_env *env,
			    const char *category, const char *problem);
void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx,
			    const char *label, const char *fmt, ...)
	__printf(4, 5);
void bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx,
			    bool cond_true);
void bpf_diag_print_history(struct bpf_verifier_env *env);

#endif /* __BPF_DIAGNOSTICS_H */
