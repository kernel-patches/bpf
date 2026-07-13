/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/compiler_attributes.h>
#include <linux/types.h>

struct bpf_reg_state;
struct bpf_verifier_env;
struct btf;

void bpf_diag_format_btf_type(char *buf, size_t size, const struct btf *btf, u32 type_id);

enum bpf_diag_mod_reason {
	BPF_DIAG_MOD_WRITE,
	BPF_DIAG_MOD_SPILL,
	BPF_DIAG_MOD_VAR_WRITE,
	BPF_DIAG_MOD_REF_RELEASE,
	BPF_DIAG_MOD_PKT_DATA_CHANGE,
	BPF_DIAG_MOD_NON_OWN_REF,
	BPF_DIAG_MOD_CALLER_SAVED,
};

enum bpf_diag_mod_target_kind {
	BPF_DIAG_MOD_TARGET_NONE,
	BPF_DIAG_MOD_TARGET_REG,
	BPF_DIAG_MOD_TARGET_STACK_ARG,
	BPF_DIAG_MOD_TARGET_STACK_SLOT,
	BPF_DIAG_MOD_TARGET_STACK_RANGE,
};

struct bpf_diag_mod_target {
	union {
		struct {
			s16 min_off;
			s16 max_off;
		} range;
		u16 spi;
		u8 regno;
		u8 stack_arg;
	};
	u8 frameno;
	u8 kind;
};

static inline struct bpf_diag_mod_target bpf_diag_reg_target(u32 frameno, u8 regno)
{
	return (struct bpf_diag_mod_target){
		.frameno = frameno,
		.kind = BPF_DIAG_MOD_TARGET_REG,
		.regno = regno,
	};
}

static inline struct bpf_diag_mod_target bpf_diag_stack_arg_target(u32 frameno, u8 slot)
{
	return (struct bpf_diag_mod_target){
		.frameno = frameno,
		.kind = BPF_DIAG_MOD_TARGET_STACK_ARG,
		.stack_arg = slot,
	};
}

static inline struct bpf_diag_mod_target bpf_diag_stack_slot_target(u32 frameno, u16 spi)
{
	return (struct bpf_diag_mod_target){
		.frameno = frameno,
		.kind = BPF_DIAG_MOD_TARGET_STACK_SLOT,
		.spi = spi,
	};
}

static inline struct bpf_diag_mod_target bpf_diag_stack_range_target(u32 frameno, s16 min_off,
								     s16 max_off)
{
	return (struct bpf_diag_mod_target){
		.frameno = frameno,
		.kind = BPF_DIAG_MOD_TARGET_STACK_RANGE,
		.range.min_off = min_off,
		.range.max_off = max_off,
	};
}

bool bpf_diag_enabled(const struct bpf_verifier_env *env);
int bpf_diag_init(struct bpf_verifier_env *env);
char *bpf_diag_scratch_buf(struct bpf_verifier_env *env, unsigned int slot, size_t *size);
struct bpf_reg_state *bpf_diag_reg_scratch(struct bpf_verifier_env *env, unsigned int slot);
const char *bpf_diag_scratch_strcpy(struct bpf_verifier_env *env, unsigned int slot,
				    const char *str);
const char *bpf_diag_scratch_printf(struct bpf_verifier_env *env, unsigned int slot,
				    const char *fmt, ...) __printf(3, 4);
const char *bpf_diag_format_btf_type_scratch(struct bpf_verifier_env *env, unsigned int slot,
					     const struct btf *btf, u32 type_id);
u32 bpf_diag_event_log_pos(struct bpf_verifier_env *env);
void bpf_diag_event_log_reset(struct bpf_verifier_env *env, u32 pos);
int bpf_diag_error(const struct bpf_verifier_env *env);
void bpf_diag_free(struct bpf_verifier_env *env);
void bpf_diag_report_header(struct bpf_verifier_env *env, const char *category,
			    const char *problem);
void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx, const char *label,
			    const char *fmt, ...) __printf(4, 5);
int bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx, bool cond_true);
void bpf_diag_record_mod(struct bpf_verifier_env *env, u32 insn_idx,
			 struct bpf_diag_mod_target target, enum bpf_diag_mod_reason reason,
			 const struct bpf_reg_state *old_reg, const struct bpf_reg_state *new_reg,
			 const struct bpf_diag_mod_target *origin);
void bpf_diag_record_ref_acquire(struct bpf_verifier_env *env, u32 insn_idx, u32 ref_id);
void bpf_diag_record_ref_release(struct bpf_verifier_env *env, u32 insn_idx, u32 ref_id);

#endif /* __BPF_DIAGNOSTICS_H */
