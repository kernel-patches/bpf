/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/bpf.h>
#include <linux/compiler_attributes.h>
#include <linux/types.h>

struct bpf_reference_state;
struct bpf_reg_state;
struct bpf_verifier_env;
struct bpf_verifier_state;
struct btf;

const char *bpf_diag_fmt_s64_sum(struct bpf_verifier_env *env, s64 value, int addend);
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

enum bpf_diag_context_kind {
	BPF_DIAG_CONTEXT_NONE,
	BPF_DIAG_CONTEXT_RCU,
	BPF_DIAG_CONTEXT_PREEMPT,
	BPF_DIAG_CONTEXT_IRQ,
	BPF_DIAG_CONTEXT_LOCK,
};

enum bpf_diag_invalid_deref_kind {
	BPF_DIAG_DEREF_SCALAR,
	BPF_DIAG_DEREF_NULLABLE_PTR,
	BPF_DIAG_DEREF_MODIFIED_PTR,
	BPF_DIAG_DEREF_INVALID_PTR,
};

bool bpf_diag_enabled(const struct bpf_verifier_env *env);
int bpf_diag_init(struct bpf_verifier_env *env);
char *bpf_diag_fmt_buf(struct bpf_verifier_env *env, size_t size);
const char *bpf_diag_vfmt(struct bpf_verifier_env *env, const char *fmt, va_list args)
	__printf(2, 0);
const char *bpf_diag_fmt(struct bpf_verifier_env *env, const char *fmt, ...) __printf(2, 3);
const char *bpf_diag_fmt_btf_type(struct bpf_verifier_env *env, const struct btf *btf, u32 type_id);
const char *bpf_diag_reg_type_plain(struct bpf_verifier_env *env, enum bpf_reg_type type);
u32 bpf_diag_event_log_pos(struct bpf_verifier_env *env);
void bpf_diag_event_log_reset(struct bpf_verifier_env *env, u32 pos);
u32 bpf_diag_irq_depth(const struct bpf_verifier_state *state);
void bpf_diag_free(struct bpf_verifier_env *env);
void bpf_diag_header(struct bpf_verifier_env *env, const char *category,
			    const char *problem);
void bpf_diag_source(struct bpf_verifier_env *env, u32 insn_idx, const char *label,
			    const char *fmt, ...) __printf(4, 5);
void bpf_diag_register_type(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				   const char *problem, const char *reason, const char *suggestion);
void bpf_diag_invalid_deref(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				   const char *reg_name, const struct bpf_reg_state *reg,
				   enum bpf_diag_invalid_deref_kind kind, s64 offset);
void bpf_diag_unreadable_reg(struct bpf_verifier_env *env, u32 insn_idx, int regno);
void bpf_diag_stack_arg_uninit(struct bpf_verifier_env *env, u32 insn_idx, int nargs,
				      int stack_arg_slot, const char *callee_name,
				      const char *arg_name);
void bpf_diag_memory(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
			    const char *reason, const char *suggestion);
void bpf_diag_mem_bounds(struct bpf_verifier_env *env, u32 insn_idx, int regno,
				const char *reg_name, const char *type_name, const char *proof,
				int off, int size, u32 mem_size, const struct bpf_reg_state *reg);
void bpf_diag_res(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		  const char *reason, const char *suggestion);
void bpf_diag_lock(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		   const char *reason, const char *suggestion,
		   const struct bpf_reference_state *active_lock);
void bpf_diag_irq(struct bpf_verifier_env *env, u32 insn_idx, const char *problem,
		  const char *reason, const char *suggestion, u32 depth);
void bpf_diag_leak(struct bpf_verifier_env *env, u32 ref_id, u32 alloc_insn, u32 fail_insn);
void bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx, bool cond_true);
void bpf_diag_mod_begin(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			const struct bpf_reg_state *origin, enum bpf_diag_mod_reason reason);
void bpf_diag_mod_end(struct bpf_verifier_env *env);
void bpf_diag_record_scrub(struct bpf_verifier_env *env, const struct bpf_reg_state *reg,
			   enum bpf_diag_mod_reason reason);
void bpf_diag_record_scrub_stack(struct bpf_verifier_env *env, u32 frameno, s16 min_off,
				 s16 max_off, enum bpf_diag_mod_reason reason);
void bpf_diag_record_ref_acquire(struct bpf_verifier_env *env, u32 insn_idx, u32 ref_id);
void bpf_diag_record_ref_release(struct bpf_verifier_env *env, u32 insn_idx, u32 ref_id);
void bpf_diag_record_context(struct bpf_verifier_env *env, u32 insn_idx,
			     enum bpf_diag_context_kind ctx_kind, bool enter, u32 depth);

#endif /* __BPF_DIAGNOSTICS_H */
