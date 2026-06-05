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

struct bpf_map;
struct btf;
struct btf_type;

void bpf_diag_format_btf_type(char *buf, size_t size,
			      const struct btf_type *type,
			      const char *type_name);

struct bpf_diag_reg_snapshot {
	u32 type;
	const struct bpf_map *map_ptr;
	const struct btf *btf;
	u32 btf_id;
	bool var_off_known;
	s64 var_off_value;
	u64 var_off_mask;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
};

enum bpf_diag_reg_mod_reason {
	BPF_DIAG_REG_MOD_WRITE,
	BPF_DIAG_REG_MOD_REF_RELEASE,
	BPF_DIAG_REG_MOD_PKT_DATA_CHANGE,
};

struct bpf_diag_history_event {
	u32 insn_idx;
	u8 kind;
	union {
		struct {
			bool cond_true;
		} branch;
		struct {
			u32 frameno;
			u8 dst_reg;
			u8 src_reg;
			u8 opcode;
			bool src_valid;
			u8 reason;
			struct bpf_diag_reg_snapshot old, new;
		} reg;
		struct {
			u32 frameno;
			u8 slot;
			u8 reason;
			struct bpf_diag_reg_snapshot old, new;
		} stack_arg;
		struct {
			u32 ref_id;
		} ref;
		struct {
			u8 kind;
			bool enter;
			u32 depth;
		} ctx;
	};
};

#define BPF_DIAG_HISTORY_MAX 1024

enum bpf_diag_history_kind {
	BPF_DIAG_HISTORY_BRANCH,
	BPF_DIAG_HISTORY_REG_MOD,
	BPF_DIAG_HISTORY_STACK_ARG,
	BPF_DIAG_HISTORY_REF_ACQUIRE,
	BPF_DIAG_HISTORY_REF_RELEASE,
	BPF_DIAG_HISTORY_CONTEXT,
};

enum bpf_diag_history_scope {
	BPF_DIAG_HISTORY_SCOPE_ALL,
	BPF_DIAG_HISTORY_SCOPE_REG,
	BPF_DIAG_HISTORY_SCOPE_STACK_ARG,
	BPF_DIAG_HISTORY_SCOPE_REF,
	BPF_DIAG_HISTORY_SCOPE_CONTEXT,
};

enum bpf_diag_context_kind {
	BPF_DIAG_CONTEXT_NONE,
	BPF_DIAG_CONTEXT_RCU,
	BPF_DIAG_CONTEXT_PREEMPT,
	BPF_DIAG_CONTEXT_IRQ,
	BPF_DIAG_CONTEXT_LOCK,
};

enum bpf_diag_stack_arg_reason {
	BPF_DIAG_STACK_ARG_WRITE,
	BPF_DIAG_STACK_ARG_REF_RELEASE,
	BPF_DIAG_STACK_ARG_PKT_DATA_CHANGE,
};

enum bpf_diag_invalid_deref_kind {
	BPF_DIAG_DEREF_SCALAR,
	BPF_DIAG_DEREF_NULLABLE_PTR,
	BPF_DIAG_DEREF_MODIFIED_PTR,
	BPF_DIAG_DEREF_INVALID_PTR,
};

enum bpf_diag_mem_bounds_kind {
	BPF_DIAG_MEM_NEGATIVE_MIN,
	BPF_DIAG_MEM_MIN_OUT_OF_RANGE,
	BPF_DIAG_MEM_UNBOUNDED,
	BPF_DIAG_MEM_MAX_OUT_OF_RANGE,
};

struct bpf_diag_history_opts {
	enum bpf_diag_history_scope scope;
	u32 frameno;
	int regno;
	int stack_arg_slot;
	u32 ref_id;
	enum bpf_diag_context_kind ctx_kind;
};

struct bpf_verifier_env;
struct bpf_reg_state;
struct bpf_verifier_state;

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
void bpf_diag_report_register_type(struct bpf_verifier_env *env,
				   u32 insn_idx, int regno,
				   const char *problem, const char *reason,
				   const char *suggestion);
void bpf_diag_report_invalid_deref(struct bpf_verifier_env *env, u32 insn_idx,
				   int regno, const char *reg_name,
				   const char *type_name,
				   enum bpf_diag_invalid_deref_kind kind,
				   s64 offset);
void bpf_diag_report_unreadable_reg(struct bpf_verifier_env *env,
				    u32 insn_idx, int regno);
void bpf_diag_report_stack_arg_uninit(struct bpf_verifier_env *env,
				      u32 insn_idx, int nargs,
				      int stack_arg_slot,
				      const char *callee_name);
void bpf_diag_report_memory(struct bpf_verifier_env *env, u32 insn_idx,
			    const char *problem, const char *reason,
			    const char *suggestion);
void bpf_diag_report_mem_bounds(struct bpf_verifier_env *env, u32 insn_idx,
				int regno, const char *reg_name,
				const char *type_name,
				enum bpf_diag_mem_bounds_kind kind,
				int off, int size, u32 mem_size,
				const struct bpf_reg_state *reg);
void bpf_diag_report_resource_state(struct bpf_verifier_env *env,
				    u32 insn_idx, const char *problem,
				    const char *reason,
				    const char *suggestion);
void bpf_diag_report_ref_leak(struct bpf_verifier_env *env, u32 ref_id,
			      u32 alloc_insn, u32 fail_insn);
void bpf_diag_report_call_type(struct bpf_verifier_env *env, u32 insn_idx,
			       int regno, const char *call_name,
			       const char *arg_name, const char *reason,
			       const char *suggestion);
void bpf_diag_report_execution_context(struct bpf_verifier_env *env,
				       u32 insn_idx, const char *operation,
				       enum bpf_diag_context_kind ctx_kind,
				       const char *context,
				       const char *suggestion);
void bpf_diag_report_context_still_active(struct bpf_verifier_env *env,
					  u32 insn_idx, const char *operation,
					  enum bpf_diag_context_kind ctx_kind,
					  const char *context,
					  const char *suggestion);
void bpf_diag_report_context_underflow(struct bpf_verifier_env *env,
				       u32 insn_idx, const char *operation,
				       enum bpf_diag_context_kind ctx_kind,
				       const char *suggestion);

void bpf_diag_clear_history(struct bpf_verifier_state *state);
void bpf_diag_copy_history(struct bpf_verifier_state *dst,
			   const struct bpf_verifier_state *src);
void bpf_diag_record_branch(struct bpf_verifier_state *state, u32 insn_idx,
			    bool cond_true);
void bpf_diag_record_reg_mod(struct bpf_verifier_state *state, u32 insn_idx,
			     u8 dst_reg, bool src_valid, u8 src_reg, u8 opcode,
			     const struct bpf_reg_state *old_reg,
			     const struct bpf_reg_state *new_reg);
void bpf_diag_record_reg_invalidate(struct bpf_verifier_state *state,
				    u32 insn_idx, u8 dst_reg,
				    enum bpf_diag_reg_mod_reason reason,
				    const struct bpf_reg_state *old_reg,
				    const struct bpf_reg_state *new_reg);
void bpf_diag_record_stack_arg(struct bpf_verifier_state *state, u32 insn_idx,
			       u32 frameno, u8 slot,
			       enum bpf_diag_stack_arg_reason reason,
			       const struct bpf_reg_state *old_reg,
			       const struct bpf_reg_state *new_reg);
void bpf_diag_record_ref_acquire(struct bpf_verifier_state *state, u32 insn_idx,
				 u32 ref_id);
void bpf_diag_record_ref_release(struct bpf_verifier_state *state, u32 insn_idx,
				 u32 ref_id);
void bpf_diag_record_context(struct bpf_verifier_state *state, u32 insn_idx,
			     enum bpf_diag_context_kind ctx_kind, bool enter,
			     u32 depth);
void bpf_diag_print_history(struct bpf_verifier_env *env,
			    const struct bpf_diag_history_opts *opts);

#endif /* __BPF_DIAGNOSTICS_H */
