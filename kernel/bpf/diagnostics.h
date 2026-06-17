/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#ifndef __BPF_DIAGNOSTICS_H
#define __BPF_DIAGNOSTICS_H

#include <linux/compiler_attributes.h>
#include <linux/cnum.h>
#include <linux/tnum.h>
#include <linux/types.h>

struct bpf_map;
struct bpf_reg_state;
struct bpf_verifier_env;
struct btf;
struct btf_type;

void bpf_diag_format_btf_type(char *buf, size_t size, const struct btf *btf,
			      u32 type_id);

struct bpf_diag_reg_snapshot {
	u32 type;
	const struct bpf_map *map_ptr;
	const struct btf *btf;
	u32 btf_id;
	struct tnum var_off;
	struct cnum64 r64;
};

enum bpf_diag_reg_mod_reason {
	BPF_DIAG_REG_MOD_WRITE,
	BPF_DIAG_REG_MOD_REF_RELEASE,
	BPF_DIAG_REG_MOD_PKT_DATA_CHANGE,
	BPF_DIAG_REG_MOD_NON_OWN_REF,
};

enum bpf_diag_stack_arg_reason {
	BPF_DIAG_STACK_ARG_WRITE,
	BPF_DIAG_STACK_ARG_REF_RELEASE,
	BPF_DIAG_STACK_ARG_PKT_DATA_CHANGE,
	BPF_DIAG_STACK_ARG_NON_OWN_REF,
};

enum bpf_diag_stack_slot_reason {
	BPF_DIAG_STACK_SLOT_SPILL,
	BPF_DIAG_STACK_SLOT_WRITE,
	BPF_DIAG_STACK_SLOT_REF_RELEASE,
	BPF_DIAG_STACK_SLOT_PKT_DATA_CHANGE,
	BPF_DIAG_STACK_SLOT_NON_OWN_REF,
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
			bool stack_slot_valid;
			u8 reason;
			u32 stack_frameno;
			u16 stack_spi;
			struct bpf_diag_reg_snapshot old, new;
		} reg;
		struct {
			u32 frameno;
			u8 slot;
			u8 reason;
			struct bpf_diag_reg_snapshot old, new;
		} stack_arg;
		struct {
			u32 frameno;
			u16 spi;
			u8 reason;
			struct bpf_diag_reg_snapshot old, new;
		} stack_slot;
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

enum bpf_diag_history_kind {
	BPF_DIAG_HISTORY_BRANCH,
	BPF_DIAG_HISTORY_REG_MOD,
	BPF_DIAG_HISTORY_STACK_ARG,
	BPF_DIAG_HISTORY_STACK_SLOT,
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
	u32 ctx_depth;
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
const char *bpf_diag_format_btf_type_scratch(struct bpf_verifier_env *env,
					     unsigned int slot,
					     const struct btf *btf,
					     u32 type_id);
u64 bpf_diag_event_log_pos(struct bpf_verifier_env *env);
void bpf_diag_event_log_reset(struct bpf_verifier_env *env, u64 pos);
void bpf_diag_free(struct bpf_verifier_env *env);
void bpf_diag_report_header(struct bpf_verifier_env *env,
			    const char *category, const char *problem);
void bpf_diag_report_source(struct bpf_verifier_env *env, u32 insn_idx,
			    const char *label, const char *fmt, ...)
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
void bpf_diag_record_branch(struct bpf_verifier_env *env, u32 insn_idx,
			    bool cond_true);
void bpf_diag_record_reg_mod(struct bpf_verifier_env *env, u32 insn_idx,
			     u32 frameno, u8 dst_reg, bool src_valid,
			     u8 src_reg, u8 opcode,
			     const struct bpf_reg_state *old_reg,
			     const struct bpf_reg_state *new_reg);
void bpf_diag_record_reg_stack_fill(struct bpf_verifier_env *env, u32 insn_idx,
				    u32 frameno, u8 dst_reg, u32 stack_frameno,
				    u16 stack_spi, bool src_valid, u8 src_reg,
				    u8 opcode,
				    const struct bpf_reg_state *old_reg,
				    const struct bpf_reg_state *new_reg);
void bpf_diag_record_reg_invalidate(struct bpf_verifier_env *env, u32 insn_idx,
				    u32 frameno, u8 dst_reg,
				    enum bpf_diag_reg_mod_reason reason,
				    const struct bpf_reg_state *old_reg,
				    const struct bpf_reg_state *new_reg);
void bpf_diag_record_stack_arg(struct bpf_verifier_env *env, u32 insn_idx,
			       u32 frameno, u8 slot,
			       enum bpf_diag_stack_arg_reason reason,
			       const struct bpf_reg_state *old_reg,
			       const struct bpf_reg_state *new_reg);
void bpf_diag_record_stack_slot(struct bpf_verifier_env *env, u32 insn_idx,
				u32 frameno, u16 spi,
				enum bpf_diag_stack_slot_reason reason,
				const struct bpf_reg_state *old_reg,
				const struct bpf_reg_state *new_reg);
void bpf_diag_record_ref_acquire(struct bpf_verifier_env *env, u32 insn_idx,
				 u32 ref_id);
void bpf_diag_record_ref_release(struct bpf_verifier_env *env, u32 insn_idx,
				 u32 ref_id);
void bpf_diag_record_context(struct bpf_verifier_env *env, u32 insn_idx,
			     enum bpf_diag_context_kind ctx_kind, bool enter,
			     u32 depth);
void bpf_diag_print_history(struct bpf_verifier_env *env,
			    const struct bpf_diag_history_opts *opts);

#endif /* __BPF_DIAGNOSTICS_H */
