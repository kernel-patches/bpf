/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook */
/* Internal BTF header for kernel/btf/ */

#ifndef _KERNEL_BTF_BTF_H
#define _KERNEL_BTF_BTF_H

#include <linux/types.h>
#include <linux/btf.h>
#include <linux/bpf_verifier.h>
#include <linux/module.h>
#include <linux/rculist.h>

/* Forward declarations */
struct btf_show;
struct btf_struct_metas;

/* btf_verifier_env and its dependencies (needed by both btf.c and bpf.c) */
enum verifier_phase {
	CHECK_META,
	CHECK_TYPE,
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum resolve_mode {
	RESOLVE_TBD,	/* To Be Determined */
	RESOLVE_PTR,	/* Resolving for Pointer */
	RESOLVE_STRUCT_OR_ARRAY,	/* Resolving for struct/union
					 * or array
					 */
};

#define MAX_RESOLVE_DEPTH 32

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[MAX_RESOLVE_DEPTH];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

#ifdef CONFIG_BPF_SYSCALL
struct btf_kfunc_set_tab;
struct btf_id_dtor_kfunc_tab;
struct btf_struct_ops_tab;
#endif

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types; /* includes VOID for base BTF */
	u32 named_start_id;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
#ifdef CONFIG_BPF_SYSCALL
	u32 id;
	struct rcu_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf_id_dtor_kfunc_tab *dtor_kfunc_tab;
	struct btf_struct_metas *struct_meta_tab;
	struct btf_struct_ops_tab *struct_ops_tab;
#endif

	/* split BTF support */
	struct btf *base_btf;
	u32 start_id; /* first type ID in this BTF (0 for base BTF) */
	u32 start_str_off; /* first string offset (0 for base BTF) */
	char name[MODULE_NAME_LEN];
	bool kernel_btf;
	__u32 *base_id_map; /* map from distilled base BTF -> vmlinux BTF ids */
};

#define BITS_PER_BYTE_MASK (BITS_PER_BYTE - 1)
#define BITS_PER_BYTE_MASKED(bits) ((bits) & BITS_PER_BYTE_MASK)
#define BITS_ROUNDDOWN_BYTES(bits) ((bits) >> 3)
#define BITS_ROUNDUP_BYTES(bits) \
	(BITS_ROUNDDOWN_BYTES(bits) + !!BITS_PER_BYTE_MASKED(bits))

/* 16MB for 64k structs and each has 16 members and
 * a few MB spaces for the string section.
 * The hard limit is S32_MAX.
 */
#define BTF_MAX_SIZE (16 * 1024 * 1024)

/*
 * The suffix of a type that indicates it cannot alias another type when
 * comparing BTF IDs for kfunc invocations.
 */
#define NOCAST_ALIAS_SUFFIX		"___init"

/* Core BTF functions needed by bpf.c */
const char *__btf_name_by_offset(const struct btf *btf, u32 offset);
const struct btf_type *
__btf_resolve_size(const struct btf *btf, const struct btf_type *type,
		   u32 *type_size, const struct btf_type **elem_type,
		   u32 *elem_id, u32 *total_nelems, u32 *type_id);
int btf_check_all_metas(struct btf_verifier_env *env);
void btf_check_sorted(struct btf *btf);
int btf_check_type_tags(struct btf_verifier_env *env,
			struct btf *btf, int start_id);
void btf_free(struct btf *btf);
struct btf *btf_parse_base(struct btf_verifier_env *env, const char *name,
			  void *data, unsigned int data_size);
int btf_parse_hdr(struct btf_verifier_env *env);
int btf_parse_str_sec(struct btf_verifier_env *env);
int btf_parse_type_sec(struct btf_verifier_env *env);
const struct btf_decl_tag *btf_type_decl_tag(const struct btf_type *t);
bool btf_type_has_size(const struct btf_type *t);
bool btf_type_is_datasec(const struct btf_type *t);
bool btf_type_is_decl_tag(const struct btf_type *t);
bool btf_type_is_modifier(const struct btf_type *t);
void btf_verifier_env_free(struct btf_verifier_env *env);

extern const char * const btf_kind_str[NR_BTF_KINDS];

/* Weak symbols - overridden by bpf.c when CONFIG_BPF_SYSCALL=y */
void btf_free_bpf_data(struct btf *btf);
void btf_put_bpf(struct btf *btf);

#endif /* _KERNEL_BTF_BTF_H */
