/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 Facebook */
/* Copyright (c) 2021, Oracle and/or its affiliates. */

#ifndef _LINUX_BTF_COMMON_H
#define _LINUX_BTF_COMMON_H 1

/* Definitions and functions common to libbpf and kernel; current use case
 * is to facilitate compilation of btf_show_common.c both for the kernel
 * and libbpf; this allows us to share the code supporting display of BTF
 * data between kernel and userspace.
 */
#include <linux/types.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>

#define BITS_PER_U128 (sizeof(u64) * BITS_PER_BYTE * 2)
#define BITS_PER_BYTE_MASK (BITS_PER_BYTE - 1)
#define BITS_PER_BYTE_MASKED(bits) ((bits) & BITS_PER_BYTE_MASK)
#define BITS_ROUNDDOWN_BYTES(bits) ((bits) >> 3)
#define BITS_ROUNDUP_BYTES(bits) \
	(BITS_ROUNDDOWN_BYTES(bits) + !!BITS_PER_BYTE_MASKED(bits))

struct btf;
struct btf_member;
struct btf_type;
struct btf_show;

#ifdef __KERNEL__

const char *btf_str_by_offset(const struct btf *btf, u32 offset);
void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
		       struct seq_file *m);
int btf_type_seq_show_flags(const struct btf *btf, u32 type_id, void *obj,
			    struct seq_file *m, u64 flags);

/* For kernel u64 is long long unsigned int... */
#define FMT64		"ll"

#else
/* ...while for userspace it is long unsigned int.  These definitions avoid
 * format specifier warnings.
 */
#define FMT64		"l"

/* libbpf names differ slightly to in-kernel function names. */
#define btf_type_by_id		btf__type_by_id
#define btf_name_by_offset	btf__name_by_offset
#define btf_str_by_offset	btf__str_by_offset
#define btf_resolve_size	btf__resolve_size

#endif /* __KERNEL__ */
/*
 * Options to control show behaviour.
 *	- BTF_SHOW_COMPACT: no formatting around type information
 *	- BTF_SHOW_NONAME: no struct/union member names/types
 *	- BTF_SHOW_PTR_RAW: show raw (unobfuscated) pointer values;
 *	  equivalent to %px.
 *	- BTF_SHOW_ZERO: show zero-valued struct/union members; they
 *	  are not displayed by default
 *	- BTF_SHOW_UNSAFE: skip use of bpf_probe_read() to safely read
 *	  data before displaying it.
 */
#define BTF_SHOW_COMPACT	BTF_F_COMPACT
#define BTF_SHOW_NONAME		BTF_F_NONAME
#define BTF_SHOW_PTR_RAW	BTF_F_PTR_RAW
#define BTF_SHOW_ZERO		BTF_F_ZERO
#define BTF_SHOW_UNSAFE		(1ULL << 4)

/*
 * Copy len bytes of string representation of obj of BTF type_id into buf.
 *
 * @btf: struct btf object
 * @type_id: type id of type obj points to
 * @obj: pointer to typed data
 * @buf: buffer to write to
 * @len: maximum length to write to buf
 * @flags: show options (see above)
 *
 * Return: length that would have been/was copied as per snprintf, or
 *	   negative error.
 */
int btf_type_snprintf_show(const struct btf *btf, u32 type_id, void *obj,
			   char *buf, int len, u64 flags);

#define for_each_member(i, struct_type, member)			\
	for (i = 0, member = btf_type_member(struct_type);	\
	     i < btf_type_vlen(struct_type);			\
	     i++, member++)

#define for_each_vsi(i, datasec_type, member)			\
	for (i = 0, member = btf_type_var_secinfo(datasec_type);	\
	     i < btf_type_vlen(datasec_type);			\
	     i++, member++)

static inline bool btf_type_is_ptr(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_PTR;
}

static inline bool btf_type_is_int(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_INT;
}

static inline bool btf_type_is_small_int(const struct btf_type *t)
{
	return btf_type_is_int(t) && t->size <= sizeof(u64);
}

static inline bool btf_type_is_enum(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_ENUM;
}

static inline bool btf_type_is_typedef(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_TYPEDEF;
}

static inline bool btf_type_is_func(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_FUNC;
}

static inline bool btf_type_is_func_proto(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_FUNC_PROTO;
}

static inline bool btf_type_is_var(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_VAR;
}

/* union is only a special case of struct:
 * all its offsetof(member) == 0
 */
static inline bool btf_type_is_struct(const struct btf_type *t)
{
	u8 kind = BTF_INFO_KIND(t->info);

	return kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION;
}

static inline bool btf_type_is_modifier(const struct btf_type *t)
{
	/* Some of them is not strictly a C modifier
	 * but they are grouped into the same bucket
	 * for BTF concern:
	 *   A type (t) that refers to another
	 *   type through t->type AND its size cannot
	 *   be determined without following the t->type.
	 *
	 * ptr does not fall into this bucket
	 * because its size is always sizeof(void *).
	 */
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
		return true;
	default:
		return false;
	}
}

static inline
const struct btf_type *btf_type_skip_modifiers(const struct btf *btf,
					       u32 id, u32 *res_id)
{
	const struct btf_type *t = btf_type_by_id(btf, id);

	while (btf_type_is_modifier(t)) {
		id = t->type;
		t = btf_type_by_id(btf, t->type);
	}

	if (res_id)
		*res_id = id;

	return t;
}

static inline u32 btf_type_int(const struct btf_type *t)
{
	return *(u32 *)(t + 1);
}

static inline const struct btf_array *btf_type_array(const struct btf_type *t)
{
	return (const struct btf_array *)(t + 1);
}

static inline const struct btf_enum *btf_type_enum(const struct btf_type *t)
{
	return (const struct btf_enum *)(t + 1);
}

static inline const struct btf_var *btf_type_var(const struct btf_type *t)
{
	return (const struct btf_var *)(t + 1);
}

static inline u16 btf_type_vlen(const struct btf_type *t)
{
	return BTF_INFO_VLEN(t->info);
}

static inline u16 btf_func_linkage(const struct btf_type *t)
{
	return BTF_INFO_VLEN(t->info);
}

/* size can be used */
static inline bool btf_type_has_size(const struct btf_type *t)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM:
	case BTF_KIND_DATASEC:
		return true;
	default:
		return false;
	}
}

static inline const struct btf_member *btf_type_member(const struct btf_type *t)
{
	return (const struct btf_member *)(t + 1);
}

static inline const struct btf_var_secinfo *btf_type_var_secinfo(
		const struct btf_type *t)
{
	return (const struct btf_var_secinfo *)(t + 1);
}

static inline const char *__btf_name_by_offset(const struct btf *btf,
					       u32 offset)
{
	const char *name;

	if (!offset)
		return "(anon)";

	name = btf_str_by_offset(btf, offset);
	return name ?: "(invalid-name-offset)";
}

/* functions shared between btf.c and btf_show_common.c */
void btf_type_ops_show(const struct btf *btf, const struct btf_type *t,
		       __u32 type_id, void *obj, u8 bits_offset,
		       struct btf_show *show);
void btf_df_show(const struct btf *btf, const struct btf_type *t,
		 u32 type_id, void *data, u8 bits_offset,
		 struct btf_show *show);
void btf_int_show(const struct btf *btf, const struct btf_type *t,
		  u32 type_id, void *data, u8 bits_offset,
		  struct btf_show *show);
void btf_modifier_show(const struct btf *btf, const struct btf_type *t,
		       u32 type_id, void *data, u8 bits_offset,
		       struct btf_show *show);
void btf_var_show(const struct btf *btf, const struct btf_type *t,
		  u32 type_id, void *data, u8 bits_offset,
		  struct btf_show *show);
void btf_ptr_show(const struct btf *btf, const struct btf_type *t,
		  u32 type_id, void *data, u8 bits_offset,
		  struct btf_show *show);
void btf_array_show(const struct btf *btf, const struct btf_type *t,
		    u32 type_id, void *data, u8 bits_offset,
		    struct btf_show *show);
void btf_struct_show(const struct btf *btf, const struct btf_type *t,
		     u32 type_id, void *data, u8 bits_offset,
		     struct btf_show *show);
void btf_enum_show(const struct btf *btf, const struct btf_type *t,
		   u32 type_id, void *data, u8 bits_offset,
		   struct btf_show *show);
void btf_datasec_show(const struct btf *btf, const struct btf_type *t,
		      u32 type_id, void *data, u8 bits_offset,
		      struct btf_show *show);

#endif
