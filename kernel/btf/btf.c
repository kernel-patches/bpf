// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2018 Facebook */

#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/types.h>
#include <linux/seq_file.h>
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/kernel.h>
#include <linux/sort.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bsearch.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/overflow.h>
#include "btf.h"

#ifndef CONFIG_BPF_SYSCALL
/*
 * When CONFIG_BPF_SYSCALL is not set, log.c is not compiled, so
 * bpf_verifier_vlog() is unavailable. Provide a simple implementation
 * that handles the BPF_LOG_KERNEL case (pr_err), which is the only
 * log level used by the core BTF verifier for kernel BTF parsing.
 */
void bpf_verifier_vlog(struct bpf_verifier_log *log, const char *fmt,
		       va_list args)
{
	char buf[256];

	vscnprintf(buf, sizeof(buf), fmt, args);
	if (log->level == BPF_LOG_KERNEL)
		pr_err("BPF: %s", buf);
}

__printf(2, 3) void bpf_log(struct bpf_verifier_log *log,
			    const char *fmt, ...)
{
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}
#endif /* !CONFIG_BPF_SYSCALL */

/* BTF (BPF Type Format) is the meta data format which describes
 * the data types of BPF program/map.  Hence, it basically focus
 * on the C programming language which the modern BPF is primary
 * using.
 *
 * ELF Section:
 * ~~~~~~~~~~~
 * The BTF data is stored under the ".BTF" ELF section
 *
 * struct btf_type:
 * ~~~~~~~~~~~~~~~
 * Each 'struct btf_type' object describes a C data type.
 * Depending on the type it is describing, a 'struct btf_type'
 * object may be followed by more data.  F.e.
 * To describe an array, 'struct btf_type' is followed by
 * 'struct btf_array'.
 *
 * 'struct btf_type' and any extra data following it are
 * 4 bytes aligned.
 *
 * Type section:
 * ~~~~~~~~~~~~~
 * The BTF type section contains a list of 'struct btf_type' objects.
 * Each one describes a C type.  Recall from the above section
 * that a 'struct btf_type' object could be immediately followed by extra
 * data in order to describe some particular C types.
 *
 * type_id:
 * ~~~~~~~
 * Each btf_type object is identified by a type_id.  The type_id
 * is implicitly implied by the location of the btf_type object in
 * the BTF type section.  The first one has type_id 1.  The second
 * one has type_id 2...etc.  Hence, an earlier btf_type has
 * a smaller type_id.
 *
 * A btf_type object may refer to another btf_type object by using
 * type_id (i.e. the "type" in the "struct btf_type").
 *
 * NOTE that we cannot assume any reference-order.
 * A btf_type object can refer to an earlier btf_type object
 * but it can also refer to a later btf_type object.
 *
 * For example, to describe "const void *".  A btf_type
 * object describing "const" may refer to another btf_type
 * object describing "void *".  This type-reference is done
 * by specifying type_id:
 *
 * [1] CONST (anon) type_id=2
 * [2] PTR (anon) type_id=0
 *
 * The above is the btf_verifier debug log:
 *   - Each line started with "[?]" is a btf_type object
 *   - [?] is the type_id of the btf_type object.
 *   - CONST/PTR is the BTF_KIND_XXX
 *   - "(anon)" is the name of the type.  It just
 *     happens that CONST and PTR has no name.
 *   - type_id=XXX is the 'u32 type' in btf_type
 *
 * NOTE: "void" has type_id 0
 *
 * String section:
 * ~~~~~~~~~~~~~~
 * The BTF string section contains the names used by the type section.
 * Each string is referred by an "offset" from the beginning of the
 * string section.
 *
 * Each string is '\0' terminated.
 *
 * The first character in the string section must be '\0'
 * which is used to mean 'anonymous'. Some btf_type may not
 * have a name.
 */

/* BTF verification:
 *
 * To verify BTF data, two passes are needed.
 *
 * Pass #1
 * ~~~~~~~
 * The first pass is to collect all btf_type objects to
 * an array: "btf->types".
 *
 * Depending on the C type that a btf_type is describing,
 * a btf_type may be followed by extra data.  We don't know
 * how many btf_type is there, and more importantly we don't
 * know where each btf_type is located in the type section.
 *
 * Without knowing the location of each type_id, most verifications
 * cannot be done.  e.g. an earlier btf_type may refer to a later
 * btf_type (recall the "const void *" above), so we cannot
 * check this type-reference in the first pass.
 *
 * In the first pass, it still does some verifications (e.g.
 * checking the name is a valid offset to the string section).
 *
 * Pass #2
 * ~~~~~~~
 * The main focus is to resolve a btf_type that is referring
 * to another type.
 *
 * We have to ensure the referring type:
 * 1) does exist in the BTF (i.e. in btf->types[])
 * 2) does not cause a loop:
 *	struct A {
 *		struct B b;
 *	};
 *
 *	struct B {
 *		struct A a;
 *	};
 *
 * btf_type_needs_resolve() decides if a btf_type needs
 * to be resolved.
 *
 * The needs_resolve type implements the "resolve()" ops which
 * essentially does a DFS and detects backedge.
 *
 * During resolve (or DFS), different C types have different
 * "RESOLVED" conditions.
 *
 * When resolving a BTF_KIND_STRUCT, we need to resolve all its
 * members because a member is always referring to another
 * type.  A struct's member can be treated as "RESOLVED" if
 * it is referring to a BTF_KIND_PTR.  Otherwise, the
 * following valid C struct would be rejected:
 *
 *	struct A {
 *		int m;
 *		struct A *a;
 *	};
 *
 * When resolving a BTF_KIND_PTR, it needs to keep resolving if
 * it is referring to another BTF_KIND_PTR.  Otherwise, we cannot
 * detect a pointer loop, e.g.:
 * BTF_KIND_CONST -> BTF_KIND_PTR -> BTF_KIND_CONST -> BTF_KIND_PTR +
 *                        ^                                         |
 *                        +-----------------------------------------+
 *
 */

#define BITS_PER_U128 (sizeof(u64) * BITS_PER_BYTE * 2)

#define BTF_INFO_MASK 0x9f00ffff
#define BTF_INT_MASK 0x0fffffff
#define BTF_TYPE_ID_VALID(type_id) ((type_id) <= BTF_MAX_TYPE)
#define BTF_STR_OFFSET_VALID(name_off) ((name_off) <= BTF_MAX_NAME_OFFSET)


#define for_each_member_from(i, from, struct_type, member)		\
	for (i = from, member = btf_type_member(struct_type) + from;	\
	     i < btf_type_vlen(struct_type);				\
	     i++, member++)

#define for_each_vsi_from(i, from, struct_type, member)				\
	for (i = from, member = btf_type_var_secinfo(struct_type) + from;	\
	     i < btf_type_vlen(struct_type);					\
	     i++, member++)




enum visit_state {
	NOT_VISITED,
	VISITED,
	RESOLVED,
};

struct btf_sec_info {
	u32 off;
	u32 len;
};

const char * const btf_kind_str[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
	[BTF_KIND_FUNC]		= "FUNC",
	[BTF_KIND_FUNC_PROTO]	= "FUNC_PROTO",
	[BTF_KIND_VAR]		= "VAR",
	[BTF_KIND_DATASEC]	= "DATASEC",
	[BTF_KIND_FLOAT]	= "FLOAT",
	[BTF_KIND_DECL_TAG]	= "DECL_TAG",
	[BTF_KIND_TYPE_TAG]	= "TYPE_TAG",
	[BTF_KIND_ENUM64]	= "ENUM64",
};

const char *btf_type_str(const struct btf_type *t)
{
	return btf_kind_str[BTF_INFO_KIND(t->info)];
}

/* Chunk size we use in safe copy of data to be shown. */
#define BTF_SHOW_OBJ_SAFE_SIZE		32

/*
 * This is the maximum size of a base type value (equivalent to a
 * 128-bit int); if we are at the end of our safe buffer and have
 * less than 16 bytes space we can't be assured of being able
 * to copy the next type safely, so in such cases we will initiate
 * a new copy.
 */
#define BTF_SHOW_OBJ_BASE_TYPE_SIZE	16

/* Type name size */
#define BTF_SHOW_NAME_SIZE		80


/*
 * Common data to all BTF show operations. Private show functions can add
 * their own data to a structure containing a struct btf_show and consult it
 * in the show callback.  See btf_type_show() below.
 *
 * One challenge with showing nested data is we want to skip 0-valued
 * data, but in order to figure out whether a nested object is all zeros
 * we need to walk through it.  As a result, we need to make two passes
 * when handling structs, unions and arrays; the first path simply looks
 * for nonzero data, while the second actually does the display.  The first
 * pass is signalled by show->state.depth_check being set, and if we
 * encounter a non-zero value we set show->state.depth_to_show to
 * the depth at which we encountered it.  When we have completed the
 * first pass, we will know if anything needs to be displayed if
 * depth_to_show > depth.  See btf_[struct,array]_show() for the
 * implementation of this.
 *
 * Another problem is we want to ensure the data for display is safe to
 * access.  To support this, the anonymous "struct {} obj" tracks the data
 * object and our safe copy of it.  We copy portions of the data needed
 * to the object "copy" buffer, but because its size is limited to
 * BTF_SHOW_OBJ_COPY_LEN bytes, multiple copies may be required as we
 * traverse larger objects for display.
 *
 * The various data type show functions all start with a call to
 * btf_show_start_type() which returns a pointer to the safe copy
 * of the data needed (or if BTF_SHOW_UNSAFE is specified, to the
 * raw data itself).  btf_show_obj_safe() is responsible for
 * using copy_from_kernel_nofault() to update the safe data if necessary
 * as we traverse the object's data.  skbuff-like semantics are
 * used:
 *
 * - obj.head points to the start of the toplevel object for display
 * - obj.size is the size of the toplevel object
 * - obj.data points to the current point in the original data at
 *   which our safe data starts.  obj.data will advance as we copy
 *   portions of the data.
 *
 * In most cases a single copy will suffice, but larger data structures
 * such as "struct task_struct" will require many copies.  The logic in
 * btf_show_obj_safe() handles the logic that determines if a new
 * copy_from_kernel_nofault() is needed.
 */
struct btf_show {
	u64 flags;
	void *target;	/* target of show operation (seq file, buffer) */
	__printf(2, 0) void (*showfn)(struct btf_show *show, const char *fmt, va_list args);
	const struct btf *btf;
	/* below are used during iteration */
	struct {
		u8 depth;
		u8 depth_to_show;
		u8 depth_check;
		u8 array_member:1,
		   array_terminated:1;
		u16 array_encoding;
		u32 type_id;
		int status;			/* non-zero for error */
		const struct btf_type *type;
		const struct btf_member *member;
		char name[BTF_SHOW_NAME_SIZE];	/* space for member name/type */
	} state;
	struct {
		u32 size;
		void *head;
		void *data;
		u8 safe[BTF_SHOW_OBJ_SAFE_SIZE];
	} obj;
};

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *env,
			  const struct btf_type *t,
			  u32 meta_left);
	int (*resolve)(struct btf_verifier_env *env,
		       const struct resolve_vertex *v);
	int (*check_member)(struct btf_verifier_env *env,
			    const struct btf_type *struct_type,
			    const struct btf_member *member,
			    const struct btf_type *member_type);
	int (*check_kflag_member)(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type);
	void (*log_details)(struct btf_verifier_env *env,
			    const struct btf_type *t);
	void (*show)(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offsets,
			 struct btf_show *show);
};

static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS];
static struct btf_type btf_void;

static int btf_resolve(struct btf_verifier_env *env,
		       const struct btf_type *t, u32 type_id);

static int btf_func_check(struct btf_verifier_env *env,
			  const struct btf_type *t);

bool btf_type_is_modifier(const struct btf_type *t)
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
	case BTF_KIND_TYPE_TAG:
		return true;
	}

	return false;
}

static int btf_start_id(const struct btf *btf)
{
	return btf->start_id + (btf->base_btf ? 0 : 1);
}

bool btf_type_is_void(const struct btf_type *t)
{
	return t == &btf_void;
}

bool btf_type_is_datasec(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_DATASEC;
}

bool btf_type_is_decl_tag(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_DECL_TAG;
}

static bool btf_type_nosize(const struct btf_type *t)
{
	return btf_type_is_void(t) || btf_type_is_fwd(t) ||
	       btf_type_is_func(t) || btf_type_is_func_proto(t) ||
	       btf_type_is_decl_tag(t);
}

static bool btf_type_nosize_or_null(const struct btf_type *t)
{
	return !t || btf_type_nosize(t);
}

static bool btf_type_is_decl_tag_target(const struct btf_type *t)
{
	return btf_type_is_func(t) || btf_type_is_struct(t) ||
	       btf_type_is_var(t) || btf_type_is_typedef(t);
}

bool btf_is_vmlinux(const struct btf *btf)
{
	return btf->kernel_btf && !btf->base_btf;
}

u32 btf_nr_types(const struct btf *btf)
{
	u32 total = 0;

	while (btf) {
		total += btf->nr_types;
		btf = btf->base_btf;
	}

	return total;
}

/*
 * Note that vmlinux and kernel module BTFs are always sorted
 * during the building phase.
 */
void btf_check_sorted(struct btf *btf)
{
	u32 i, n, named_start_id = 0;

	n = btf_nr_types(btf);
	if (btf_is_vmlinux(btf)) {
		for (i = btf_start_id(btf); i < n; i++) {
			const struct btf_type *t = btf_type_by_id(btf, i);
			const char *n = btf_name_by_offset(btf, t->name_off);

			if (n[0] != '\0') {
				btf->named_start_id = i;
				return;
			}
		}
		return;
	}

	for (i = btf_start_id(btf) + 1; i < n; i++) {
		const struct btf_type *ta = btf_type_by_id(btf, i - 1);
		const struct btf_type *tb = btf_type_by_id(btf, i);
		const char *na = btf_name_by_offset(btf, ta->name_off);
		const char *nb = btf_name_by_offset(btf, tb->name_off);

		if (strcmp(na, nb) > 0)
			return;

		if (named_start_id == 0 && na[0] != '\0')
			named_start_id = i - 1;
		if (named_start_id == 0 && nb[0] != '\0')
			named_start_id = i;
	}

	if (named_start_id)
		btf->named_start_id = named_start_id;
}

/*
 * btf_named_start_id - Get the named starting ID for the BTF
 * @btf: Pointer to the target BTF object
 * @own: Flag indicating whether to query only the current BTF (true = current BTF only,
 *       false = recursively traverse the base BTF chain)
 *
 * Return value rules:
 * 1. For a sorted btf, return its named_start_id
 * 2. Else for a split BTF, return its start_id
 * 3. Else for a base BTF, return 1
 */
u32 btf_named_start_id(const struct btf *btf, bool own)
{
	const struct btf *base_btf = btf;

	while (!own && base_btf->base_btf)
		base_btf = base_btf->base_btf;

	return base_btf->named_start_id ?: (base_btf->start_id ?: 1);
}

static s32 btf_find_by_name_kind_bsearch(const struct btf *btf, const char *name)
{
	const struct btf_type *t;
	const char *tname;
	s32 l, r, m;

	l = btf_named_start_id(btf, true);
	r = btf_nr_types(btf) - 1;
	while (l <= r) {
		m = l + (r - l) / 2;
		t = btf_type_by_id(btf, m);
		tname = btf_name_by_offset(btf, t->name_off);
		if (strcmp(tname, name) >= 0) {
			if (l == r)
				return r;
			r = m;
		} else {
			l = m + 1;
		}
	}

	return btf_nr_types(btf);
}

s32 btf_find_by_name_kind(const struct btf *btf, const char *name, u8 kind)
{
	const struct btf *base_btf = btf_base_btf(btf);
	const struct btf_type *t;
	const char *tname;
	s32 id, total;

	if (base_btf) {
		id = btf_find_by_name_kind(base_btf, name, kind);
		if (id > 0)
			return id;
	}

	total = btf_nr_types(btf);
	if (btf->named_start_id > 0 && name[0]) {
		id = btf_find_by_name_kind_bsearch(btf, name);
		for (; id < total; id++) {
			t = btf_type_by_id(btf, id);
			tname = btf_name_by_offset(btf, t->name_off);
			if (strcmp(tname, name) != 0)
				return -ENOENT;
			if (BTF_INFO_KIND(t->info) == kind)
				return id;
		}
	} else {
		for (id = btf_start_id(btf); id < total; id++) {
			t = btf_type_by_id(btf, id);
			if (BTF_INFO_KIND(t->info) != kind)
				continue;
			tname = btf_name_by_offset(btf, t->name_off);
			if (strcmp(tname, name) == 0)
				return id;
		}
	}

	return -ENOENT;
}


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

const struct btf_type *btf_type_resolve_ptr(const struct btf *btf,
					    u32 id, u32 *res_id)
{
	const struct btf_type *t;

	t = btf_type_skip_modifiers(btf, id, NULL);
	if (!btf_type_is_ptr(t))
		return NULL;

	return btf_type_skip_modifiers(btf, t->type, res_id);
}

const struct btf_type *btf_type_resolve_func_ptr(const struct btf *btf,
						 u32 id, u32 *res_id)
{
	const struct btf_type *ptype;

	ptype = btf_type_resolve_ptr(btf, id, res_id);
	if (ptype && btf_type_is_func_proto(ptype))
		return ptype;

	return NULL;
}

/* Types that act only as a source, not sink or intermediate
 * type when resolving.
 */
static bool btf_type_is_resolve_source_only(const struct btf_type *t)
{
	return btf_type_is_var(t) ||
	       btf_type_is_decl_tag(t) ||
	       btf_type_is_datasec(t);
}

/* What types need to be resolved?
 *
 * btf_type_is_modifier() is an obvious one.
 *
 * btf_type_is_struct() because its member refers to
 * another type (through member->type).
 *
 * btf_type_is_var() because the variable refers to
 * another type. btf_type_is_datasec() holds multiple
 * btf_type_is_var() types that need resolving.
 *
 * btf_type_is_array() because its element (array->type)
 * refers to another type.  Array can be thought of a
 * special case of struct while array just has the same
 * member-type repeated by array->nelems of times.
 */
static bool btf_type_needs_resolve(const struct btf_type *t)
{
	return btf_type_is_modifier(t) ||
	       btf_type_is_ptr(t) ||
	       btf_type_is_struct(t) ||
	       btf_type_is_array(t) ||
	       btf_type_is_var(t) ||
	       btf_type_is_func(t) ||
	       btf_type_is_decl_tag(t) ||
	       btf_type_is_datasec(t);
}

/* t->size can be used */
bool btf_type_has_size(const struct btf_type *t)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM:
	case BTF_KIND_DATASEC:
	case BTF_KIND_FLOAT:
	case BTF_KIND_ENUM64:
		return true;
	}

	return false;
}

static const char *btf_int_encoding_str(u8 encoding)
{
	if (encoding == 0)
		return "(none)";
	else if (encoding == BTF_INT_SIGNED)
		return "SIGNED";
	else if (encoding == BTF_INT_CHAR)
		return "CHAR";
	else if (encoding == BTF_INT_BOOL)
		return "BOOL";
	else
		return "UNKN";
}

static u32 btf_type_int(const struct btf_type *t)
{
	return *(u32 *)(t + 1);
}

static const struct btf_array *btf_type_array(const struct btf_type *t)
{
	return (const struct btf_array *)(t + 1);
}

static const struct btf_enum *btf_type_enum(const struct btf_type *t)
{
	return (const struct btf_enum *)(t + 1);
}

static const struct btf_var *btf_type_var(const struct btf_type *t)
{
	return (const struct btf_var *)(t + 1);
}

const struct btf_decl_tag *btf_type_decl_tag(const struct btf_type *t)
{
	return (const struct btf_decl_tag *)(t + 1);
}

static const struct btf_enum64 *btf_type_enum64(const struct btf_type *t)
{
	return (const struct btf_enum64 *)(t + 1);
}

static const struct btf_kind_operations *btf_type_ops(const struct btf_type *t)
{
	return kind_ops[BTF_INFO_KIND(t->info)];
}

static bool btf_name_offset_valid(const struct btf *btf, u32 offset)
{
	if (!BTF_STR_OFFSET_VALID(offset))
		return false;

	while (offset < btf->start_str_off)
		btf = btf->base_btf;

	offset -= btf->start_str_off;
	return offset < btf->hdr.str_len;
}

static bool __btf_name_char_ok(char c, bool first)
{
	if ((first ? !isalpha(c) :
		     !isalnum(c)) &&
	    c != '_' &&
	    c != '.')
		return false;
	return true;
}

const char *btf_str_by_offset(const struct btf *btf, u32 offset)
{
	while (offset < btf->start_str_off)
		btf = btf->base_btf;

	offset -= btf->start_str_off;
	if (offset < btf->hdr.str_len)
		return &btf->strings[offset];

	return NULL;
}

static bool btf_name_valid_identifier(const struct btf *btf, u32 offset)
{
	/* offset must be valid */
	const char *src = btf_str_by_offset(btf, offset);
	const char *src_limit;

	if (!__btf_name_char_ok(*src, true))
		return false;

	/* set a limit on identifier length */
	src_limit = src + KSYM_NAME_LEN;
	src++;
	while (*src && src < src_limit) {
		if (!__btf_name_char_ok(*src, false))
			return false;
		src++;
	}

	return !*src;
}

/* Allow any printable character in DATASEC names */
static bool btf_name_valid_section(const struct btf *btf, u32 offset)
{
	/* offset must be valid */
	const char *src = btf_str_by_offset(btf, offset);
	const char *src_limit;

	if (!*src)
		return false;

	/* set a limit on identifier length */
	src_limit = src + KSYM_NAME_LEN;
	while (*src && src < src_limit) {
		if (!isprint(*src))
			return false;
		src++;
	}

	return !*src;
}

const char *__btf_name_by_offset(const struct btf *btf, u32 offset)
{
	const char *name;

	if (!offset)
		return "(anon)";

	name = btf_str_by_offset(btf, offset);
	return name ?: "(invalid-name-offset)";
}

const char *btf_name_by_offset(const struct btf *btf, u32 offset)
{
	return btf_str_by_offset(btf, offset);
}

const struct btf_type *btf_type_by_id(const struct btf *btf, u32 type_id)
{
	while (type_id < btf->start_id)
		btf = btf->base_btf;

	type_id -= btf->start_id;
	if (type_id >= btf->nr_types)
		return NULL;
	return btf->types[type_id];
}
EXPORT_SYMBOL_GPL(btf_type_by_id);

/*
 * Check that the type @t is a regular int. This means that @t is not
 * a bit field and it has the same size as either of u8/u16/u32/u64
 * or __int128. If @expected_size is not zero, then size of @t should
 * be the same. A caller should already have checked that the type @t
 * is an integer.
 */
static bool __btf_type_int_is_regular(const struct btf_type *t, size_t expected_size)
{
	u32 int_data = btf_type_int(t);
	u8 nr_bits = BTF_INT_BITS(int_data);
	u8 nr_bytes = BITS_ROUNDUP_BYTES(nr_bits);

	return BITS_PER_BYTE_MASKED(nr_bits) == 0 &&
	       BTF_INT_OFFSET(int_data) == 0 &&
	       (nr_bytes <= 16 && is_power_of_2(nr_bytes)) &&
	       (expected_size == 0 || nr_bytes == expected_size);
}

static bool btf_type_int_is_regular(const struct btf_type *t)
{
	return __btf_type_int_is_regular(t, 0);
}

bool btf_type_is_i32(const struct btf_type *t)
{
	return btf_type_is_int(t) && __btf_type_int_is_regular(t, 4);
}

bool btf_type_is_i64(const struct btf_type *t)
{
	return btf_type_is_int(t) && __btf_type_int_is_regular(t, 8);
}

bool btf_type_is_primitive(const struct btf_type *t)
{
	return (btf_type_is_int(t) && btf_type_int_is_regular(t)) ||
	       btf_is_any_enum(t);
}

/*
 * Check that given struct member is a regular int with expected
 * offset and size.
 */
bool btf_member_is_reg_int(const struct btf *btf, const struct btf_type *s,
			   const struct btf_member *m,
			   u32 expected_offset, u32 expected_size)
{
	const struct btf_type *t;
	u32 id, int_data;
	u8 nr_bits;

	id = m->type;
	t = btf_type_id_size(btf, &id, NULL);
	if (!t || !btf_type_is_int(t))
		return false;

	int_data = btf_type_int(t);
	nr_bits = BTF_INT_BITS(int_data);
	if (btf_type_kflag(s)) {
		u32 bitfield_size = BTF_MEMBER_BITFIELD_SIZE(m->offset);
		u32 bit_offset = BTF_MEMBER_BIT_OFFSET(m->offset);

		/* if kflag set, int should be a regular int and
		 * bit offset should be at byte boundary.
		 */
		return !bitfield_size &&
		       BITS_ROUNDUP_BYTES(bit_offset) == expected_offset &&
		       BITS_ROUNDUP_BYTES(nr_bits) == expected_size;
	}

	if (BTF_INT_OFFSET(int_data) ||
	    BITS_PER_BYTE_MASKED(m->offset) ||
	    BITS_ROUNDUP_BYTES(m->offset) != expected_offset ||
	    BITS_PER_BYTE_MASKED(nr_bits) ||
	    BITS_ROUNDUP_BYTES(nr_bits) != expected_size)
		return false;

	return true;
}

/* Similar to btf_type_skip_modifiers() but does not skip typedefs. */
static const struct btf_type *btf_type_skip_qualifiers(const struct btf *btf,
						       u32 id)
{
	const struct btf_type *t = btf_type_by_id(btf, id);

	while (btf_type_is_modifier(t) &&
	       BTF_INFO_KIND(t->info) != BTF_KIND_TYPEDEF) {
		t = btf_type_by_id(btf, t->type);
	}

	return t;
}

#define BTF_SHOW_MAX_ITER	10

#define BTF_KIND_BIT(kind)	(1ULL << kind)

/*
 * Populate show->state.name with type name information.
 * Format of type name is
 *
 * [.member_name = ] (type_name)
 */
static const char *btf_show_name(struct btf_show *show)
{
	/* BTF_MAX_ITER array suffixes "[]" */
	const char *array_suffixes = "[][][][][][][][][][]";
	const char *array_suffix = &array_suffixes[strlen(array_suffixes)];
	/* BTF_MAX_ITER pointer suffixes "*" */
	const char *ptr_suffixes = "**********";
	const char *ptr_suffix = &ptr_suffixes[strlen(ptr_suffixes)];
	const char *name = NULL, *prefix = "", *parens = "";
	const struct btf_member *m = show->state.member;
	const struct btf_type *t;
	const struct btf_array *array;
	u32 id = show->state.type_id;
	const char *member = NULL;
	bool show_member = false;
	u64 kinds = 0;
	int i;

	show->state.name[0] = '\0';

	/*
	 * Don't show type name if we're showing an array member;
	 * in that case we show the array type so don't need to repeat
	 * ourselves for each member.
	 */
	if (show->state.array_member)
		return "";

	/* Retrieve member name, if any. */
	if (m) {
		member = btf_name_by_offset(show->btf, m->name_off);
		show_member = strlen(member) > 0;
		id = m->type;
	}

	/*
	 * Start with type_id, as we have resolved the struct btf_type *
	 * via btf_modifier_show() past the parent typedef to the child
	 * struct, int etc it is defined as.  In such cases, the type_id
	 * still represents the starting type while the struct btf_type *
	 * in our show->state points at the resolved type of the typedef.
	 */
	t = btf_type_by_id(show->btf, id);
	if (!t)
		return "";

	/*
	 * The goal here is to build up the right number of pointer and
	 * array suffixes while ensuring the type name for a typedef
	 * is represented.  Along the way we accumulate a list of
	 * BTF kinds we have encountered, since these will inform later
	 * display; for example, pointer types will not require an
	 * opening "{" for struct, we will just display the pointer value.
	 *
	 * We also want to accumulate the right number of pointer or array
	 * indices in the format string while iterating until we get to
	 * the typedef/pointee/array member target type.
	 *
	 * We start by pointing at the end of pointer and array suffix
	 * strings; as we accumulate pointers and arrays we move the pointer
	 * or array string backwards so it will show the expected number of
	 * '*' or '[]' for the type.  BTF_SHOW_MAX_ITER of nesting of pointers
	 * and/or arrays and typedefs are supported as a precaution.
	 *
	 * We also want to get typedef name while proceeding to resolve
	 * type it points to so that we can add parentheses if it is a
	 * "typedef struct" etc.
	 */
	for (i = 0; i < BTF_SHOW_MAX_ITER; i++) {

		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
			if (!name)
				name = btf_name_by_offset(show->btf,
							       t->name_off);
			kinds |= BTF_KIND_BIT(BTF_KIND_TYPEDEF);
			id = t->type;
			break;
		case BTF_KIND_ARRAY:
			kinds |= BTF_KIND_BIT(BTF_KIND_ARRAY);
			parens = "[";
			if (!t)
				return "";
			array = btf_type_array(t);
			if (array_suffix > array_suffixes)
				array_suffix -= 2;
			id = array->type;
			break;
		case BTF_KIND_PTR:
			kinds |= BTF_KIND_BIT(BTF_KIND_PTR);
			if (ptr_suffix > ptr_suffixes)
				ptr_suffix -= 1;
			id = t->type;
			break;
		default:
			id = 0;
			break;
		}
		if (!id)
			break;
		t = btf_type_skip_qualifiers(show->btf, id);
	}
	/* We may not be able to represent this type; bail to be safe */
	if (i == BTF_SHOW_MAX_ITER)
		return "";

	if (!name)
		name = btf_name_by_offset(show->btf, t->name_off);

	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		prefix = BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT ?
			 "struct" : "union";
		/* if it's an array of struct/union, parens is already set */
		if (!(kinds & (BTF_KIND_BIT(BTF_KIND_ARRAY))))
			parens = "{";
		break;
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		prefix = "enum";
		break;
	default:
		break;
	}

	/* pointer does not require parens */
	if (kinds & BTF_KIND_BIT(BTF_KIND_PTR))
		parens = "";
	/* typedef does not require struct/union/enum prefix */
	if (kinds & BTF_KIND_BIT(BTF_KIND_TYPEDEF))
		prefix = "";

	if (!name)
		name = "";

	/* Even if we don't want type name info, we want parentheses etc */
	if (show->flags & BTF_SHOW_NONAME)
		snprintf(show->state.name, sizeof(show->state.name), "%s",
			 parens);
	else
		snprintf(show->state.name, sizeof(show->state.name),
			 "%s%s%s(%s%s%s%s%s%s)%s",
			 /* first 3 strings comprise ".member = " */
			 show_member ? "." : "",
			 show_member ? member : "",
			 show_member ? " = " : "",
			 /* ...next is our prefix (struct, enum, etc) */
			 prefix,
			 strlen(prefix) > 0 && strlen(name) > 0 ? " " : "",
			 /* ...this is the type name itself */
			 name,
			 /* ...suffixed by the appropriate '*', '[]' suffixes */
			 strlen(ptr_suffix) > 0 ? " " : "", ptr_suffix,
			 array_suffix, parens);

	return show->state.name;
}

static const char *__btf_show_indent(struct btf_show *show)
{
	const char *indents = "                                ";
	const char *indent = &indents[strlen(indents)];

	if ((indent - show->state.depth) >= indents)
		return indent - show->state.depth;
	return indents;
}

static const char *btf_show_indent(struct btf_show *show)
{
	return show->flags & BTF_SHOW_COMPACT ? "" : __btf_show_indent(show);
}

static const char *btf_show_newline(struct btf_show *show)
{
	return show->flags & BTF_SHOW_COMPACT ? "" : "\n";
}

static const char *btf_show_delim(struct btf_show *show)
{
	if (show->state.depth == 0)
		return "";

	if ((show->flags & BTF_SHOW_COMPACT) && show->state.type &&
		BTF_INFO_KIND(show->state.type->info) == BTF_KIND_UNION)
		return "|";

	return ",";
}

__printf(2, 3) static void btf_show(struct btf_show *show, const char *fmt, ...)
{
	va_list args;

	if (!show->state.depth_check) {
		va_start(args, fmt);
		show->showfn(show, fmt, args);
		va_end(args);
	}
}

/* Macros are used here as btf_show_type_value[s]() prepends and appends
 * format specifiers to the format specifier passed in; these do the work of
 * adding indentation, delimiters etc while the caller simply has to specify
 * the type value(s) in the format specifier + value(s).
 */
#define btf_show_type_value(show, fmt, value)				       \
	do {								       \
		if ((value) != (__typeof__(value))0 ||			       \
		    (show->flags & BTF_SHOW_ZERO) ||			       \
		    show->state.depth == 0) {				       \
			btf_show(show, "%s%s" fmt "%s%s",		       \
				 btf_show_indent(show),			       \
				 btf_show_name(show),			       \
				 value, btf_show_delim(show),		       \
				 btf_show_newline(show));		       \
			if (show->state.depth > show->state.depth_to_show)     \
				show->state.depth_to_show = show->state.depth; \
		}							       \
	} while (0)

#define btf_show_type_values(show, fmt, ...)				       \
	do {								       \
		btf_show(show, "%s%s" fmt "%s%s", btf_show_indent(show),       \
			 btf_show_name(show),				       \
			 __VA_ARGS__, btf_show_delim(show),		       \
			 btf_show_newline(show));			       \
		if (show->state.depth > show->state.depth_to_show)	       \
			show->state.depth_to_show = show->state.depth;	       \
	} while (0)

/* How much is left to copy to safe buffer after @data? */
static int btf_show_obj_size_left(struct btf_show *show, void *data)
{
	return show->obj.head + show->obj.size - data;
}

/* Is object pointed to by @data of @size already copied to our safe buffer? */
static bool btf_show_obj_is_safe(struct btf_show *show, void *data, int size)
{
	return data >= show->obj.data &&
	       (data + size) < (show->obj.data + BTF_SHOW_OBJ_SAFE_SIZE);
}

/*
 * If object pointed to by @data of @size falls within our safe buffer, return
 * the equivalent pointer to the same safe data.  Assumes
 * copy_from_kernel_nofault() has already happened and our safe buffer is
 * populated.
 */
static void *__btf_show_obj_safe(struct btf_show *show, void *data, int size)
{
	if (btf_show_obj_is_safe(show, data, size))
		return show->obj.safe + (data - show->obj.data);
	return NULL;
}

/*
 * Return a safe-to-access version of data pointed to by @data.
 * We do this by copying the relevant amount of information
 * to the struct btf_show obj.safe buffer using copy_from_kernel_nofault().
 *
 * If BTF_SHOW_UNSAFE is specified, just return data as-is; no
 * safe copy is needed.
 *
 * Otherwise we need to determine if we have the required amount
 * of data (determined by the @data pointer and the size of the
 * largest base type we can encounter (represented by
 * BTF_SHOW_OBJ_BASE_TYPE_SIZE). Having that much data ensures
 * that we will be able to print some of the current object,
 * and if more is needed a copy will be triggered.
 * Some objects such as structs will not fit into the buffer;
 * in such cases additional copies when we iterate over their
 * members may be needed.
 *
 * btf_show_obj_safe() is used to return a safe buffer for
 * btf_show_start_type(); this ensures that as we recurse into
 * nested types we always have safe data for the given type.
 * This approach is somewhat wasteful; it's possible for example
 * that when iterating over a large union we'll end up copying the
 * same data repeatedly, but the goal is safety not performance.
 * We use stack data as opposed to per-CPU buffers because the
 * iteration over a type can take some time, and preemption handling
 * would greatly complicate use of the safe buffer.
 */
static void *btf_show_obj_safe(struct btf_show *show,
			       const struct btf_type *t,
			       void *data)
{
	const struct btf_type *rt;
	int size_left, size;
	void *safe = NULL;

	if (show->flags & BTF_SHOW_UNSAFE)
		return data;

	rt = btf_resolve_size(show->btf, t, &size);
	if (IS_ERR(rt)) {
		show->state.status = PTR_ERR(rt);
		return NULL;
	}

	/*
	 * Is this toplevel object? If so, set total object size and
	 * initialize pointers.  Otherwise check if we still fall within
	 * our safe object data.
	 */
	if (show->state.depth == 0) {
		show->obj.size = size;
		show->obj.head = data;
	} else {
		/*
		 * If the size of the current object is > our remaining
		 * safe buffer we _may_ need to do a new copy.  However
		 * consider the case of a nested struct; it's size pushes
		 * us over the safe buffer limit, but showing any individual
		 * struct members does not.  In such cases, we don't need
		 * to initiate a fresh copy yet; however we definitely need
		 * at least BTF_SHOW_OBJ_BASE_TYPE_SIZE bytes left
		 * in our buffer, regardless of the current object size.
		 * The logic here is that as we resolve types we will
		 * hit a base type at some point, and we need to be sure
		 * the next chunk of data is safely available to display
		 * that type info safely.  We cannot rely on the size of
		 * the current object here because it may be much larger
		 * than our current buffer (e.g. task_struct is 8k).
		 * All we want to do here is ensure that we can print the
		 * next basic type, which we can if either
		 * - the current type size is within the safe buffer; or
		 * - at least BTF_SHOW_OBJ_BASE_TYPE_SIZE bytes are left in
		 *   the safe buffer.
		 */
		safe = __btf_show_obj_safe(show, data,
					   min(size,
					       BTF_SHOW_OBJ_BASE_TYPE_SIZE));
	}

	/*
	 * We need a new copy to our safe object, either because we haven't
	 * yet copied and are initializing safe data, or because the data
	 * we want falls outside the boundaries of the safe object.
	 */
	if (!safe) {
		size_left = btf_show_obj_size_left(show, data);
		if (size_left > BTF_SHOW_OBJ_SAFE_SIZE)
			size_left = BTF_SHOW_OBJ_SAFE_SIZE;
		show->state.status = copy_from_kernel_nofault(show->obj.safe,
							      data, size_left);
		if (!show->state.status) {
			show->obj.data = data;
			safe = show->obj.safe;
		}
	}

	return safe;
}

/*
 * Set the type we are starting to show and return a safe data pointer
 * to be used for showing the associated data.
 */
static void *btf_show_start_type(struct btf_show *show,
				 const struct btf_type *t,
				 u32 type_id, void *data)
{
	show->state.type = t;
	show->state.type_id = type_id;
	show->state.name[0] = '\0';

	return btf_show_obj_safe(show, t, data);
}

static void btf_show_end_type(struct btf_show *show)
{
	show->state.type = NULL;
	show->state.type_id = 0;
	show->state.name[0] = '\0';
}

static void *btf_show_start_aggr_type(struct btf_show *show,
				      const struct btf_type *t,
				      u32 type_id, void *data)
{
	void *safe_data = btf_show_start_type(show, t, type_id, data);

	if (!safe_data)
		return safe_data;

	btf_show(show, "%s%s%s", btf_show_indent(show),
		 btf_show_name(show),
		 btf_show_newline(show));
	show->state.depth++;
	return safe_data;
}

static void btf_show_end_aggr_type(struct btf_show *show,
				   const char *suffix)
{
	show->state.depth--;
	btf_show(show, "%s%s%s%s", btf_show_indent(show), suffix,
		 btf_show_delim(show), btf_show_newline(show));
	btf_show_end_type(show);
}

static void btf_show_start_member(struct btf_show *show,
				  const struct btf_member *m)
{
	show->state.member = m;
}

static void btf_show_start_array_member(struct btf_show *show)
{
	show->state.array_member = 1;
	btf_show_start_member(show, NULL);
}

static void btf_show_end_member(struct btf_show *show)
{
	show->state.member = NULL;
}

static void btf_show_end_array_member(struct btf_show *show)
{
	show->state.array_member = 0;
	btf_show_end_member(show);
}

static void *btf_show_start_array_type(struct btf_show *show,
				       const struct btf_type *t,
				       u32 type_id,
				       u16 array_encoding,
				       void *data)
{
	show->state.array_encoding = array_encoding;
	show->state.array_terminated = 0;
	return btf_show_start_aggr_type(show, t, type_id, data);
}

static void btf_show_end_array_type(struct btf_show *show)
{
	show->state.array_encoding = 0;
	show->state.array_terminated = 0;
	btf_show_end_aggr_type(show, "]");
}

static void *btf_show_start_struct_type(struct btf_show *show,
					const struct btf_type *t,
					u32 type_id,
					void *data)
{
	return btf_show_start_aggr_type(show, t, type_id, data);
}

static void btf_show_end_struct_type(struct btf_show *show)
{
	btf_show_end_aggr_type(show, "}");
}

__printf(2, 3) static void __btf_verifier_log(struct bpf_verifier_log *log,
					      const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

__printf(2, 3) static void btf_verifier_log(struct btf_verifier_env *env,
					    const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

__printf(4, 5) static void __btf_verifier_log_type(struct btf_verifier_env *env,
						   const struct btf_type *t,
						   bool log_details,
						   const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	struct btf *btf = env->btf;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	if (log->level == BPF_LOG_KERNEL) {
		/* btf verifier prints all types it is processing via
		 * btf_verifier_log_type(..., fmt = NULL).
		 * Skip those prints for in-kernel BTF verification.
		 */
		if (!fmt)
			return;

		/* Skip logging when loading module BTF with mismatches permitted */
		if (env->btf->base_btf && IS_ENABLED(CONFIG_MODULE_ALLOW_BTF_MISMATCH))
			return;
	}

	__btf_verifier_log(log, "[%u] %s %s%s",
			   env->log_type_id,
			   btf_type_str(t),
			   __btf_name_by_offset(btf, t->name_off),
			   log_details ? " " : "");

	if (log_details)
		btf_type_ops(t)->log_details(env, t);

	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

#define btf_verifier_log_type(env, t, ...) \
	__btf_verifier_log_type((env), (t), true, __VA_ARGS__)
#define btf_verifier_log_basic(env, t, ...) \
	__btf_verifier_log_type((env), (t), false, __VA_ARGS__)

__printf(4, 5)
static void btf_verifier_log_member(struct btf_verifier_env *env,
				    const struct btf_type *struct_type,
				    const struct btf_member *member,
				    const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	struct btf *btf = env->btf;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	if (log->level == BPF_LOG_KERNEL) {
		if (!fmt)
			return;

		/* Skip logging when loading module BTF with mismatches permitted */
		if (env->btf->base_btf && IS_ENABLED(CONFIG_MODULE_ALLOW_BTF_MISMATCH))
			return;
	}

	/* The CHECK_META phase already did a btf dump.
	 *
	 * If member is logged again, it must hit an error in
	 * parsing this member.  It is useful to print out which
	 * struct this member belongs to.
	 */
	if (env->phase != CHECK_META)
		btf_verifier_log_type(env, struct_type, NULL);

	if (btf_type_kflag(struct_type))
		__btf_verifier_log(log,
				   "\t%s type_id=%u bitfield_size=%u bits_offset=%u",
				   __btf_name_by_offset(btf, member->name_off),
				   member->type,
				   BTF_MEMBER_BITFIELD_SIZE(member->offset),
				   BTF_MEMBER_BIT_OFFSET(member->offset));
	else
		__btf_verifier_log(log, "\t%s type_id=%u bits_offset=%u",
				   __btf_name_by_offset(btf, member->name_off),
				   member->type, member->offset);

	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

__printf(4, 5)
static void btf_verifier_log_vsi(struct btf_verifier_env *env,
				 const struct btf_type *datasec_type,
				 const struct btf_var_secinfo *vsi,
				 const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;
	if (log->level == BPF_LOG_KERNEL && !fmt)
		return;
	if (env->phase != CHECK_META)
		btf_verifier_log_type(env, datasec_type, NULL);

	__btf_verifier_log(log, "\t type_id=%u offset=%u size=%u",
			   vsi->type, vsi->offset, vsi->size);
	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

static void btf_verifier_log_hdr(struct btf_verifier_env *env,
				 u32 btf_data_size)
{
	struct bpf_verifier_log *log = &env->log;
	const struct btf *btf = env->btf;
	const struct btf_header *hdr;

	if (!bpf_verifier_log_needed(log))
		return;

	if (log->level == BPF_LOG_KERNEL)
		return;
	hdr = &btf->hdr;
	__btf_verifier_log(log, "magic: 0x%x\n", hdr->magic);
	__btf_verifier_log(log, "version: %u\n", hdr->version);
	__btf_verifier_log(log, "flags: 0x%x\n", hdr->flags);
	__btf_verifier_log(log, "hdr_len: %u\n", hdr->hdr_len);
	__btf_verifier_log(log, "type_off: %u\n", hdr->type_off);
	__btf_verifier_log(log, "type_len: %u\n", hdr->type_len);
	__btf_verifier_log(log, "str_off: %u\n", hdr->str_off);
	__btf_verifier_log(log, "str_len: %u\n", hdr->str_len);
	__btf_verifier_log(log, "btf_total_size: %u\n", btf_data_size);
}

static int btf_add_type(struct btf_verifier_env *env, struct btf_type *t)
{
	struct btf *btf = env->btf;

	if (btf->types_size == btf->nr_types) {
		/* Expand 'types' array */

		struct btf_type **new_types;
		u32 expand_by, new_size;

		if (btf->start_id + btf->types_size == BTF_MAX_TYPE) {
			btf_verifier_log(env, "Exceeded max num of types");
			return -E2BIG;
		}

		expand_by = max_t(u32, btf->types_size >> 2, 16);
		new_size = min_t(u32, BTF_MAX_TYPE,
				 btf->types_size + expand_by);

		new_types = kvzalloc_objs(*new_types, new_size,
					  GFP_KERNEL | __GFP_NOWARN);
		if (!new_types)
			return -ENOMEM;

		if (btf->nr_types == 0) {
			if (!btf->base_btf) {
				/* lazily init VOID type */
				new_types[0] = &btf_void;
				btf->nr_types++;
			}
		} else {
			memcpy(new_types, btf->types,
			       sizeof(*btf->types) * btf->nr_types);
		}

		kvfree(btf->types);
		btf->types = new_types;
		btf->types_size = new_size;
	}

	btf->types[btf->nr_types++] = t;

	return 0;
}


void __weak btf_free_bpf_data(struct btf *btf)
{
}

void btf_free(struct btf *btf)
{
	btf_free_bpf_data(btf);
	kvfree(btf->types);
	kvfree(btf->resolved_sizes);
	kvfree(btf->resolved_ids);
	/* vmlinux does not allocate btf->data, it simply points it at
	 * __start_BTF.
	 */
	if (!btf_is_vmlinux(btf))
		kvfree(btf->data);
	kvfree(btf->base_id_map);
	kfree(btf);
}


const char *btf_get_name(const struct btf *btf)
{
	return btf->name;
}

void btf_get(struct btf *btf)
{
	refcount_inc(&btf->refcnt);
}

void __weak btf_put_bpf(struct btf *btf)
{
	btf_free(btf);
}

void btf_put(struct btf *btf)
{
	if (btf && refcount_dec_and_test(&btf->refcnt)) {
		btf_put_bpf(btf);
	}
}

struct btf *btf_base_btf(const struct btf *btf)
{
	return btf->base_btf;
}

const struct btf_header *btf_header(const struct btf *btf)
{
	return &btf->hdr;
}

void btf_set_base_btf(struct btf *btf, const struct btf *base_btf)
{
	btf->base_btf = (struct btf *)base_btf;
	btf->start_id = btf_nr_types(base_btf);
	btf->start_str_off = base_btf->hdr.str_len;
}

static int env_resolve_init(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	u32 nr_types = btf->nr_types;
	u32 *resolved_sizes = NULL;
	u32 *resolved_ids = NULL;
	u8 *visit_states = NULL;

	resolved_sizes = kvcalloc(nr_types, sizeof(*resolved_sizes),
				  GFP_KERNEL | __GFP_NOWARN);
	if (!resolved_sizes)
		goto nomem;

	resolved_ids = kvcalloc(nr_types, sizeof(*resolved_ids),
				GFP_KERNEL | __GFP_NOWARN);
	if (!resolved_ids)
		goto nomem;

	visit_states = kvcalloc(nr_types, sizeof(*visit_states),
				GFP_KERNEL | __GFP_NOWARN);
	if (!visit_states)
		goto nomem;

	btf->resolved_sizes = resolved_sizes;
	btf->resolved_ids = resolved_ids;
	env->visit_states = visit_states;

	return 0;

nomem:
	kvfree(resolved_sizes);
	kvfree(resolved_ids);
	kvfree(visit_states);
	return -ENOMEM;
}

void btf_verifier_env_free(struct btf_verifier_env *env)
{
	kvfree(env->visit_states);
	kfree(env);
}

static bool env_type_is_resolve_sink(const struct btf_verifier_env *env,
				     const struct btf_type *next_type)
{
	switch (env->resolve_mode) {
	case RESOLVE_TBD:
		/* int, enum or void is a sink */
		return !btf_type_needs_resolve(next_type);
	case RESOLVE_PTR:
		/* int, enum, void, struct, array, func or func_proto is a sink
		 * for ptr
		 */
		return !btf_type_is_modifier(next_type) &&
			!btf_type_is_ptr(next_type);
	case RESOLVE_STRUCT_OR_ARRAY:
		/* int, enum, void, ptr, func or func_proto is a sink
		 * for struct and array
		 */
		return !btf_type_is_modifier(next_type) &&
			!btf_type_is_array(next_type) &&
			!btf_type_is_struct(next_type);
	default:
		BUG();
	}
}

static bool env_type_is_resolved(const struct btf_verifier_env *env,
				 u32 type_id)
{
	/* base BTF types should be resolved by now */
	if (type_id < env->btf->start_id)
		return true;

	return env->visit_states[type_id - env->btf->start_id] == RESOLVED;
}

static int env_stack_push(struct btf_verifier_env *env,
			  const struct btf_type *t, u32 type_id)
{
	const struct btf *btf = env->btf;
	struct resolve_vertex *v;

	if (env->top_stack == MAX_RESOLVE_DEPTH)
		return -E2BIG;

	if (type_id < btf->start_id
	    || env->visit_states[type_id - btf->start_id] != NOT_VISITED)
		return -EEXIST;

	env->visit_states[type_id - btf->start_id] = VISITED;

	v = &env->stack[env->top_stack++];
	v->t = t;
	v->type_id = type_id;
	v->next_member = 0;

	if (env->resolve_mode == RESOLVE_TBD) {
		if (btf_type_is_ptr(t))
			env->resolve_mode = RESOLVE_PTR;
		else if (btf_type_is_struct(t) || btf_type_is_array(t))
			env->resolve_mode = RESOLVE_STRUCT_OR_ARRAY;
	}

	return 0;
}

static void env_stack_set_next_member(struct btf_verifier_env *env,
				      u16 next_member)
{
	env->stack[env->top_stack - 1].next_member = next_member;
}

static void env_stack_pop_resolved(struct btf_verifier_env *env,
				   u32 resolved_type_id,
				   u32 resolved_size)
{
	u32 type_id = env->stack[--(env->top_stack)].type_id;
	struct btf *btf = env->btf;

	type_id -= btf->start_id; /* adjust to local type id */
	btf->resolved_sizes[type_id] = resolved_size;
	btf->resolved_ids[type_id] = resolved_type_id;
	env->visit_states[type_id] = RESOLVED;
}

static const struct resolve_vertex *env_stack_peak(struct btf_verifier_env *env)
{
	return env->top_stack ? &env->stack[env->top_stack - 1] : NULL;
}

/* Resolve the size of a passed-in "type"
 *
 * type: is an array (e.g. u32 array[x][y])
 * return type: type "u32[x][y]", i.e. BTF_KIND_ARRAY,
 * *type_size: (x * y * sizeof(u32)).  Hence, *type_size always
 *             corresponds to the return type.
 * *elem_type: u32
 * *elem_id: id of u32
 * *total_nelems: (x * y).  Hence, individual elem size is
 *                (*type_size / *total_nelems)
 * *type_id: id of type if it's changed within the function, 0 if not
 *
 * type: is not an array (e.g. const struct X)
 * return type: type "struct X"
 * *type_size: sizeof(struct X)
 * *elem_type: same as return type ("struct X")
 * *elem_id: 0
 * *total_nelems: 1
 * *type_id: id of type if it's changed within the function, 0 if not
 */
const struct btf_type *
__btf_resolve_size(const struct btf *btf, const struct btf_type *type,
		   u32 *type_size, const struct btf_type **elem_type,
		   u32 *elem_id, u32 *total_nelems, u32 *type_id)
{
	const struct btf_type *array_type = NULL;
	const struct btf_array *array = NULL;
	u32 i, size, nelems = 1, id = 0;

	for (i = 0; i < MAX_RESOLVE_DEPTH; i++) {
		switch (BTF_INFO_KIND(type->info)) {
		/* type->size can be used */
		case BTF_KIND_INT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_FLOAT:
		case BTF_KIND_ENUM64:
			size = type->size;
			goto resolved;

		case BTF_KIND_PTR:
			size = sizeof(void *);
			goto resolved;

		/* Modifiers */
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		case BTF_KIND_TYPE_TAG:
			id = type->type;
			type = btf_type_by_id(btf, type->type);
			break;

		case BTF_KIND_ARRAY:
			if (!array_type)
				array_type = type;
			array = btf_type_array(type);
			if (nelems && array->nelems > U32_MAX / nelems)
				return ERR_PTR(-EINVAL);
			nelems *= array->nelems;
			type = btf_type_by_id(btf, array->type);
			break;

		/* type without size */
		default:
			return ERR_PTR(-EINVAL);
		}
	}

	return ERR_PTR(-EINVAL);

resolved:
	if (nelems && size > U32_MAX / nelems)
		return ERR_PTR(-EINVAL);

	*type_size = nelems * size;
	if (total_nelems)
		*total_nelems = nelems;
	if (elem_type)
		*elem_type = type;
	if (elem_id)
		*elem_id = array ? array->type : 0;
	if (type_id && id)
		*type_id = id;

	return array_type ? : type;
}

const struct btf_type *
btf_resolve_size(const struct btf *btf, const struct btf_type *type,
		 u32 *type_size)
{
	return __btf_resolve_size(btf, type, type_size, NULL, NULL, NULL, NULL);
}

static u32 btf_resolved_type_id(const struct btf *btf, u32 type_id)
{
	while (type_id < btf->start_id)
		btf = btf->base_btf;

	return btf->resolved_ids[type_id - btf->start_id];
}

/* The input param "type_id" must point to a needs_resolve type */
static const struct btf_type *btf_type_id_resolve(const struct btf *btf,
						  u32 *type_id)
{
	*type_id = btf_resolved_type_id(btf, *type_id);
	return btf_type_by_id(btf, *type_id);
}

static u32 btf_resolved_type_size(const struct btf *btf, u32 type_id)
{
	while (type_id < btf->start_id)
		btf = btf->base_btf;

	return btf->resolved_sizes[type_id - btf->start_id];
}

const struct btf_type *btf_type_id_size(const struct btf *btf,
					u32 *type_id, u32 *ret_size)
{
	const struct btf_type *size_type;
	u32 size_type_id = *type_id;
	u32 size = 0;

	size_type = btf_type_by_id(btf, size_type_id);
	if (btf_type_nosize_or_null(size_type))
		return NULL;

	if (btf_type_has_size(size_type)) {
		size = size_type->size;
	} else if (btf_type_is_array(size_type)) {
		size = btf_resolved_type_size(btf, size_type_id);
	} else if (btf_type_is_ptr(size_type)) {
		size = sizeof(void *);
	} else {
		if (WARN_ON_ONCE(!btf_type_is_modifier(size_type) &&
				 !btf_type_is_var(size_type)))
			return NULL;

		size_type_id = btf_resolved_type_id(btf, size_type_id);
		size_type = btf_type_by_id(btf, size_type_id);
		if (btf_type_nosize_or_null(size_type))
			return NULL;
		else if (btf_type_has_size(size_type))
			size = size_type->size;
		else if (btf_type_is_array(size_type))
			size = btf_resolved_type_size(btf, size_type_id);
		else if (btf_type_is_ptr(size_type))
			size = sizeof(void *);
		else
			return NULL;
	}

	*type_id = size_type_id;
	if (ret_size)
		*ret_size = size;

	return size_type;
}

static int btf_df_check_member(struct btf_verifier_env *env,
			       const struct btf_type *struct_type,
			       const struct btf_member *member,
			       const struct btf_type *member_type)
{
	btf_verifier_log_basic(env, struct_type,
			       "Unsupported check_member");
	return -EINVAL;
}

static int btf_df_check_kflag_member(struct btf_verifier_env *env,
				     const struct btf_type *struct_type,
				     const struct btf_member *member,
				     const struct btf_type *member_type)
{
	btf_verifier_log_basic(env, struct_type,
			       "Unsupported check_kflag_member");
	return -EINVAL;
}

/* Used for ptr, array struct/union and float type members.
 * int, enum and modifier types have their specific callback functions.
 */
static int btf_generic_check_kflag_member(struct btf_verifier_env *env,
					  const struct btf_type *struct_type,
					  const struct btf_member *member,
					  const struct btf_type *member_type)
{
	if (BTF_MEMBER_BITFIELD_SIZE(member->offset)) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member bitfield_size");
		return -EINVAL;
	}

	/* bitfield size is 0, so member->offset represents bit offset only.
	 * It is safe to call non kflag check_member variants.
	 */
	return btf_type_ops(member_type)->check_member(env, struct_type,
						       member,
						       member_type);
}

static int btf_df_resolve(struct btf_verifier_env *env,
			  const struct resolve_vertex *v)
{
	btf_verifier_log_basic(env, v->t, "Unsupported resolve");
	return -EINVAL;
}

static void btf_df_show(const struct btf *btf, const struct btf_type *t,
			u32 type_id, void *data, u8 bits_offsets,
			struct btf_show *show)
{
	btf_show(show, "<unsupported kind:%u>", BTF_INFO_KIND(t->info));
}

static int btf_int_check_member(struct btf_verifier_env *env,
				const struct btf_type *struct_type,
				const struct btf_member *member,
				const struct btf_type *member_type)
{
	u32 int_data = btf_type_int(member_type);
	u32 struct_bits_off = member->offset;
	u32 struct_size = struct_type->size;
	u32 nr_copy_bits;
	u32 bytes_offset;

	if (U32_MAX - struct_bits_off < BTF_INT_OFFSET(int_data)) {
		btf_verifier_log_member(env, struct_type, member,
					"bits_offset exceeds U32_MAX");
		return -EINVAL;
	}

	struct_bits_off += BTF_INT_OFFSET(int_data);
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	nr_copy_bits = BTF_INT_BITS(int_data) +
		BITS_PER_BYTE_MASKED(struct_bits_off);

	if (nr_copy_bits > BITS_PER_U128) {
		btf_verifier_log_member(env, struct_type, member,
					"nr_copy_bits exceeds 128");
		return -EINVAL;
	}

	if (struct_size < bytes_offset ||
	    struct_size - bytes_offset < BITS_ROUNDUP_BYTES(nr_copy_bits)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_int_check_kflag_member(struct btf_verifier_env *env,
				      const struct btf_type *struct_type,
				      const struct btf_member *member,
				      const struct btf_type *member_type)
{
	u32 struct_bits_off, nr_bits, nr_int_data_bits, bytes_offset;
	u32 int_data = btf_type_int(member_type);
	u32 struct_size = struct_type->size;
	u32 nr_copy_bits;

	/* a regular int type is required for the kflag int member */
	if (!btf_type_int_is_regular(member_type)) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member base type");
		return -EINVAL;
	}

	/* check sanity of bitfield size */
	nr_bits = BTF_MEMBER_BITFIELD_SIZE(member->offset);
	struct_bits_off = BTF_MEMBER_BIT_OFFSET(member->offset);
	nr_int_data_bits = BTF_INT_BITS(int_data);
	if (!nr_bits) {
		/* Not a bitfield member, member offset must be at byte
		 * boundary.
		 */
		if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
			btf_verifier_log_member(env, struct_type, member,
						"Invalid member offset");
			return -EINVAL;
		}

		nr_bits = nr_int_data_bits;
	} else if (nr_bits > nr_int_data_bits) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member bitfield_size");
		return -EINVAL;
	}

	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	nr_copy_bits = nr_bits + BITS_PER_BYTE_MASKED(struct_bits_off);
	if (nr_copy_bits > BITS_PER_U128) {
		btf_verifier_log_member(env, struct_type, member,
					"nr_copy_bits exceeds 128");
		return -EINVAL;
	}

	if (struct_size < bytes_offset ||
	    struct_size - bytes_offset < BITS_ROUNDUP_BYTES(nr_copy_bits)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_int_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	u32 int_data, nr_bits, meta_needed = sizeof(int_data);
	u16 encoding;

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	int_data = btf_type_int(t);
	if (int_data & ~BTF_INT_MASK) {
		btf_verifier_log_basic(env, t, "Invalid int_data:%x",
				       int_data);
		return -EINVAL;
	}

	nr_bits = BTF_INT_BITS(int_data) + BTF_INT_OFFSET(int_data);

	if (nr_bits > BITS_PER_U128) {
		btf_verifier_log_type(env, t, "nr_bits exceeds %zu",
				      BITS_PER_U128);
		return -EINVAL;
	}

	if (BITS_ROUNDUP_BYTES(nr_bits) > t->size) {
		btf_verifier_log_type(env, t, "nr_bits exceeds type_size");
		return -EINVAL;
	}

	/*
	 * Only one of the encoding bits is allowed and it
	 * should be sufficient for the pretty print purpose (i.e. decoding).
	 * Multiple bits can be allowed later if it is found
	 * to be insufficient.
	 */
	encoding = BTF_INT_ENCODING(int_data);
	if (encoding &&
	    encoding != BTF_INT_SIGNED &&
	    encoding != BTF_INT_CHAR &&
	    encoding != BTF_INT_BOOL) {
		btf_verifier_log_type(env, t, "Unsupported encoding");
		return -ENOTSUPP;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_int_log(struct btf_verifier_env *env,
			const struct btf_type *t)
{
	int int_data = btf_type_int(t);

	btf_verifier_log(env,
			 "size=%u bits_offset=%u nr_bits=%u encoding=%s",
			 t->size, BTF_INT_OFFSET(int_data),
			 BTF_INT_BITS(int_data),
			 btf_int_encoding_str(BTF_INT_ENCODING(int_data)));
}

static void btf_int128_print(struct btf_show *show, void *data)
{
	/* data points to a __int128 number.
	 * Suppose
	 *     int128_num = *(__int128 *)data;
	 * The below formulas shows what upper_num and lower_num represents:
	 *     upper_num = int128_num >> 64;
	 *     lower_num = int128_num & 0xffffffffFFFFFFFFULL;
	 */
	u64 upper_num, lower_num;

#ifdef __BIG_ENDIAN_BITFIELD
	upper_num = *(u64 *)data;
	lower_num = *(u64 *)(data + 8);
#else
	upper_num = *(u64 *)(data + 8);
	lower_num = *(u64 *)data;
#endif
	if (upper_num == 0)
		btf_show_type_value(show, "0x%llx", lower_num);
	else
		btf_show_type_values(show, "0x%llx%016llx", upper_num,
				     lower_num);
}

static void btf_int128_shift(u64 *print_num, u16 left_shift_bits,
			     u16 right_shift_bits)
{
	u64 upper_num, lower_num;

#ifdef __BIG_ENDIAN_BITFIELD
	upper_num = print_num[0];
	lower_num = print_num[1];
#else
	upper_num = print_num[1];
	lower_num = print_num[0];
#endif

	/* shake out un-needed bits by shift/or operations */
	if (left_shift_bits >= 64) {
		upper_num = lower_num << (left_shift_bits - 64);
		lower_num = 0;
	} else {
		upper_num = (upper_num << left_shift_bits) |
			    (lower_num >> (64 - left_shift_bits));
		lower_num = lower_num << left_shift_bits;
	}

	if (right_shift_bits >= 64) {
		lower_num = upper_num >> (right_shift_bits - 64);
		upper_num = 0;
	} else {
		lower_num = (lower_num >> right_shift_bits) |
			    (upper_num << (64 - right_shift_bits));
		upper_num = upper_num >> right_shift_bits;
	}

#ifdef __BIG_ENDIAN_BITFIELD
	print_num[0] = upper_num;
	print_num[1] = lower_num;
#else
	print_num[0] = lower_num;
	print_num[1] = upper_num;
#endif
}

static void btf_bitfield_show(void *data, u8 bits_offset,
			      u8 nr_bits, struct btf_show *show)
{
	u16 left_shift_bits, right_shift_bits;
	u8 nr_copy_bytes;
	u8 nr_copy_bits;
	u64 print_num[2] = {};

	nr_copy_bits = nr_bits + bits_offset;
	nr_copy_bytes = BITS_ROUNDUP_BYTES(nr_copy_bits);

	memcpy(print_num, data, nr_copy_bytes);

#ifdef __BIG_ENDIAN_BITFIELD
	left_shift_bits = bits_offset;
#else
	left_shift_bits = BITS_PER_U128 - nr_copy_bits;
#endif
	right_shift_bits = BITS_PER_U128 - nr_bits;

	btf_int128_shift(print_num, left_shift_bits, right_shift_bits);
	btf_int128_print(show, print_num);
}


static void btf_int_bits_show(const struct btf *btf,
			      const struct btf_type *t,
			      void *data, u8 bits_offset,
			      struct btf_show *show)
{
	u32 int_data = btf_type_int(t);
	u8 nr_bits = BTF_INT_BITS(int_data);
	u8 total_bits_offset;

	/*
	 * bits_offset is at most 7.
	 * BTF_INT_OFFSET() cannot exceed 128 bits.
	 */
	total_bits_offset = bits_offset + BTF_INT_OFFSET(int_data);
	data += BITS_ROUNDDOWN_BYTES(total_bits_offset);
	bits_offset = BITS_PER_BYTE_MASKED(total_bits_offset);
	btf_bitfield_show(data, bits_offset, nr_bits, show);
}

static void btf_int_show(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offset,
			 struct btf_show *show)
{
	u32 int_data = btf_type_int(t);
	u8 encoding = BTF_INT_ENCODING(int_data);
	bool sign = encoding & BTF_INT_SIGNED;
	u8 nr_bits = BTF_INT_BITS(int_data);
	void *safe_data;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	if (bits_offset || BTF_INT_OFFSET(int_data) ||
	    BITS_PER_BYTE_MASKED(nr_bits)) {
		btf_int_bits_show(btf, t, safe_data, bits_offset, show);
		goto out;
	}

	switch (nr_bits) {
	case 128:
		btf_int128_print(show, safe_data);
		break;
	case 64:
		if (sign)
			btf_show_type_value(show, "%lld", *(s64 *)safe_data);
		else
			btf_show_type_value(show, "%llu", *(u64 *)safe_data);
		break;
	case 32:
		if (sign)
			btf_show_type_value(show, "%d", *(s32 *)safe_data);
		else
			btf_show_type_value(show, "%u", *(u32 *)safe_data);
		break;
	case 16:
		if (sign)
			btf_show_type_value(show, "%d", *(s16 *)safe_data);
		else
			btf_show_type_value(show, "%u", *(u16 *)safe_data);
		break;
	case 8:
		if (show->state.array_encoding == BTF_INT_CHAR) {
			/* check for null terminator */
			if (show->state.array_terminated)
				break;
			if (*(char *)data == '\0') {
				show->state.array_terminated = 1;
				break;
			}
			if (isprint(*(char *)data)) {
				btf_show_type_value(show, "'%c'",
						    *(char *)safe_data);
				break;
			}
		}
		if (sign)
			btf_show_type_value(show, "%d", *(s8 *)safe_data);
		else
			btf_show_type_value(show, "%u", *(u8 *)safe_data);
		break;
	default:
		btf_int_bits_show(btf, t, safe_data, bits_offset, show);
		break;
	}
out:
	btf_show_end_type(show);
}

static const struct btf_kind_operations int_ops = {
	.check_meta = btf_int_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_int_check_member,
	.check_kflag_member = btf_int_check_kflag_member,
	.log_details = btf_int_log,
	.show = btf_int_show,
};

static int btf_modifier_check_member(struct btf_verifier_env *env,
				     const struct btf_type *struct_type,
				     const struct btf_member *member,
				     const struct btf_type *member_type)
{
	const struct btf_type *resolved_type;
	u32 resolved_type_id = member->type;
	struct btf_member resolved_member;
	struct btf *btf = env->btf;

	resolved_type = btf_type_id_size(btf, &resolved_type_id, NULL);
	if (!resolved_type) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member");
		return -EINVAL;
	}

	resolved_member = *member;
	resolved_member.type = resolved_type_id;

	return btf_type_ops(resolved_type)->check_member(env, struct_type,
							 &resolved_member,
							 resolved_type);
}

static int btf_modifier_check_kflag_member(struct btf_verifier_env *env,
					   const struct btf_type *struct_type,
					   const struct btf_member *member,
					   const struct btf_type *member_type)
{
	const struct btf_type *resolved_type;
	u32 resolved_type_id = member->type;
	struct btf_member resolved_member;
	struct btf *btf = env->btf;

	resolved_type = btf_type_id_size(btf, &resolved_type_id, NULL);
	if (!resolved_type) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member");
		return -EINVAL;
	}

	resolved_member = *member;
	resolved_member.type = resolved_type_id;

	return btf_type_ops(resolved_type)->check_kflag_member(env, struct_type,
							       &resolved_member,
							       resolved_type);
}

static int btf_ptr_check_member(struct btf_verifier_env *env,
				const struct btf_type *struct_type,
				const struct btf_member *member,
				const struct btf_type *member_type)
{
	u32 struct_size, struct_bits_off, bytes_offset;

	struct_size = struct_type->size;
	struct_bits_off = member->offset;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	if (struct_size - bytes_offset < sizeof(void *)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_ref_type_check_meta(struct btf_verifier_env *env,
				   const struct btf_type *t,
				   u32 meta_left)
{
	const char *value;

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t) && !btf_type_is_type_tag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (!BTF_TYPE_ID_VALID(t->type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	/* typedef/type_tag type must have a valid name, and other ref types,
	 * volatile, const, restrict, should have a null name.
	 */
	if (BTF_INFO_KIND(t->info) == BTF_KIND_TYPEDEF) {
		if (!t->name_off ||
		    !btf_name_valid_identifier(env->btf, t->name_off)) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}
	} else if (BTF_INFO_KIND(t->info) == BTF_KIND_TYPE_TAG) {
		value = btf_name_by_offset(env->btf, t->name_off);
		if (!value || !value[0]) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}
	} else {
		if (t->name_off) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static int btf_modifier_resolve(struct btf_verifier_env *env,
				const struct resolve_vertex *v)
{
	const struct btf_type *t = v->t;
	const struct btf_type *next_type;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || btf_type_is_resolve_source_only(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	/* Figure out the resolved next_type_id with size.
	 * They will be stored in the current modifier's
	 * resolved_ids and resolved_sizes such that it can
	 * save us a few type-following when we use it later (e.g. in
	 * pretty print).
	 */
	if (!btf_type_id_size(btf, &next_type_id, NULL)) {
		if (env_type_is_resolved(env, next_type_id))
			next_type = btf_type_id_resolve(btf, &next_type_id);

		/* "typedef void new_void", "const void"...etc */
		if (!btf_type_is_void(next_type) &&
		    !btf_type_is_fwd(next_type) &&
		    !btf_type_is_func_proto(next_type)) {
			btf_verifier_log_type(env, v->t, "Invalid type_id");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static int btf_var_resolve(struct btf_verifier_env *env,
			   const struct resolve_vertex *v)
{
	const struct btf_type *next_type;
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || btf_type_is_resolve_source_only(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	if (btf_type_is_modifier(next_type)) {
		const struct btf_type *resolved_type;
		u32 resolved_type_id;

		resolved_type_id = next_type_id;
		resolved_type = btf_type_id_resolve(btf, &resolved_type_id);

		if (btf_type_is_ptr(resolved_type) &&
		    !env_type_is_resolve_sink(env, resolved_type) &&
		    !env_type_is_resolved(env, resolved_type_id))
			return env_stack_push(env, resolved_type,
					      resolved_type_id);
	}

	/* We must resolve to something concrete at this point, no
	 * forward types or similar that would resolve to size of
	 * zero is allowed.
	 */
	if (!btf_type_id_size(btf, &next_type_id, NULL)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static int btf_ptr_resolve(struct btf_verifier_env *env,
			   const struct resolve_vertex *v)
{
	const struct btf_type *next_type;
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || btf_type_is_resolve_source_only(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	/* If the modifier was RESOLVED during RESOLVE_STRUCT_OR_ARRAY,
	 * the modifier may have stopped resolving when it was resolved
	 * to a ptr (last-resolved-ptr).
	 *
	 * We now need to continue from the last-resolved-ptr to
	 * ensure the last-resolved-ptr will not referring back to
	 * the current ptr (t).
	 */
	if (btf_type_is_modifier(next_type)) {
		const struct btf_type *resolved_type;
		u32 resolved_type_id;

		resolved_type_id = next_type_id;
		resolved_type = btf_type_id_resolve(btf, &resolved_type_id);

		if (btf_type_is_ptr(resolved_type) &&
		    !env_type_is_resolve_sink(env, resolved_type) &&
		    !env_type_is_resolved(env, resolved_type_id))
			return env_stack_push(env, resolved_type,
					      resolved_type_id);
	}

	if (!btf_type_id_size(btf, &next_type_id, NULL)) {
		if (env_type_is_resolved(env, next_type_id))
			next_type = btf_type_id_resolve(btf, &next_type_id);

		if (!btf_type_is_void(next_type) &&
		    !btf_type_is_fwd(next_type) &&
		    !btf_type_is_func_proto(next_type)) {
			btf_verifier_log_type(env, v->t, "Invalid type_id");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static void btf_modifier_show(const struct btf *btf,
			      const struct btf_type *t,
			      u32 type_id, void *data,
			      u8 bits_offset, struct btf_show *show)
{
	if (btf->resolved_ids)
		t = btf_type_id_resolve(btf, &type_id);
	else
		t = btf_type_skip_modifiers(btf, type_id, NULL);

	btf_type_ops(t)->show(btf, t, type_id, data, bits_offset, show);
}

static void btf_var_show(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offset,
			 struct btf_show *show)
{
	t = btf_type_id_resolve(btf, &type_id);

	btf_type_ops(t)->show(btf, t, type_id, data, bits_offset, show);
}

static void btf_ptr_show(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offset,
			 struct btf_show *show)
{
	void *safe_data;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	/* It is a hashed value unless BTF_SHOW_PTR_RAW is specified */
	if (show->flags & BTF_SHOW_PTR_RAW)
		btf_show_type_value(show, "0x%px", *(void **)safe_data);
	else
		btf_show_type_value(show, "0x%p", *(void **)safe_data);
	btf_show_end_type(show);
}

static void btf_ref_type_log(struct btf_verifier_env *env,
			     const struct btf_type *t)
{
	btf_verifier_log(env, "type_id=%u", t->type);
}

static const struct btf_kind_operations modifier_ops = {
	.check_meta = btf_ref_type_check_meta,
	.resolve = btf_modifier_resolve,
	.check_member = btf_modifier_check_member,
	.check_kflag_member = btf_modifier_check_kflag_member,
	.log_details = btf_ref_type_log,
	.show = btf_modifier_show,
};

static const struct btf_kind_operations ptr_ops = {
	.check_meta = btf_ref_type_check_meta,
	.resolve = btf_ptr_resolve,
	.check_member = btf_ptr_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_ref_type_log,
	.show = btf_ptr_show,
};

static s32 btf_fwd_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (t->type) {
		btf_verifier_log_type(env, t, "type != 0");
		return -EINVAL;
	}

	/* fwd type must have a valid name */
	if (!t->name_off ||
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static void btf_fwd_type_log(struct btf_verifier_env *env,
			     const struct btf_type *t)
{
	btf_verifier_log(env, "%s", btf_type_kflag(t) ? "union" : "struct");
}

static const struct btf_kind_operations fwd_ops = {
	.check_meta = btf_fwd_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_fwd_type_log,
	.show = btf_df_show,
};

static int btf_array_check_member(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;
	u32 array_type_id, array_size;
	struct btf *btf = env->btf;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	array_type_id = member->type;
	btf_type_id_size(btf, &array_type_id, &array_size);
	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < array_size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_array_check_meta(struct btf_verifier_env *env,
				const struct btf_type *t,
				u32 meta_left)
{
	const struct btf_array *array = btf_type_array(t);
	u32 meta_needed = sizeof(*array);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	/* array type should not have a name */
	if (t->name_off) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (t->size) {
		btf_verifier_log_type(env, t, "size != 0");
		return -EINVAL;
	}

	/* Array elem type and index type cannot be in type void,
	 * so !array->type and !array->index_type are not allowed.
	 */
	if (!array->type || !BTF_TYPE_ID_VALID(array->type)) {
		btf_verifier_log_type(env, t, "Invalid elem");
		return -EINVAL;
	}

	if (!array->index_type || !BTF_TYPE_ID_VALID(array->index_type)) {
		btf_verifier_log_type(env, t, "Invalid index");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static int btf_array_resolve(struct btf_verifier_env *env,
			     const struct resolve_vertex *v)
{
	const struct btf_array *array = btf_type_array(v->t);
	const struct btf_type *elem_type, *index_type;
	u32 elem_type_id, index_type_id;
	struct btf *btf = env->btf;
	u32 elem_size;

	/* Check array->index_type */
	index_type_id = array->index_type;
	index_type = btf_type_by_id(btf, index_type_id);
	if (btf_type_nosize_or_null(index_type) ||
	    btf_type_is_resolve_source_only(index_type)) {
		btf_verifier_log_type(env, v->t, "Invalid index");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, index_type) &&
	    !env_type_is_resolved(env, index_type_id))
		return env_stack_push(env, index_type, index_type_id);

	index_type = btf_type_id_size(btf, &index_type_id, NULL);
	if (!index_type || !btf_type_is_int(index_type) ||
	    !btf_type_int_is_regular(index_type)) {
		btf_verifier_log_type(env, v->t, "Invalid index");
		return -EINVAL;
	}

	/* Check array->type */
	elem_type_id = array->type;
	elem_type = btf_type_by_id(btf, elem_type_id);
	if (btf_type_nosize_or_null(elem_type) ||
	    btf_type_is_resolve_source_only(elem_type)) {
		btf_verifier_log_type(env, v->t,
				      "Invalid elem");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, elem_type) &&
	    !env_type_is_resolved(env, elem_type_id))
		return env_stack_push(env, elem_type, elem_type_id);

	elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
	if (!elem_type) {
		btf_verifier_log_type(env, v->t, "Invalid elem");
		return -EINVAL;
	}

	if (btf_type_is_int(elem_type) && !btf_type_int_is_regular(elem_type)) {
		btf_verifier_log_type(env, v->t, "Invalid array of int");
		return -EINVAL;
	}

	if (array->nelems && elem_size > U32_MAX / array->nelems) {
		btf_verifier_log_type(env, v->t,
				      "Array size overflows U32_MAX");
		return -EINVAL;
	}

	env_stack_pop_resolved(env, elem_type_id, elem_size * array->nelems);

	return 0;
}

static void btf_array_log(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	const struct btf_array *array = btf_type_array(t);

	btf_verifier_log(env, "type_id=%u index_type_id=%u nr_elems=%u",
			 array->type, array->index_type, array->nelems);
}

static void __btf_array_show(const struct btf *btf, const struct btf_type *t,
			     u32 type_id, void *data, u8 bits_offset,
			     struct btf_show *show)
{
	const struct btf_array *array = btf_type_array(t);
	const struct btf_kind_operations *elem_ops;
	const struct btf_type *elem_type;
	u32 i, elem_size = 0, elem_type_id;
	u16 encoding = 0;

	elem_type_id = array->type;
	elem_type = btf_type_skip_modifiers(btf, elem_type_id, NULL);
	if (elem_type && btf_type_has_size(elem_type))
		elem_size = elem_type->size;

	if (elem_type && btf_type_is_int(elem_type)) {
		u32 int_type = btf_type_int(elem_type);

		encoding = BTF_INT_ENCODING(int_type);

		/*
		 * BTF_INT_CHAR encoding never seems to be set for
		 * char arrays, so if size is 1 and element is
		 * printable as a char, we'll do that.
		 */
		if (elem_size == 1)
			encoding = BTF_INT_CHAR;
	}

	if (!btf_show_start_array_type(show, t, type_id, encoding, data))
		return;

	if (!elem_type)
		goto out;
	elem_ops = btf_type_ops(elem_type);

	for (i = 0; i < array->nelems; i++) {

		btf_show_start_array_member(show);

		elem_ops->show(btf, elem_type, elem_type_id, data,
			       bits_offset, show);
		data += elem_size;

		btf_show_end_array_member(show);

		if (show->state.array_terminated)
			break;
	}
out:
	btf_show_end_array_type(show);
}

static void btf_array_show(const struct btf *btf, const struct btf_type *t,
			   u32 type_id, void *data, u8 bits_offset,
			   struct btf_show *show)
{
	const struct btf_member *m = show->state.member;

	/*
	 * First check if any members would be shown (are non-zero).
	 * See comments above "struct btf_show" definition for more
	 * details on how this works at a high-level.
	 */
	if (show->state.depth > 0 && !(show->flags & BTF_SHOW_ZERO)) {
		if (!show->state.depth_check) {
			show->state.depth_check = show->state.depth + 1;
			show->state.depth_to_show = 0;
		}
		__btf_array_show(btf, t, type_id, data, bits_offset, show);
		show->state.member = m;

		if (show->state.depth_check != show->state.depth + 1)
			return;
		show->state.depth_check = 0;

		if (show->state.depth_to_show <= show->state.depth)
			return;
		/*
		 * Reaching here indicates we have recursed and found
		 * non-zero array member(s).
		 */
	}
	__btf_array_show(btf, t, type_id, data, bits_offset, show);
}

static const struct btf_kind_operations array_ops = {
	.check_meta = btf_array_check_meta,
	.resolve = btf_array_resolve,
	.check_member = btf_array_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_array_log,
	.show = btf_array_show,
};

static int btf_struct_check_member(struct btf_verifier_env *env,
				   const struct btf_type *struct_type,
				   const struct btf_member *member,
				   const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < member_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_struct_check_meta(struct btf_verifier_env *env,
				 const struct btf_type *t,
				 u32 meta_left)
{
	bool is_union = BTF_INFO_KIND(t->info) == BTF_KIND_UNION;
	const struct btf_member *member;
	u32 meta_needed, last_offset;
	struct btf *btf = env->btf;
	u32 struct_size = t->size;
	u32 offset;
	u16 i;

	meta_needed = btf_type_vlen(t) * sizeof(*member);
	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	/* struct type either no name or a valid one */
	if (t->name_off &&
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	last_offset = 0;
	for_each_member(i, t, member) {
		if (!btf_name_offset_valid(btf, member->name_off)) {
			btf_verifier_log_member(env, t, member,
						"Invalid member name_offset:%u",
						member->name_off);
			return -EINVAL;
		}

		/* struct member either no name or a valid one */
		if (member->name_off &&
		    !btf_name_valid_identifier(btf, member->name_off)) {
			btf_verifier_log_member(env, t, member, "Invalid name");
			return -EINVAL;
		}
		/* A member cannot be in type void */
		if (!member->type || !BTF_TYPE_ID_VALID(member->type)) {
			btf_verifier_log_member(env, t, member,
						"Invalid type_id");
			return -EINVAL;
		}

		offset = __btf_member_bit_offset(t, member);
		if (is_union && offset) {
			btf_verifier_log_member(env, t, member,
						"Invalid member bits_offset");
			return -EINVAL;
		}

		/*
		 * ">" instead of ">=" because the last member could be
		 * "char a[0];"
		 */
		if (last_offset > offset) {
			btf_verifier_log_member(env, t, member,
						"Invalid member bits_offset");
			return -EINVAL;
		}

		if (BITS_ROUNDUP_BYTES(offset) > struct_size) {
			btf_verifier_log_member(env, t, member,
						"Member bits_offset exceeds its struct size");
			return -EINVAL;
		}

		btf_verifier_log_member(env, t, member, NULL);
		last_offset = offset;
	}

	return meta_needed;
}

static int btf_struct_resolve(struct btf_verifier_env *env,
			      const struct resolve_vertex *v)
{
	const struct btf_member *member;
	int err;
	u16 i;

	/* Before continue resolving the next_member,
	 * ensure the last member is indeed resolved to a
	 * type with size info.
	 */
	if (v->next_member) {
		const struct btf_type *last_member_type;
		const struct btf_member *last_member;
		u32 last_member_type_id;

		last_member = btf_type_member(v->t) + v->next_member - 1;
		last_member_type_id = last_member->type;
		if (WARN_ON_ONCE(!env_type_is_resolved(env,
						       last_member_type_id)))
			return -EINVAL;

		last_member_type = btf_type_by_id(env->btf,
						  last_member_type_id);
		if (btf_type_kflag(v->t))
			err = btf_type_ops(last_member_type)->check_kflag_member(env, v->t,
								last_member,
								last_member_type);
		else
			err = btf_type_ops(last_member_type)->check_member(env, v->t,
								last_member,
								last_member_type);
		if (err)
			return err;
	}

	for_each_member_from(i, v->next_member, v->t, member) {
		u32 member_type_id = member->type;
		const struct btf_type *member_type = btf_type_by_id(env->btf,
								member_type_id);

		if (btf_type_nosize_or_null(member_type) ||
		    btf_type_is_resolve_source_only(member_type)) {
			btf_verifier_log_member(env, v->t, member,
						"Invalid member");
			return -EINVAL;
		}

		if (!env_type_is_resolve_sink(env, member_type) &&
		    !env_type_is_resolved(env, member_type_id)) {
			env_stack_set_next_member(env, i + 1);
			return env_stack_push(env, member_type, member_type_id);
		}

		if (btf_type_kflag(v->t))
			err = btf_type_ops(member_type)->check_kflag_member(env, v->t,
									    member,
									    member_type);
		else
			err = btf_type_ops(member_type)->check_member(env, v->t,
								      member,
								      member_type);
		if (err)
			return err;
	}

	env_stack_pop_resolved(env, 0, 0);

	return 0;
}

static void btf_struct_log(struct btf_verifier_env *env,
			   const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}


static void __btf_struct_show(const struct btf *btf, const struct btf_type *t,
			      u32 type_id, void *data, u8 bits_offset,
			      struct btf_show *show)
{
	const struct btf_member *member;
	void *safe_data;
	u32 i;

	safe_data = btf_show_start_struct_type(show, t, type_id, data);
	if (!safe_data)
		return;

	for_each_member(i, t, member) {
		const struct btf_type *member_type = btf_type_by_id(btf,
								member->type);
		const struct btf_kind_operations *ops;
		u32 member_offset, bitfield_size;
		u32 bytes_offset;
		u8 bits8_offset;

		btf_show_start_member(show, member);

		member_offset = __btf_member_bit_offset(t, member);
		bitfield_size = __btf_member_bitfield_size(t, member);
		bytes_offset = BITS_ROUNDDOWN_BYTES(member_offset);
		bits8_offset = BITS_PER_BYTE_MASKED(member_offset);
		if (bitfield_size) {
			safe_data = btf_show_start_type(show, member_type,
							member->type,
							data + bytes_offset);
			if (safe_data)
				btf_bitfield_show(safe_data,
						  bits8_offset,
						  bitfield_size, show);
			btf_show_end_type(show);
		} else {
			ops = btf_type_ops(member_type);
			ops->show(btf, member_type, member->type,
				  data + bytes_offset, bits8_offset, show);
		}

		btf_show_end_member(show);
	}

	btf_show_end_struct_type(show);
}

static void btf_struct_show(const struct btf *btf, const struct btf_type *t,
			    u32 type_id, void *data, u8 bits_offset,
			    struct btf_show *show)
{
	const struct btf_member *m = show->state.member;

	/*
	 * First check if any members would be shown (are non-zero).
	 * See comments above "struct btf_show" definition for more
	 * details on how this works at a high-level.
	 */
	if (show->state.depth > 0 && !(show->flags & BTF_SHOW_ZERO)) {
		if (!show->state.depth_check) {
			show->state.depth_check = show->state.depth + 1;
			show->state.depth_to_show = 0;
		}
		__btf_struct_show(btf, t, type_id, data, bits_offset, show);
		/* Restore saved member data here */
		show->state.member = m;
		if (show->state.depth_check != show->state.depth + 1)
			return;
		show->state.depth_check = 0;

		if (show->state.depth_to_show <= show->state.depth)
			return;
		/*
		 * Reaching here indicates we have recursed and found
		 * non-zero child values.
		 */
	}

	__btf_struct_show(btf, t, type_id, data, bits_offset, show);
}

static const struct btf_kind_operations struct_ops = {
	.check_meta = btf_struct_check_meta,
	.resolve = btf_struct_resolve,
	.check_member = btf_struct_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_struct_log,
	.show = btf_struct_show,
};

static int btf_enum_check_member(struct btf_verifier_env *env,
				 const struct btf_type *struct_type,
				 const struct btf_member *member,
				 const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < member_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_enum_check_kflag_member(struct btf_verifier_env *env,
				       const struct btf_type *struct_type,
				       const struct btf_member *member,
				       const struct btf_type *member_type)
{
	u32 struct_bits_off, nr_bits, bytes_end, struct_size;
	u32 int_bitsize = sizeof(int) * BITS_PER_BYTE;

	struct_bits_off = BTF_MEMBER_BIT_OFFSET(member->offset);
	nr_bits = BTF_MEMBER_BITFIELD_SIZE(member->offset);
	if (!nr_bits) {
		if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
			btf_verifier_log_member(env, struct_type, member,
						"Member is not byte aligned");
			return -EINVAL;
		}

		nr_bits = int_bitsize;
	} else if (nr_bits > int_bitsize) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member bitfield_size");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_end = BITS_ROUNDUP_BYTES(struct_bits_off + nr_bits);
	if (struct_size < bytes_end) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_enum_check_meta(struct btf_verifier_env *env,
			       const struct btf_type *t,
			       u32 meta_left)
{
	const struct btf_enum *enums = btf_type_enum(t);
	struct btf *btf = env->btf;
	const char *fmt_str;
	u16 i, nr_enums;
	u32 meta_needed;

	nr_enums = btf_type_vlen(t);
	meta_needed = nr_enums * sizeof(*enums);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (t->size > 8 || !is_power_of_2(t->size)) {
		btf_verifier_log_type(env, t, "Unexpected size");
		return -EINVAL;
	}

	/* enum type either no name or a valid one */
	if (t->name_off &&
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	for (i = 0; i < nr_enums; i++) {
		if (!btf_name_offset_valid(btf, enums[i].name_off)) {
			btf_verifier_log(env, "\tInvalid name_offset:%u",
					 enums[i].name_off);
			return -EINVAL;
		}

		/* enum member must have a valid name */
		if (!enums[i].name_off ||
		    !btf_name_valid_identifier(btf, enums[i].name_off)) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}

		if (env->log.level == BPF_LOG_KERNEL)
			continue;
		fmt_str = btf_type_kflag(t) ? "\t%s val=%d\n" : "\t%s val=%u\n";
		btf_verifier_log(env, fmt_str,
				 __btf_name_by_offset(btf, enums[i].name_off),
				 enums[i].val);
	}

	return meta_needed;
}

static void btf_enum_log(struct btf_verifier_env *env,
			 const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}

static void btf_enum_show(const struct btf *btf, const struct btf_type *t,
			  u32 type_id, void *data, u8 bits_offset,
			  struct btf_show *show)
{
	const struct btf_enum *enums = btf_type_enum(t);
	u32 i, nr_enums = btf_type_vlen(t);
	void *safe_data;
	int v;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	v = *(int *)safe_data;

	for (i = 0; i < nr_enums; i++) {
		if (v != enums[i].val)
			continue;

		btf_show_type_value(show, "%s",
				    __btf_name_by_offset(btf,
							 enums[i].name_off));

		btf_show_end_type(show);
		return;
	}

	if (btf_type_kflag(t))
		btf_show_type_value(show, "%d", v);
	else
		btf_show_type_value(show, "%u", v);
	btf_show_end_type(show);
}

static const struct btf_kind_operations enum_ops = {
	.check_meta = btf_enum_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_enum_check_member,
	.check_kflag_member = btf_enum_check_kflag_member,
	.log_details = btf_enum_log,
	.show = btf_enum_show,
};

static s32 btf_enum64_check_meta(struct btf_verifier_env *env,
				 const struct btf_type *t,
				 u32 meta_left)
{
	const struct btf_enum64 *enums = btf_type_enum64(t);
	struct btf *btf = env->btf;
	const char *fmt_str;
	u16 i, nr_enums;
	u32 meta_needed;

	nr_enums = btf_type_vlen(t);
	meta_needed = nr_enums * sizeof(*enums);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (t->size > 8 || !is_power_of_2(t->size)) {
		btf_verifier_log_type(env, t, "Unexpected size");
		return -EINVAL;
	}

	/* enum type either no name or a valid one */
	if (t->name_off &&
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	for (i = 0; i < nr_enums; i++) {
		if (!btf_name_offset_valid(btf, enums[i].name_off)) {
			btf_verifier_log(env, "\tInvalid name_offset:%u",
					 enums[i].name_off);
			return -EINVAL;
		}

		/* enum member must have a valid name */
		if (!enums[i].name_off ||
		    !btf_name_valid_identifier(btf, enums[i].name_off)) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}

		if (env->log.level == BPF_LOG_KERNEL)
			continue;

		fmt_str = btf_type_kflag(t) ? "\t%s val=%lld\n" : "\t%s val=%llu\n";
		btf_verifier_log(env, fmt_str,
				 __btf_name_by_offset(btf, enums[i].name_off),
				 btf_enum64_value(enums + i));
	}

	return meta_needed;
}

static void btf_enum64_show(const struct btf *btf, const struct btf_type *t,
			    u32 type_id, void *data, u8 bits_offset,
			    struct btf_show *show)
{
	const struct btf_enum64 *enums = btf_type_enum64(t);
	u32 i, nr_enums = btf_type_vlen(t);
	void *safe_data;
	s64 v;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	v = *(u64 *)safe_data;

	for (i = 0; i < nr_enums; i++) {
		if (v != btf_enum64_value(enums + i))
			continue;

		btf_show_type_value(show, "%s",
				    __btf_name_by_offset(btf,
							 enums[i].name_off));

		btf_show_end_type(show);
		return;
	}

	if (btf_type_kflag(t))
		btf_show_type_value(show, "%lld", v);
	else
		btf_show_type_value(show, "%llu", v);
	btf_show_end_type(show);
}

static const struct btf_kind_operations enum64_ops = {
	.check_meta = btf_enum64_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_enum_check_member,
	.check_kflag_member = btf_enum_check_kflag_member,
	.log_details = btf_enum_log,
	.show = btf_enum64_show,
};

static s32 btf_func_proto_check_meta(struct btf_verifier_env *env,
				     const struct btf_type *t,
				     u32 meta_left)
{
	u32 meta_needed = btf_type_vlen(t) * sizeof(struct btf_param);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (t->name_off) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_func_proto_log(struct btf_verifier_env *env,
			       const struct btf_type *t)
{
	const struct btf_param *args = (const struct btf_param *)(t + 1);
	u16 nr_args = btf_type_vlen(t), i;

	btf_verifier_log(env, "return=%u args=(", t->type);
	if (!nr_args) {
		btf_verifier_log(env, "void");
		goto done;
	}

	if (nr_args == 1 && !args[0].type) {
		/* Only one vararg */
		btf_verifier_log(env, "vararg");
		goto done;
	}

	btf_verifier_log(env, "%u %s", args[0].type,
			 __btf_name_by_offset(env->btf,
					      args[0].name_off));
	for (i = 1; i < nr_args - 1; i++)
		btf_verifier_log(env, ", %u %s", args[i].type,
				 __btf_name_by_offset(env->btf,
						      args[i].name_off));

	if (nr_args > 1) {
		const struct btf_param *last_arg = &args[nr_args - 1];

		if (last_arg->type)
			btf_verifier_log(env, ", %u %s", last_arg->type,
					 __btf_name_by_offset(env->btf,
							      last_arg->name_off));
		else
			btf_verifier_log(env, ", vararg");
	}

done:
	btf_verifier_log(env, ")");
}

static const struct btf_kind_operations func_proto_ops = {
	.check_meta = btf_func_proto_check_meta,
	.resolve = btf_df_resolve,
	/*
	 * BTF_KIND_FUNC_PROTO cannot be directly referred by
	 * a struct's member.
	 *
	 * It should be a function pointer instead.
	 * (i.e. struct's member -> BTF_KIND_PTR -> BTF_KIND_FUNC_PROTO)
	 *
	 * Hence, there is no btf_func_check_member().
	 */
	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_func_proto_log,
	.show = btf_df_show,
};

static s32 btf_func_check_meta(struct btf_verifier_env *env,
			       const struct btf_type *t,
			       u32 meta_left)
{
	if (!t->name_off ||
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	if (btf_type_vlen(t) > BTF_FUNC_GLOBAL) {
		btf_verifier_log_type(env, t, "Invalid func linkage");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static int btf_func_resolve(struct btf_verifier_env *env,
			    const struct resolve_vertex *v)
{
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	int err;

	err = btf_func_check(env, t);
	if (err)
		return err;

	env_stack_pop_resolved(env, next_type_id, 0);
	return 0;
}

static const struct btf_kind_operations func_ops = {
	.check_meta = btf_func_check_meta,
	.resolve = btf_func_resolve,
	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_ref_type_log,
	.show = btf_df_show,
};

static s32 btf_var_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	const struct btf_var *var;
	u32 meta_needed = sizeof(*var);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (!t->name_off ||
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	/* A var cannot be in type void */
	if (!t->type || !BTF_TYPE_ID_VALID(t->type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	var = btf_type_var(t);
	if (var->linkage != BTF_VAR_STATIC &&
	    var->linkage != BTF_VAR_GLOBAL_ALLOCATED) {
		btf_verifier_log_type(env, t, "Linkage not supported");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_var_log(struct btf_verifier_env *env, const struct btf_type *t)
{
	const struct btf_var *var = btf_type_var(t);

	btf_verifier_log(env, "type_id=%u linkage=%u", t->type, var->linkage);
}

static const struct btf_kind_operations var_ops = {
	.check_meta		= btf_var_check_meta,
	.resolve		= btf_var_resolve,
	.check_member		= btf_df_check_member,
	.check_kflag_member	= btf_df_check_kflag_member,
	.log_details		= btf_var_log,
	.show			= btf_var_show,
};

static s32 btf_datasec_check_meta(struct btf_verifier_env *env,
				  const struct btf_type *t,
				  u32 meta_left)
{
	const struct btf_var_secinfo *vsi;
	u64 last_vsi_end_off = 0, sum = 0;
	u32 i, meta_needed;

	meta_needed = btf_type_vlen(t) * sizeof(*vsi);
	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (!t->size) {
		btf_verifier_log_type(env, t, "size == 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (!t->name_off ||
	    !btf_name_valid_section(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	for_each_vsi(i, t, vsi) {
		/* A var cannot be in type void */
		if (!vsi->type || !BTF_TYPE_ID_VALID(vsi->type)) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid type_id");
			return -EINVAL;
		}

		if (vsi->offset < last_vsi_end_off || vsi->offset >= t->size) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid offset");
			return -EINVAL;
		}

		if (!vsi->size || vsi->size > t->size) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid size");
			return -EINVAL;
		}

		last_vsi_end_off = vsi->offset + vsi->size;
		if (last_vsi_end_off > t->size) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid offset+size");
			return -EINVAL;
		}

		btf_verifier_log_vsi(env, t, vsi, NULL);
		sum += vsi->size;
	}

	if (t->size < sum) {
		btf_verifier_log_type(env, t, "Invalid btf_info size");
		return -EINVAL;
	}

	return meta_needed;
}

static int btf_datasec_resolve(struct btf_verifier_env *env,
			       const struct resolve_vertex *v)
{
	const struct btf_var_secinfo *vsi;
	struct btf *btf = env->btf;
	u16 i;

	env->resolve_mode = RESOLVE_TBD;
	for_each_vsi_from(i, v->next_member, v->t, vsi) {
		u32 var_type_id = vsi->type, type_id, type_size = 0;
		const struct btf_type *var_type = btf_type_by_id(env->btf,
								 var_type_id);
		if (!var_type || !btf_type_is_var(var_type)) {
			btf_verifier_log_vsi(env, v->t, vsi,
					     "Not a VAR kind member");
			return -EINVAL;
		}

		if (!env_type_is_resolve_sink(env, var_type) &&
		    !env_type_is_resolved(env, var_type_id)) {
			env_stack_set_next_member(env, i + 1);
			return env_stack_push(env, var_type, var_type_id);
		}

		type_id = var_type->type;
		if (!btf_type_id_size(btf, &type_id, &type_size)) {
			btf_verifier_log_vsi(env, v->t, vsi, "Invalid type");
			return -EINVAL;
		}

		if (vsi->size < type_size) {
			btf_verifier_log_vsi(env, v->t, vsi, "Invalid size");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, 0, 0);
	return 0;
}

static void btf_datasec_log(struct btf_verifier_env *env,
			    const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}

static void btf_datasec_show(const struct btf *btf,
			     const struct btf_type *t, u32 type_id,
			     void *data, u8 bits_offset,
			     struct btf_show *show)
{
	const struct btf_var_secinfo *vsi;
	const struct btf_type *var;
	u32 i;

	if (!btf_show_start_type(show, t, type_id, data))
		return;

	btf_show_type_value(show, "section (\"%s\") = {",
			    __btf_name_by_offset(btf, t->name_off));
	for_each_vsi(i, t, vsi) {
		var = btf_type_by_id(btf, vsi->type);
		if (i)
			btf_show(show, ",");
		btf_type_ops(var)->show(btf, var, vsi->type,
					data + vsi->offset, bits_offset, show);
	}
	btf_show_end_type(show);
}

static const struct btf_kind_operations datasec_ops = {
	.check_meta		= btf_datasec_check_meta,
	.resolve		= btf_datasec_resolve,
	.check_member		= btf_df_check_member,
	.check_kflag_member	= btf_df_check_kflag_member,
	.log_details		= btf_datasec_log,
	.show			= btf_datasec_show,
};

static s32 btf_float_check_meta(struct btf_verifier_env *env,
				const struct btf_type *t,
				u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (t->size != 2 && t->size != 4 && t->size != 8 && t->size != 12 &&
	    t->size != 16) {
		btf_verifier_log_type(env, t, "Invalid type_size");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static int btf_float_check_member(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type)
{
	u64 start_offset_bytes;
	u64 end_offset_bytes;
	u64 misalign_bits;
	u64 align_bytes;
	u64 align_bits;

	/* Different architectures have different alignment requirements, so
	 * here we check only for the reasonable minimum. This way we ensure
	 * that types after CO-RE can pass the kernel BTF verifier.
	 */
	align_bytes = min_t(u64, sizeof(void *), member_type->size);
	align_bits = align_bytes * BITS_PER_BYTE;
	div64_u64_rem(member->offset, align_bits, &misalign_bits);
	if (misalign_bits) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not properly aligned");
		return -EINVAL;
	}

	start_offset_bytes = member->offset / BITS_PER_BYTE;
	end_offset_bytes = start_offset_bytes + member_type->size;
	if (end_offset_bytes > struct_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static void btf_float_log(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u", t->size);
}

static const struct btf_kind_operations float_ops = {
	.check_meta = btf_float_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_float_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_float_log,
	.show = btf_df_show,
};

static s32 btf_decl_tag_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	const struct btf_decl_tag *tag;
	u32 meta_needed = sizeof(*tag);
	s32 component_idx;
	const char *value;

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	value = btf_name_by_offset(env->btf, t->name_off);
	if (!value || !value[0]) {
		btf_verifier_log_type(env, t, "Invalid value");
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	component_idx = btf_type_decl_tag(t)->component_idx;
	if (component_idx < -1) {
		btf_verifier_log_type(env, t, "Invalid component_idx");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static int btf_decl_tag_resolve(struct btf_verifier_env *env,
			   const struct resolve_vertex *v)
{
	const struct btf_type *next_type;
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;
	s32 component_idx;
	u32 vlen;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || !btf_type_is_decl_tag_target(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	component_idx = btf_type_decl_tag(t)->component_idx;
	if (component_idx != -1) {
		if (btf_type_is_var(next_type) || btf_type_is_typedef(next_type)) {
			btf_verifier_log_type(env, v->t, "Invalid component_idx");
			return -EINVAL;
		}

		if (btf_type_is_struct(next_type)) {
			vlen = btf_type_vlen(next_type);
		} else {
			/* next_type should be a function */
			next_type = btf_type_by_id(btf, next_type->type);
			vlen = btf_type_vlen(next_type);
		}

		if ((u32)component_idx >= vlen) {
			btf_verifier_log_type(env, v->t, "Invalid component_idx");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static void btf_decl_tag_log(struct btf_verifier_env *env, const struct btf_type *t)
{
	btf_verifier_log(env, "type=%u component_idx=%d", t->type,
			 btf_type_decl_tag(t)->component_idx);
}

static const struct btf_kind_operations decl_tag_ops = {
	.check_meta = btf_decl_tag_check_meta,
	.resolve = btf_decl_tag_resolve,
	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_decl_tag_log,
	.show = btf_df_show,
};

static int btf_func_proto_check(struct btf_verifier_env *env,
				const struct btf_type *t)
{
	const struct btf_type *ret_type;
	const struct btf_param *args;
	const struct btf *btf;
	u16 nr_args, i;
	int err;

	btf = env->btf;
	args = (const struct btf_param *)(t + 1);
	nr_args = btf_type_vlen(t);

	/* Check func return type which could be "void" (t->type == 0) */
	if (t->type) {
		u32 ret_type_id = t->type;

		ret_type = btf_type_by_id(btf, ret_type_id);
		if (!ret_type) {
			btf_verifier_log_type(env, t, "Invalid return type");
			return -EINVAL;
		}

		if (btf_type_is_resolve_source_only(ret_type)) {
			btf_verifier_log_type(env, t, "Invalid return type");
			return -EINVAL;
		}

		if (btf_type_needs_resolve(ret_type) &&
		    !env_type_is_resolved(env, ret_type_id)) {
			err = btf_resolve(env, ret_type, ret_type_id);
			if (err)
				return err;
		}

		/* Ensure the return type is a type that has a size */
		if (!btf_type_id_size(btf, &ret_type_id, NULL)) {
			btf_verifier_log_type(env, t, "Invalid return type");
			return -EINVAL;
		}
	}

	if (!nr_args)
		return 0;

	/* Last func arg type_id could be 0 if it is a vararg */
	if (!args[nr_args - 1].type) {
		if (args[nr_args - 1].name_off) {
			btf_verifier_log_type(env, t, "Invalid arg#%u",
					      nr_args);
			return -EINVAL;
		}
		nr_args--;
	}

	for (i = 0; i < nr_args; i++) {
		const struct btf_type *arg_type;
		u32 arg_type_id;

		arg_type_id = args[i].type;
		arg_type = btf_type_by_id(btf, arg_type_id);
		if (!arg_type) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			return -EINVAL;
		}

		if (btf_type_is_resolve_source_only(arg_type)) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			return -EINVAL;
		}

		if (args[i].name_off &&
		    (!btf_name_offset_valid(btf, args[i].name_off) ||
		     !btf_name_valid_identifier(btf, args[i].name_off))) {
			btf_verifier_log_type(env, t,
					      "Invalid arg#%u", i + 1);
			return -EINVAL;
		}

		if (btf_type_needs_resolve(arg_type) &&
		    !env_type_is_resolved(env, arg_type_id)) {
			err = btf_resolve(env, arg_type, arg_type_id);
			if (err)
				return err;
		}

		if (!btf_type_id_size(btf, &arg_type_id, NULL)) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			return -EINVAL;
		}
	}

	return 0;
}

static int btf_func_check(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	const struct btf_type *proto_type;
	const struct btf_param *args;
	const struct btf *btf;
	u16 nr_args, i;

	btf = env->btf;
	proto_type = btf_type_by_id(btf, t->type);

	if (!proto_type || !btf_type_is_func_proto(proto_type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	args = (const struct btf_param *)(proto_type + 1);
	nr_args = btf_type_vlen(proto_type);
	for (i = 0; i < nr_args; i++) {
		if (!args[i].name_off && args[i].type) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			return -EINVAL;
		}
	}

	return 0;
}

static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS] = {
	[BTF_KIND_INT] = &int_ops,
	[BTF_KIND_PTR] = &ptr_ops,
	[BTF_KIND_ARRAY] = &array_ops,
	[BTF_KIND_STRUCT] = &struct_ops,
	[BTF_KIND_UNION] = &struct_ops,
	[BTF_KIND_ENUM] = &enum_ops,
	[BTF_KIND_FWD] = &fwd_ops,
	[BTF_KIND_TYPEDEF] = &modifier_ops,
	[BTF_KIND_VOLATILE] = &modifier_ops,
	[BTF_KIND_CONST] = &modifier_ops,
	[BTF_KIND_RESTRICT] = &modifier_ops,
	[BTF_KIND_FUNC] = &func_ops,
	[BTF_KIND_FUNC_PROTO] = &func_proto_ops,
	[BTF_KIND_VAR] = &var_ops,
	[BTF_KIND_DATASEC] = &datasec_ops,
	[BTF_KIND_FLOAT] = &float_ops,
	[BTF_KIND_DECL_TAG] = &decl_tag_ops,
	[BTF_KIND_TYPE_TAG] = &modifier_ops,
	[BTF_KIND_ENUM64] = &enum64_ops,
};

static s32 btf_check_meta(struct btf_verifier_env *env,
			  const struct btf_type *t,
			  u32 meta_left)
{
	u32 saved_meta_left = meta_left;
	s32 var_meta_size;

	if (meta_left < sizeof(*t)) {
		btf_verifier_log(env, "[%u] meta_left:%u meta_needed:%zu",
				 env->log_type_id, meta_left, sizeof(*t));
		return -EINVAL;
	}
	meta_left -= sizeof(*t);

	if (t->info & ~BTF_INFO_MASK) {
		btf_verifier_log(env, "[%u] Invalid btf_info:%x",
				 env->log_type_id, t->info);
		return -EINVAL;
	}

	if (BTF_INFO_KIND(t->info) > BTF_KIND_MAX ||
	    BTF_INFO_KIND(t->info) == BTF_KIND_UNKN) {
		btf_verifier_log(env, "[%u] Invalid kind:%u",
				 env->log_type_id, BTF_INFO_KIND(t->info));
		return -EINVAL;
	}

	if (!btf_name_offset_valid(env->btf, t->name_off)) {
		btf_verifier_log(env, "[%u] Invalid name_offset:%u",
				 env->log_type_id, t->name_off);
		return -EINVAL;
	}

	var_meta_size = btf_type_ops(t)->check_meta(env, t, meta_left);
	if (var_meta_size < 0)
		return var_meta_size;

	meta_left -= var_meta_size;

	return saved_meta_left - meta_left;
}

int btf_check_all_metas(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	struct btf_header *hdr;
	void *cur, *end;

	hdr = &btf->hdr;
	cur = btf->nohdr_data + hdr->type_off;
	end = cur + hdr->type_len;

	env->log_type_id = btf->base_btf ? btf->start_id : 1;
	while (cur < end) {
		struct btf_type *t = cur;
		s32 meta_size;

		meta_size = btf_check_meta(env, t, end - cur);
		if (meta_size < 0)
			return meta_size;

		btf_add_type(env, t);
		cur += meta_size;
		env->log_type_id++;
	}

	return 0;
}

static bool btf_resolve_valid(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 type_id)
{
	struct btf *btf = env->btf;

	if (!env_type_is_resolved(env, type_id))
		return false;

	if (btf_type_is_struct(t) || btf_type_is_datasec(t))
		return !btf_resolved_type_id(btf, type_id) &&
		       !btf_resolved_type_size(btf, type_id);

	if (btf_type_is_decl_tag(t) || btf_type_is_func(t))
		return btf_resolved_type_id(btf, type_id) &&
		       !btf_resolved_type_size(btf, type_id);

	if (btf_type_is_modifier(t) || btf_type_is_ptr(t) ||
	    btf_type_is_var(t)) {
		t = btf_type_id_resolve(btf, &type_id);
		return t &&
		       !btf_type_is_modifier(t) &&
		       !btf_type_is_var(t) &&
		       !btf_type_is_datasec(t);
	}

	if (btf_type_is_array(t)) {
		const struct btf_array *array = btf_type_array(t);
		const struct btf_type *elem_type;
		u32 elem_type_id = array->type;
		u32 elem_size;

		elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
		return elem_type && !btf_type_is_modifier(elem_type) &&
			(array->nelems * elem_size ==
			 btf_resolved_type_size(btf, type_id));
	}

	return false;
}

static int btf_resolve(struct btf_verifier_env *env,
		       const struct btf_type *t, u32 type_id)
{
	u32 save_log_type_id = env->log_type_id;
	const struct resolve_vertex *v;
	int err = 0;

	env->resolve_mode = RESOLVE_TBD;
	env_stack_push(env, t, type_id);
	while (!err && (v = env_stack_peak(env))) {
		env->log_type_id = v->type_id;
		err = btf_type_ops(v->t)->resolve(env, v);
	}

	env->log_type_id = type_id;
	if (err == -E2BIG) {
		btf_verifier_log_type(env, t,
				      "Exceeded max resolving depth:%u",
				      MAX_RESOLVE_DEPTH);
	} else if (err == -EEXIST) {
		btf_verifier_log_type(env, t, "Loop detected");
	}

	/* Final sanity check */
	if (!err && !btf_resolve_valid(env, t, type_id)) {
		btf_verifier_log_type(env, t, "Invalid resolve state");
		err = -EINVAL;
	}

	env->log_type_id = save_log_type_id;
	return err;
}

static int btf_check_all_types(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	const struct btf_type *t;
	u32 type_id, i;
	int err;

	err = env_resolve_init(env);
	if (err)
		return err;

	env->phase++;
	for (i = btf->base_btf ? 0 : 1; i < btf->nr_types; i++) {
		type_id = btf->start_id + i;
		t = btf_type_by_id(btf, type_id);

		env->log_type_id = type_id;
		if (btf_type_needs_resolve(t) &&
		    !env_type_is_resolved(env, type_id)) {
			err = btf_resolve(env, t, type_id);
			if (err)
				return err;
		}

		if (btf_type_is_func_proto(t)) {
			err = btf_func_proto_check(env, t);
			if (err)
				return err;
		}
	}

	return 0;
}

int btf_parse_type_sec(struct btf_verifier_env *env)
{
	const struct btf_header *hdr = &env->btf->hdr;
	int err;

	/* Type section must align to 4 bytes */
	if (hdr->type_off & (sizeof(u32) - 1)) {
		btf_verifier_log(env, "Unaligned type_off");
		return -EINVAL;
	}

	if (!env->btf->base_btf && !hdr->type_len) {
		btf_verifier_log(env, "No type found");
		return -EINVAL;
	}

	err = btf_check_all_metas(env);
	if (err)
		return err;

	return btf_check_all_types(env);
}

int btf_parse_str_sec(struct btf_verifier_env *env)
{
	const struct btf_header *hdr;
	struct btf *btf = env->btf;
	const char *start, *end;

	hdr = &btf->hdr;
	start = btf->nohdr_data + hdr->str_off;
	end = start + hdr->str_len;

	if (end != btf->data + btf->data_size) {
		btf_verifier_log(env, "String section is not at the end");
		return -EINVAL;
	}

	btf->strings = start;

	if (btf->base_btf && !hdr->str_len)
		return 0;
	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_NAME_OFFSET || end[-1]) {
		btf_verifier_log(env, "Invalid string section");
		return -EINVAL;
	}
	if (!btf->base_btf && start[0]) {
		btf_verifier_log(env, "Invalid string section");
		return -EINVAL;
	}

	return 0;
}

static const size_t btf_sec_info_offset[] = {
	offsetof(struct btf_header, type_off),
	offsetof(struct btf_header, str_off),
};

static int btf_sec_info_cmp(const void *a, const void *b)
{
	const struct btf_sec_info *x = a;
	const struct btf_sec_info *y = b;

	return (int)(x->off - y->off) ? : (int)(x->len - y->len);
}

static int btf_check_sec_info(struct btf_verifier_env *env,
			      u32 btf_data_size)
{
	struct btf_sec_info secs[ARRAY_SIZE(btf_sec_info_offset)];
	u32 total, expected_total, i;
	const struct btf_header *hdr;
	const struct btf *btf;

	btf = env->btf;
	hdr = &btf->hdr;

	/* Populate the secs from hdr */
	for (i = 0; i < ARRAY_SIZE(btf_sec_info_offset); i++)
		secs[i] = *(struct btf_sec_info *)((void *)hdr +
						   btf_sec_info_offset[i]);

	sort(secs, ARRAY_SIZE(btf_sec_info_offset),
	     sizeof(struct btf_sec_info), btf_sec_info_cmp, NULL);

	/* Check for gaps and overlap among sections */
	total = 0;
	expected_total = btf_data_size - hdr->hdr_len;
	for (i = 0; i < ARRAY_SIZE(btf_sec_info_offset); i++) {
		if (expected_total < secs[i].off) {
			btf_verifier_log(env, "Invalid section offset");
			return -EINVAL;
		}
		if (total < secs[i].off) {
			/* gap */
			btf_verifier_log(env, "Unsupported section found");
			return -EINVAL;
		}
		if (total > secs[i].off) {
			btf_verifier_log(env, "Section overlap found");
			return -EINVAL;
		}
		if (expected_total - total < secs[i].len) {
			btf_verifier_log(env,
					 "Total section length too long");
			return -EINVAL;
		}
		total += secs[i].len;
	}

	/* There is data other than hdr and known sections */
	if (expected_total != total) {
		btf_verifier_log(env, "Unsupported section found");
		return -EINVAL;
	}

	return 0;
}

int btf_parse_hdr(struct btf_verifier_env *env)
{
	u32 hdr_len, hdr_copy, btf_data_size;
	const struct btf_header *hdr;
	struct btf *btf;

	btf = env->btf;
	btf_data_size = btf->data_size;

	if (btf_data_size < offsetofend(struct btf_header, hdr_len)) {
		btf_verifier_log(env, "hdr_len not found");
		return -EINVAL;
	}

	hdr = btf->data;
	hdr_len = hdr->hdr_len;
	if (btf_data_size < hdr_len) {
		btf_verifier_log(env, "btf_header not found");
		return -EINVAL;
	}

	/* Ensure the unsupported header fields are zero */
	if (hdr_len > sizeof(btf->hdr)) {
		u8 *expected_zero = btf->data + sizeof(btf->hdr);
		u8 *end = btf->data + hdr_len;

		for (; expected_zero < end; expected_zero++) {
			if (*expected_zero) {
				btf_verifier_log(env, "Unsupported btf_header");
				return -E2BIG;
			}
		}
	}

	hdr_copy = min_t(u32, hdr_len, sizeof(btf->hdr));
	memcpy(&btf->hdr, btf->data, hdr_copy);

	hdr = &btf->hdr;

	btf_verifier_log_hdr(env, btf_data_size);

	if (hdr->magic != BTF_MAGIC) {
		btf_verifier_log(env, "Invalid magic");
		return -EINVAL;
	}

	if (hdr->version != BTF_VERSION) {
		btf_verifier_log(env, "Unsupported version");
		return -ENOTSUPP;
	}

	if (hdr->flags) {
		btf_verifier_log(env, "Unsupported flags");
		return -ENOTSUPP;
	}

	if (!btf->base_btf && btf_data_size == hdr->hdr_len) {
		btf_verifier_log(env, "No data");
		return -EINVAL;
	}

	return btf_check_sec_info(env, btf_data_size);
}


int btf_check_type_tags(struct btf_verifier_env *env,
			       struct btf *btf, int start_id)
{
	int i, n, good_id = start_id - 1;
	bool in_tags;

	n = btf_nr_types(btf);
	for (i = start_id; i < n; i++) {
		const struct btf_type *t;
		int chain_limit = 32;
		u32 cur_id = i;

		t = btf_type_by_id(btf, i);
		if (!t)
			return -EINVAL;
		if (!btf_type_is_modifier(t))
			continue;

		cond_resched();

		in_tags = btf_type_is_type_tag(t);
		while (btf_type_is_modifier(t)) {
			if (!chain_limit--) {
				btf_verifier_log(env, "Max chain length or cycle detected");
				return -ELOOP;
			}
			if (btf_type_is_type_tag(t)) {
				if (!in_tags) {
					btf_verifier_log(env, "Type tags don't precede modifiers");
					return -EINVAL;
				}
			} else if (in_tags) {
				in_tags = false;
			}
			if (cur_id <= good_id)
				break;
			/* Move to next type */
			cur_id = t->type;
			t = btf_type_by_id(btf, cur_id);
			if (!t)
				return -EINVAL;
		}
		good_id = i;
	}
	return 0;
}


struct btf *
btf_parse_base(struct btf_verifier_env *env, const char *name,
	       void *data, unsigned int data_size)
{
	struct btf *btf = NULL;
	int err;

	if (!IS_ENABLED(CONFIG_DEBUG_INFO_BTF))
		return ERR_PTR(-ENOENT);

	btf = kzalloc_obj(*btf, GFP_KERNEL | __GFP_NOWARN);
	if (!btf) {
		err = -ENOMEM;
		goto errout;
	}
	env->btf = btf;

	btf->data = data;
	btf->data_size = data_size;
	btf->kernel_btf = true;
	btf->named_start_id = 0;
	strscpy(btf->name, name);

	err = btf_parse_hdr(env);
	if (err)
		goto errout;

	btf->nohdr_data = btf->data + btf->hdr.hdr_len;

	err = btf_parse_str_sec(env);
	if (err)
		goto errout;

	err = btf_check_all_metas(env);
	if (err)
		goto errout;

	err = btf_check_type_tags(env, btf, 1);
	if (err)
		goto errout;

	btf_check_sorted(btf);
	refcount_set(&btf->refcnt, 1);

	return btf;

errout:
	if (btf) {
		kvfree(btf->types);
		kfree(btf);
	}
	return ERR_PTR(err);
}


static void btf_type_show(const struct btf *btf, u32 type_id, void *obj,
			  struct btf_show *show)
{
	const struct btf_type *t = btf_type_by_id(btf, type_id);

	show->btf = btf;
	memset(&show->state, 0, sizeof(show->state));
	memset(&show->obj, 0, sizeof(show->obj));

	btf_type_ops(t)->show(btf, t, type_id, obj, 0, show);
}

__printf(2, 0) static void btf_seq_show(struct btf_show *show, const char *fmt,
					va_list args)
{
	seq_vprintf((struct seq_file *)show->target, fmt, args);
}

int btf_type_seq_show_flags(const struct btf *btf, u32 type_id,
			    void *obj, struct seq_file *m, u64 flags)
{
	struct btf_show sseq;

	sseq.target = m;
	sseq.showfn = btf_seq_show;
	sseq.flags = flags;

	btf_type_show(btf, type_id, obj, &sseq);

	return sseq.state.status;
}

void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
		       struct seq_file *m)
{
	(void) btf_type_seq_show_flags(btf, type_id, obj, m,
				       BTF_SHOW_NONAME | BTF_SHOW_COMPACT |
				       BTF_SHOW_ZERO | BTF_SHOW_UNSAFE);
}

struct btf_show_snprintf {
	struct btf_show show;
	int len_left;		/* space left in string */
	int len;		/* length we would have written */
};

__printf(2, 0) static void btf_snprintf_show(struct btf_show *show, const char *fmt,
					     va_list args)
{
	struct btf_show_snprintf *ssnprintf = (struct btf_show_snprintf *)show;
	int len;

	len = vsnprintf(show->target, ssnprintf->len_left, fmt, args);

	if (len < 0) {
		ssnprintf->len_left = 0;
		ssnprintf->len = len;
	} else if (len >= ssnprintf->len_left) {
		/* no space, drive on to get length we would have written */
		ssnprintf->len_left = 0;
		ssnprintf->len += len;
	} else {
		ssnprintf->len_left -= len;
		ssnprintf->len += len;
		show->target += len;
	}
}

int btf_type_snprintf_show(const struct btf *btf, u32 type_id, void *obj,
			   char *buf, int len, u64 flags)
{
	struct btf_show_snprintf ssnprintf;

	ssnprintf.show.target = buf;
	ssnprintf.show.flags = flags;
	ssnprintf.show.showfn = btf_snprintf_show;
	ssnprintf.len_left = len;
	ssnprintf.len = 0;

	btf_type_show(btf, type_id, obj, (struct btf_show *)&ssnprintf);

	/* If we encountered an error, return it. */
	if (ssnprintf.show.state.status)
		return ssnprintf.show.state.status;

	/* Otherwise return length we would have written */
	return ssnprintf.len;
}


bool btf_is_kernel(const struct btf *btf)
{
	return btf->kernel_btf;
}

bool btf_is_module(const struct btf *btf)
{
	return btf->kernel_btf && strcmp(btf->name, "vmlinux") != 0;
}


bool btf_param_match_suffix(const struct btf *btf,
			    const struct btf_param *arg,
			    const char *suffix)
{
	int suffix_len = strlen(suffix), len;
	const char *param_name;

	/* In the future, this can be ported to use BTF tagging */
	param_name = btf_name_by_offset(btf, arg->name_off);
	if (str_is_empty(param_name))
		return false;
	len = strlen(param_name);
	if (len <= suffix_len)
		return false;
	param_name += len - suffix_len;
	return !strncmp(param_name, suffix, suffix_len);
}
