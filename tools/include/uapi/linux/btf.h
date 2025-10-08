/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2018 Facebook */
#ifndef _UAPI__LINUX_BTF_H__
#define _UAPI__LINUX_BTF_H__

#include <linux/types.h>

#define BTF_MAGIC	0xeB9F
#define BTF_VERSION	1

struct btf_header {
	__u16	magic;
	__u8	version;
	__u8	flags;
	__u32	hdr_len;

	/* All offsets are in bytes relative to the end of this header */
	__u32	type_off;	/* offset of type section	*/
	__u32	type_len;	/* length of type section	*/
	__u32	str_off;	/* offset of string section	*/
	__u32	str_len;	/* length of string section	*/
};

/* Max # of type identifier */
#define BTF_MAX_TYPE	0x000fffff
/* Max offset into the string section */
#define BTF_MAX_NAME_OFFSET	0x00ffffff
/* Max # of struct/union/enum members or func args */
#define BTF_MAX_VLEN	0xffff

struct btf_type {
	__u32 name_off;
	/* "info" bits arrangement
	 * bits  0-15: vlen (e.g. # of struct's members)
	 * bits 16-23: unused
	 * bits 24-28: kind (e.g. int, ptr, array...etc)
	 * bits 29-30: unused
	 * bit     31: kind_flag, currently used by
	 *             struct, union, enum, fwd, enum64,
	 *             decl_tag, type_tag and loc
	 */
	__u32 info;
	/* "size" is used by INT, ENUM, STRUCT, UNION, DATASEC, ENUM64
	 * and LOC.
	 *
	 * "size" tells the size of the type it is describing.
	 *
	 * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
	 * FUNC, FUNC_PROTO, VAR, DECL_TAG, TYPE_TAG and LOC_PROTO.
	 * "type" is a type_id referring to another type.
	 */
	union {
		__u32 size;
		__u32 type;
	};
};

#define BTF_INFO_KIND(info)	(((info) >> 24) & 0x1f)
#define BTF_INFO_VLEN(info)	((info) & 0xffff)
#define BTF_INFO_KFLAG(info)	((info) >> 31)

enum {
	BTF_KIND_UNKN		= 0,	/* Unknown	*/
	BTF_KIND_INT		= 1,	/* Integer	*/
	BTF_KIND_PTR		= 2,	/* Pointer	*/
	BTF_KIND_ARRAY		= 3,	/* Array	*/
	BTF_KIND_STRUCT		= 4,	/* Struct	*/
	BTF_KIND_UNION		= 5,	/* Union	*/
	BTF_KIND_ENUM		= 6,	/* Enumeration up to 32-bit values */
	BTF_KIND_FWD		= 7,	/* Forward	*/
	BTF_KIND_TYPEDEF	= 8,	/* Typedef	*/
	BTF_KIND_VOLATILE	= 9,	/* Volatile	*/
	BTF_KIND_CONST		= 10,	/* Const	*/
	BTF_KIND_RESTRICT	= 11,	/* Restrict	*/
	BTF_KIND_FUNC		= 12,	/* Function	*/
	BTF_KIND_FUNC_PROTO	= 13,	/* Function Proto	*/
	BTF_KIND_VAR		= 14,	/* Variable	*/
	BTF_KIND_DATASEC	= 15,	/* Section	*/
	BTF_KIND_FLOAT		= 16,	/* Floating point	*/
	BTF_KIND_DECL_TAG	= 17,	/* Decl Tag */
	BTF_KIND_TYPE_TAG	= 18,	/* Type Tag */
	BTF_KIND_ENUM64		= 19,	/* Enumeration up to 64-bit values */
	BTF_KIND_LOC_PARAM	= 20,	/* Location parameter information */
	BTF_KIND_LOC_PROTO	= 21,	/* Location prototype for site */
	BTF_KIND_LOCSEC		= 22,	/* Location section */

	NR_BTF_KINDS,
	BTF_KIND_MAX		= NR_BTF_KINDS - 1,
};

/* For some specific BTF_KIND, "struct btf_type" is immediately
 * followed by extra data.
 */

/* BTF_KIND_INT is followed by a u32 and the following
 * is the 32 bits arrangement:
 */
#define BTF_INT_ENCODING(VAL)	(((VAL) & 0x0f000000) >> 24)
#define BTF_INT_OFFSET(VAL)	(((VAL) & 0x00ff0000) >> 16)
#define BTF_INT_BITS(VAL)	((VAL)  & 0x000000ff)

/* Attributes stored in the BTF_INT_ENCODING */
#define BTF_INT_SIGNED	(1 << 0)
#define BTF_INT_CHAR	(1 << 1)
#define BTF_INT_BOOL	(1 << 2)

/* BTF_KIND_ENUM is followed by multiple "struct btf_enum".
 * The exact number of btf_enum is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_enum {
	__u32	name_off;
	__s32	val;
};

/* BTF_KIND_ARRAY is followed by one "struct btf_array" */
struct btf_array {
	__u32	type;
	__u32	index_type;
	__u32	nelems;
};

/* BTF_KIND_STRUCT and BTF_KIND_UNION are followed
 * by multiple "struct btf_member".  The exact number
 * of btf_member is stored in the vlen (of the info in
 * "struct btf_type").
 */
struct btf_member {
	__u32	name_off;
	__u32	type;
	/* If the type info kind_flag is set, the btf_member offset
	 * contains both member bitfield size and bit offset. The
	 * bitfield size is set for bitfield members. If the type
	 * info kind_flag is not set, the offset contains only bit
	 * offset.
	 */
	__u32	offset;
};

/* If the struct/union type info kind_flag is set, the
 * following two macros are used to access bitfield_size
 * and bit_offset from btf_member.offset.
 */
#define BTF_MEMBER_BITFIELD_SIZE(val)	((val) >> 24)
#define BTF_MEMBER_BIT_OFFSET(val)	((val) & 0xffffff)

/* BTF_KIND_FUNC_PROTO is followed by multiple "struct btf_param".
 * The exact number of btf_param is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_param {
	__u32	name_off;
	__u32	type;
};

enum {
	BTF_VAR_STATIC = 0,
	BTF_VAR_GLOBAL_ALLOCATED = 1,
	BTF_VAR_GLOBAL_EXTERN = 2,
};

enum btf_func_linkage {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

/* BTF_KIND_VAR is followed by a single "struct btf_var" to describe
 * additional information related to the variable such as its linkage.
 */
struct btf_var {
	__u32	linkage;
};

/* BTF_KIND_DATASEC is followed by multiple "struct btf_var_secinfo"
 * to describe all BTF_KIND_VAR types it contains along with it's
 * in-section offset as well as size.
 */
struct btf_var_secinfo {
	__u32	type;
	__u32	offset;
	__u32	size;
};

/* BTF_KIND_DECL_TAG is followed by a single "struct btf_decl_tag" to describe
 * additional information related to the tag applied location.
 * If component_idx == -1, the tag is applied to a struct, union,
 * variable or function. Otherwise, it is applied to a struct/union
 * member or a func argument, and component_idx indicates which member
 * or argument (0 ... vlen-1).
 */
struct btf_decl_tag {
       __s32   component_idx;
};

/* BTF_KIND_ENUM64 is followed by multiple "struct btf_enum64".
 * The exact number of btf_enum64 is stored in the vlen (of the
 * info in "struct btf_type").
 */
struct btf_enum64 {
	__u32	name_off;
	__u32	val_lo32;
	__u32	val_hi32;
};

/* BTF_KIND_LOC_PARAM consists a btf_type specifying a vlen of 0, name_off is 0
 * and is followed by a singular "struct btf_loc_param". type/size specifies
 * the size of the associated location value.  The size value should be
 * cast to a __s32 as negative sizes can be specified; -8 to indicate a signed
 * 8 byte value for example.
 *
 * If kind_flag is 1 the btf_loc is a constant value, otherwise it represents
 * a register, possibly dereferencing it with the specified offset.
 *
 * "struct btf_type" is followed by a "struct btf_loc_param" which consists
 * of either the 64-bit value or the register number, offset etc.
 * Interpretation depends on whether the kind_flag is set as described above.
 */

/* BTF_KIND_LOC_PARAM specifies a signed size; negative values represent signed
 * values of the specific size, for example -8 is an 8-byte signed value.
 */
#define BTF_TYPE_LOC_PARAM_SIZE(t)	((__s32)((t)->size))

/* location param specified by reg + offset is a dereference */
#define BTF_LOC_FLAG_REG_DEREF		0x1
/* next location param is needed to specify parameter location also; for example
 * when two registers are used to store a 16-byte struct by value.
 */
#define BTF_LOC_FLAG_CONTINUE		0x2

struct btf_loc_param {
	union {
		struct {
			__u16	reg;		/* register number */
			__u16	flags;		/* register dereference */
			__s32	offset;		/* offset from register-stored address */
		};
		struct {
			__u32 val_lo32;		/* lo 32 bits of 64-bit value */
			__u32 val_hi32;		/* hi 32 bits of 64-bit value */
		};
	};
};

/* BTF_KIND_LOC_PROTO specifies location prototypes; i.e. how locations relate
 * to parameters; a struct btf_type of BTF_KIND_LOC_PROTO is followed by a
 * a vlen-specified number of __u32 which specify the associated
 * BTF_KIND_LOC_PARAM for each function parameter associated with the
 * location.  The type should either be 0 (no location info) or point at
 * a BTF_KIND_LOC_PARAM.  Multiple BTF_KIND_LOC_PARAMs can be used to
 * represent a single function parameter; in such a case each should specify
 * BTF_LOC_FLAG_CONTINUE.
 *
 * The type field in the associated "struct btf_type" should point at an
 * associated BTF_KIND_FUNC_PROTO.
 */

/* BTF_KIND_LOCSEC consists of vlen-specified number of "struct btf_loc"
 * containing location site-specific information;
 *
 * - name associated with the location (name_off)
 * - function prototype type id (func_proto)
 * - location prototype type id (loc_proto)
 * - address offset (offset)
 */

struct btf_loc {
	__u32 name_off;
	__u32 func_proto;
	__u32 loc_proto;
	__u32 offset;
};

/* helps libbpf know that location declarations are present; libbpf
 * can then work around absence if this value is not set.
 */
#define BTF_KIND_LOC_UAPI_DEFINED 1

#endif /* _UAPI__LINUX_BTF_H__ */
