/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2025, Oracle and/or its affiliates. */
#ifndef __LOC_BPF_H__
#define __LOC_BPF_H__

#include <linux/errno.h>
#include "bpf_helpers.h"
#include "bpf_tracing.h"

/* Below types and maps are internal implementation details of libbpf's loc
 * support and are subjects to change. Also, bpf_loc_xxx() API helpers should
 * be considered an unstable API as well and might be adjusted based on user
 * feedback from using libbpf's location support in production.
 *
 * This is based heavily upon usdt.bpf.h.
 */

/* User can override BPF_LOC_MAX_SPEC_CNT to change default size of internal
 * map that keeps track of location argument specifications. This might be
 * necessary if there are a lot of location attachments.
 */
#ifndef BPF_LOC_MAX_SPEC_CNT
#define BPF_LOC_MAX_SPEC_CNT 256
#endif
/* User can override BPF_LOC_MAX_IP_CNT to change default size of internal
 * map that keeps track of IP (memory address) mapping to loc argument
 * specification.
 * Note, if kernel supports BPF cookies, this map is not used and could be
 * resized all the way to 1 to save a bit of memory.
 */
#ifndef BPF_LOC_MAX_IP_CNT
#define BPF_LOC_MAX_IP_CNT (4 * BPF_LOC_MAX_SPEC_CNT)
#endif

enum __bpf_loc_arg_type {
	BPF_LOC_ARG_UNAVAILABLE,
	BPF_LOC_ARG_CONST,
	BPF_LOC_ARG_REG,
	BPF_LOC_ARG_REG_DEREF,
	BPF_LOC_ARG_REG_MULTI,
};

struct __bpf_loc_arg_spec {
	/* u64 scalar interpreted depending on arg_type, see below */
	__u64 val_off;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	enum __bpf_loc_arg_type arg_type: 8;
	/* reserved for future use, keeps reg_off offset stable */
	__u32 __reserved: 24;
#else
	__u32 __reserved: 24;
	enum __bpf_loc_arg_type arg_type: 8;
#endif
	/* offset of referenced register within struct pt_regs */
	union {
		short reg_off;
		short reg_offs[2];
	};
	/* whether arg should be interpreted as signed value */
	bool arg_signed;
	/* number of bits that need to be cleared and, optionally,
	 * sign-extended to cast arguments that are 1, 2, or 4 bytes
	 * long into final 8-byte u64/s64 value returned to user
	 */
	char arg_bitshift;
};

/* should match LOC_MAX_ARG_CNT in loc.c exactly */
#define BPF_LOC_MAX_ARG_CNT 12
struct __bpf_loc_spec {
	struct __bpf_loc_arg_spec args[BPF_LOC_MAX_ARG_CNT];
	__u64 loc_cookie;
	short arg_cnt;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, BPF_LOC_MAX_SPEC_CNT);
	__type(key, int);
	__type(value, struct __bpf_loc_spec);
} __bpf_loc_specs SEC(".maps") __weak;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, BPF_LOC_MAX_IP_CNT);
	__type(key, long);
	__type(value, __u32);
} __bpf_loc_ip_to_spec_id SEC(".maps") __weak;

extern const _Bool LINUX_HAS_BPF_COOKIE __kconfig;

static __always_inline
int __bpf_loc_spec_id(struct pt_regs *ctx)
{
	if (!LINUX_HAS_BPF_COOKIE) {
		long ip = PT_REGS_IP(ctx);
		int *spec_id_ptr;

		spec_id_ptr = bpf_map_lookup_elem(&__bpf_loc_ip_to_spec_id, &ip);
		return spec_id_ptr ? *spec_id_ptr : -ESRCH;
	}

	return bpf_get_attach_cookie(ctx);
}

/* Return number of loc arguments defined for currently traced loc. */
__weak __hidden
int bpf_loc_arg_cnt(struct pt_regs *ctx)
{
	struct __bpf_loc_spec *spec;
	int spec_id;

	spec_id = __bpf_loc_spec_id(ctx);
	if (spec_id < 0)
		return -ESRCH;

	spec = bpf_map_lookup_elem(&__bpf_loc_specs, &spec_id);
	if (!spec)
		return -ESRCH;

	return spec->arg_cnt;
}

/* Returns the size in bytes of the #*arg_num* (zero-indexed) loc argument.
 * Returns negative error if argument is not found or arg_num is invalid.
 */
static __always_inline
int bpf_loc_arg_size(struct pt_regs *ctx, __u64 arg_num)
{
	struct __bpf_loc_arg_spec *arg_spec;
	struct __bpf_loc_spec *spec;
	int spec_id;

	spec_id = __bpf_loc_spec_id(ctx);
	if (spec_id < 0)
		return -ESRCH;

	spec = bpf_map_lookup_elem(&__bpf_loc_specs, &spec_id);
	if (!spec)
		return -ESRCH;

	if (arg_num >= BPF_LOC_MAX_ARG_CNT)
		return -ENOENT;
	barrier_var(arg_num);
	if (arg_num >= spec->arg_cnt)
		return -ENOENT;

	arg_spec = &spec->args[arg_num];

	/* arg_spec->arg_bitshift = 64 - arg_sz * 8
	 * so: arg_sz = (64 - arg_spec->arg_bitshift) / 8
	 */
	return (unsigned int)(64 - arg_spec->arg_bitshift) / 8;
}

/* Fetch loc argument #*arg_num* (zero-indexed) and put its value into *res.
 * Returns 0 on success; negative error, otherwise.
 * On error *res is guaranteed to be set to zero.
 */
__weak __hidden
int bpf_loc_arg(struct pt_regs *ctx, __u64 arg_num, long *res)
{
	struct __bpf_loc_spec *spec;
	struct __bpf_loc_arg_spec *arg_spec;
	unsigned long val;
	int err, spec_id;

	*res = 0;

	spec_id = __bpf_loc_spec_id(ctx);
	if (spec_id < 0)
		return -ESRCH;

	spec = bpf_map_lookup_elem(&__bpf_loc_specs, &spec_id);
	if (!spec)
		return -ESRCH;

	if (arg_num >= BPF_LOC_MAX_ARG_CNT)
		return -ENOENT;
	barrier_var(arg_num);
	if (arg_num >= spec->arg_cnt)
		return -ENOENT;

	arg_spec = &spec->args[arg_num];
	switch (arg_spec->arg_type) {
	case BPF_LOC_ARG_UNAVAILABLE:
		*res = 0;
		return -ENOENT;
	case BPF_LOC_ARG_CONST:
		/* Arg is just a constant ("-4@$-9" in loc arg spec).
		 * value is recorded in arg_spec->val_off directly.
		 */
		val = arg_spec->val_off;
		break;
	case BPF_LOC_ARG_REG:
		/* Arg is stored directly in a register, so we read the
		 * contents of that register directly from struct pt_regs.
		 * To keep things simple user-space parts record
		 * offsetof(struct pt_regs, <regname>) in arg_spec->reg_off.
		 */
		err = bpf_probe_read_kernel(&val, sizeof(val), (void *)ctx + arg_spec->reg_off);
		if (err)
			return err;
		break;
	case BPF_LOC_ARG_REG_DEREF:
		/* Arg is in memory addressed by register, plus some offset
		 * Register is identified like with BPF_LOC_ARG_REG case,
		 * and the offset is in arg_spec->val_off. We first fetch
		 * register contents from pt_regs, then do another probe read
		 * to fetch argument value itself.
		 */
		err = bpf_probe_read_kernel(&val, sizeof(val), (void *)ctx + arg_spec->reg_off);
		if (err)
			return err;
		err = bpf_probe_read_kernel(&val, sizeof(val), (void *)val + arg_spec->val_off);
		if (err)
			return err;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		val >>= arg_spec->arg_bitshift;
#endif
		break;
	default:
		return -EINVAL;
	}

	/* cast arg from 1, 2, or 4 bytes to final 8 byte size clearing
	 * necessary upper arg_bitshift bits, with sign extension if argument
	 * is signed
	 */
	val <<= arg_spec->arg_bitshift;
	if (arg_spec->arg_signed)
		val = ((long)val) >> arg_spec->arg_bitshift;
	else
		val = val >> arg_spec->arg_bitshift;
	*res = val;
	return 0;
}

/* Retrieve user-specified cookie value provided during attach as
 * bpf_loc_opts.loc_cookie. This serves the same purpose as BPF cookie
 * returned by bpf_get_attach_cookie(). Libbpf's support for locs is itself
 * utilizing BPF cookies internally, so user can't use BPF cookie directly
 * for loc programs and has to use bpf_loc_cookie() API instead.
 */
__weak __hidden
long bpf_loc_cookie(struct pt_regs *ctx)
{
	struct __bpf_loc_spec *spec;
	int spec_id;

	spec_id = __bpf_loc_spec_id(ctx);
	if (spec_id < 0)
		return 0;

	spec = bpf_map_lookup_elem(&__bpf_loc_specs, &spec_id);
	if (!spec)
		return 0;

	return spec->loc_cookie;
}

/* we rely on ___bpf_apply() and ___bpf_narg() macros already defined in bpf_tracing.h */
#define ___bpf_loc_args0() ctx
#define ___bpf_loc_args1(x) ___bpf_loc_args0(), ({ long _x; bpf_loc_arg(ctx, 0, &_x); _x; })
#define ___bpf_loc_args2(x, args...) ___bpf_loc_args1(args), ({ long _x; bpf_loc_arg(ctx, 1, &_x); _x; })
#define ___bpf_loc_args3(x, args...) ___bpf_loc_args2(args), ({ long _x; bpf_loc_arg(ctx, 2, &_x); _x; })
#define ___bpf_loc_args4(x, args...) ___bpf_loc_args3(args), ({ long _x; bpf_loc_arg(ctx, 3, &_x); _x; })
#define ___bpf_loc_args5(x, args...) ___bpf_loc_args4(args), ({ long _x; bpf_loc_arg(ctx, 4, &_x); _x; })
#define ___bpf_loc_args6(x, args...) ___bpf_loc_args5(args), ({ long _x; bpf_loc_arg(ctx, 5, &_x); _x; })
#define ___bpf_loc_args7(x, args...) ___bpf_loc_args6(args), ({ long _x; bpf_loc_arg(ctx, 6, &_x); _x; })
#define ___bpf_loc_args8(x, args...) ___bpf_loc_args7(args), ({ long _x; bpf_loc_arg(ctx, 7, &_x); _x; })
#define ___bpf_loc_args9(x, args...) ___bpf_loc_args8(args), ({ long _x; bpf_loc_arg(ctx, 8, &_x); _x; })
#define ___bpf_loc_args10(x, args...) ___bpf_loc_args9(args), ({ long _x; bpf_loc_arg(ctx, 9, &_x); _x; })
#define ___bpf_loc_args11(x, args...) ___bpf_loc_args10(args), ({ long _x; bpf_loc_arg(ctx, 10, &_x); _x; })
#define ___bpf_loc_args12(x, args...) ___bpf_loc_args11(args), ({ long _x; bpf_loc_arg(ctx, 11, &_x); _x; })
#define ___bpf_loc_args(args...) ___bpf_apply(___bpf_loc_args, ___bpf_narg(args))(args)

/*
 * BPF_KLOC serves the same purpose for loc handlers as BPF_PROG for
 * tp_btf/fentry/fexit BPF programs and BPF_KPROBE for kprobes.
 * Original struct pt_regs * context is preserved as 'ctx' argument.
 */
#define BPF_KLOC(name, args...)						    \
name(struct pt_regs *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_loc_args(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)

#endif /* __LOC_BPF_H__ */
