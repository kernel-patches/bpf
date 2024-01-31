/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2024, Oracle and/or its affiliates. */

#ifndef __URDT_BPF_H__
#define __URDT_BPF_H__

#include "usdt.bpf.h"

/* Return number of URDT arguments defined; these are 1 less then the USDT-defined
 * number, as we have provider/probe hash after actual arguments.
 */
__weak __hidden
int bpf_urdt_arg_cnt(struct pt_regs *ctx)
{
	int cnt = bpf_usdt_arg_cnt(ctx);

	if (cnt < 0)
		return cnt;
	if (cnt < 1)
		return -ENOENT;
	return cnt - 1;
}

/* Fetch URDT argument #*arg_num* (zero-indexed) and put its value into *res.
 * Returns 0 on success; negative error, otherwise.
 * On error *res is guaranteed to be set to zero.
 */
__weak __hidden
int bpf_urdt_arg(struct pt_regs *ctx, __u64 arg_num, long *res)
{
	if (arg_num >= bpf_urdt_arg_cnt(ctx))
		return -ENOENT;
	return bpf_usdt_arg(ctx, arg_num, res);
}

/* Retrieve user-specified cookie value provided during attach as
 * bpf_urdt_opts.urdt_cookie.  This corresponds to the low 32 bits of
 * the 64-bit USDT cookie; the higher-order bits are a hash identifying
 * the provider/probe.
 */
__weak __hidden
int bpf_urdt_cookie(struct pt_regs *ctx)
{
	long cookie = bpf_usdt_cookie(ctx);

	return (int)cookie;
}

/* Return 0 if last USDT argument (provider/probe hash) matches high-order
 * 32 bits of USDT cookie; this tells us the probe is for us in cases
 * where the same USDT probe is shared among multiple URDT probes.
 */
static __always_inline int bpf_urdt_check_hash(struct pt_regs *ctx)
{
	int cnt = bpf_urdt_arg_cnt(ctx);
	long h = 0, cookie = bpf_usdt_cookie(ctx);

	if (cnt < 0)
		return cnt;
	if (bpf_usdt_arg(ctx, cnt, &h) || (int)h != (int)(cookie >> 32))
		return -ENOENT;
	return 0;
}

/* we rely on ___bpf_apply() and ___bpf_narg() macros already defined in bpf_tracing.h;
 * urdt args start at arg 3 (args 0, 1 and 2 are provider, probe and hash respectively)
 */
#define ___bpf_urdt_args0() ctx
#define ___bpf_urdt_args1(x) ___bpf_urdt_args0(), ({ long _x; bpf_urdt_arg(ctx, 0, &_x); (void *)_x; })
#define ___bpf_urdt_args2(x, args...) ___bpf_urdt_args1(args), ({ long _x; bpf_urdt_arg(ctx, 1, &_x); (void *)_x; })
#define ___bpf_urdt_args3(x, args...) ___bpf_urdt_args2(args), ({ long _x; bpf_urdt_arg(ctx, 2, &_x); (void *)_x; })
#define ___bpf_urdt_args4(x, args...) ___bpf_urdt_args3(args), ({ long _x; bpf_urdt_arg(ctx, 3, &_x); (void *)_x; })
#define ___bpf_urdt_args5(x, args...) ___bpf_urdt_args4(args), ({ long _x; bpf_urdt_arg(ctx, 4, &_x); (void *)_x; })
#define ___bpf_urdt_args6(x, args...) ___bpf_urdt_args5(args), ({ long _x; bpf_urdt_arg(ctx, 5, &_x); (void *)_x; })
#define ___bpf_urdt_args7(x, args...) ___bpf_urdt_args6(args), ({ long _x; bpf_urdt_arg(ctx, 6, &_x); (void *)_x; })
#define ___bpf_urdt_args8(x, args...) ___bpf_urdt_args7(args), ({ long _x; bpf_urdt_arg(ctx, 7, &_x); (void *)_x; })
#define ___bpf_urdt_args9(x, args...) ___bpf_urdt_args8(args), ({ long _x; bpf_urdt_arg(ctx, 8, &_x); (void *)_x; })
#define ___bpf_urdt_args10(x, args...) ___bpf_urdt_args9(args), ({ long _x; bpf_urdt_arg(ctx, 9, &_x); (void *)_x; })
#define ___bpf_urdt_args11(x, args...) ___bpf_urdt_args10(args), ({ long _x; bpf_urdt_arg(ctx, 10, &_x); (void *)_x; })
#define ___bpf_urdt_args(args...) ___bpf_apply(___bpf_urdt_args, ___bpf_narg(args))(args)

/*
 * BPF_URDT serves the same purpose for URDT handlers as BPF_PROG for
 * tp_btf/fentry/fexit BPF programs and BPF_KPROBE for kprobes.
 * Original struct pt_regs * context is preserved as 'ctx' argument.
 */
#define BPF_URDT(name, args...)						    \
name(struct pt_regs *ctx);						    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args);				    \
typeof(name(0)) name(struct pt_regs *ctx)				    \
{									    \
	if (bpf_urdt_check_hash(ctx))					    \
		return 0;						    \
	_Pragma("GCC diagnostic push")					    \
	_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")		    \
	return ____##name(___bpf_usdt_args(args));			    \
	_Pragma("GCC diagnostic pop")					    \
}									    \
static __always_inline typeof(name(0))					    \
____##name(struct pt_regs *ctx, ##args)

#endif /* __URDT_BPF_H__ */
