// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * Tests for the linear "base + step * k" description tracked per scalar
 * register.
 *
 * The base/step computed by scalar arithmetic is observed directly in the
 * level-2 register dump, printed as "step=<base>+<step>" when the register is
 * not the trivial base=0, step=1. Range inference that depends on the line
 * (e.g. a sign-crossing range with a non-power-of-2 step) is checked via the
 * resulting smin/smax, which feed ordinary signed branch decisions.
 *
 * Note: eq/neq branch checks do not consult base/step, so impossible-value
 * pruning is intentionally not relied upon here; the register dump is the
 * reliable signal.
 */

/* a &= 0xff; a *= 3  =>  multiples of 3, step=0+3 (not representable as tnum) */
SEC("socket")
__success __log_level(2)
__msg("r0 *= 3 {{.*}}step=0+3)")
__naked void step_mul_non_pow2(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r0 *= 3;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* a &= 0xff; a <<= 2  =>  step=0+4 */
SEC("socket")
__success __log_level(2)
__msg("r0 <<= 2 {{.*}}step=0+4)")
__naked void step_lsh(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r0 <<= 2;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* a &= 0xff; a *= 4; a += 1  =>  base shifts to 1, step=1+4 */
SEC("socket")
__success __log_level(2)
__msg("r0 += 1 {{.*}}step=1+4)")
__naked void step_add_const_base(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r0 *= 4;					\
	r0 += 1;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Sign-crossing range with a non-power-of-2 step. After "*= 3; += -3" the value
 * set is {-3, 0, 3, 6}. The line description is tracked in signed space, so the
 * intersection keeps smax=6. A u64-modular intersection would mis-place the
 * line for the negative values and wrongly narrow smax to 4.
 */
SEC("socket")
__success __log_level(2)
__msg("r0 += -3 {{.*}}smax=smax32=6)")
__naked void step_neg_value_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 3;					\
	r0 *= 3;					\
	r0 += -3;					\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Same {-3, 0, 3, 6} value set: 6 is reachable, so "if r0 s> 4" can be taken
 * and the illegal scalar dereference behind it must be rejected. Guards against
 * the unsound narrowing (smax=4) that would prune the branch and accept the
 * program. This rides on the signed comparison, which uses smin/smax.
 */
SEC("socket")
__failure __msg("invalid mem access 'scalar'")
__naked void step_neg_value_sound(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 3;					\
	r0 *= 3;					\
	r0 += -3;					\
	if r0 s> 4 goto l_bad_%=;			\
	r0 = 0;						\
	exit;						\
l_bad_%=:						\
	r1 = *(u8 *)(r0 + 0);				\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
