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

struct step_val {
	__u8 data[1024];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct step_val);
} step_map SEC(".maps");

/* Old register [4..130, step 2] should prune cur register [8..64, step 4]. */
SEC("socket")
__success __log_level(2)
__msg("7: (27) r6 *= 4                       ; R6=scalar({{.*}}umin32=8,{{.*}}umax32=68,{{.*}},step=0+4)")
__msg("10: (27) r7 *= 2                      ; R7=scalar({{.*}}umin32=4,{{.*}}umax32=130,{{.*}},step=0+2)")
__msg("11: (25) if r0 > 0x2a goto pc+1")
__msg("from 11 to 13: safe")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void step_prune_hit_multiple(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = r0;					\
	call %[bpf_get_prandom_u32];			\
	r7 = r0;					\
	call %[bpf_get_prandom_u32];			\
	r6 &= 0x0f;					\
	r6 += 2;					\
	r6 *= 4;					\
	r7 &= 0x3f;					\
	r7 += 2;					\
	r7 *= 2;					\
	if r0 > 42 goto 1f;	/* can't predict */	\
	r6 = r7;		/* step=2 explored first, step=4 explored next */ \
1:	r0 = r10;					\
	r6 = -r6;					\
	r0 += r6;					\
	*(u8 *)(r0 + 0) = 7;	/* force r6 precise */	\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(step_map)
	: __clobber_all);
}

/* Old register [0..126, step 2] should not prune cur register [0..45, step 3]. */
SEC("socket")
__failure __log_level(2)
__msg("6: (27) r6 *= 3                       ; R6=scalar({{.*}}smin32=0,{{.*}}umax32=45,{{.*}},step=0+3)")
__msg("8: (27) r7 *= 2                       ; R7=scalar({{.*}}smin32=0,{{.*}}umax32=126,{{.*}},step=0+2)")
__msg("9: (25) if r0 > 0x2a goto pc+1")
__msg("11: (15) if r6 == 0x3 goto pc+2")
__msg("11: R6=scalar({{.*}},step=0+2)")
__msg("13: (95) exit")
__msg("from 9 to 11: {{.*}} R6=scalar({{.*}},step=0+3)")
__msg("from 11 to 14")
__msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void step_prune_miss_non_multiple(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = r0;					\
	call %[bpf_get_prandom_u32];			\
	r7 = r0;					\
	call %[bpf_get_prandom_u32];			\
	r6 &= 0x0f;					\
	r6 *= 3;					\
	r7 &= 0x3f;					\
	r7 *= 2;					\
	if r0 > 42 goto 1f;	/* can't predict */	\
	r6 = r7;		/* step=2 explored first, step=3 explored next */ \
1:							\
	if r6 == 3 goto 2f;	/* false if step=2, should not prune step=3 */ \
	r0 = 0;						\
	exit;						\
2:							\
	r0 /= 0;		/* trap */		\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Constant current register lying on the cached line: cached is {0,3,6,...}
 * (step 3, base 0), current is the constant 6. range_within() takes the
 * constant branch: imod(6, 3) == base 0, so cur is on the line and the
 * (precise) state is pruned -> "safe".
 */
SEC("socket")
__success __log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("14: (27) r1 *= 3")		/* cached path: step 3 line */
__msg("16: (b7) r1 = 6")		/* current path: const 6, on the line */
__msg("17: safe")			/* pruned at join: imod(6, 3) == 0 */
__naked void step_prune_hit_const_on_line(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = r0;					\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[step_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l_out_%=;			\
	r7 = r0;					\
	r1 = r6;					\
	r1 &= 0xff;					\
	if r6 > 0 goto l_cur_%=;			\
	r1 *= 3;			/* old: step 3 */	\
	goto l_join_%=;					\
l_cur_%=:						\
	r1 = 6;				/* cur: const on line */	\
l_join_%=:						\
	r0 = r7;					\
	r0 += r1;			/* r1 forced precise */	\
	r2 = *(u8 *)(r0 + 0);				\
l_out_%=:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(step_map)
	: __clobber_all);
}

/*
 * Constant current register NOT on the cached line: cached is {0,3,6,...}
 * (step 3, base 0), current is the constant 7. imod(7, 3) == 1 != base 0,
 * so range_within() fails and the join is traversed again. A power-of-two
 * step is avoided on purpose: with step 3 the tnum is loose enough to admit
 * 7, so imod() is
 * the sole check that rejects it. No failure shape is possible here: 7 is
 * within the line's bounds and tnum, and the cached line path already
 * verifies the whole outro, so an eager prune could not miss an error.
 */
SEC("socket")
__success __log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
__msg("14: (27) r1 *= 3")		/* cached path: step 3 line */
__msg("16: (b7) r1 = 7")		/* current path: const 7, off the line */
/* not pruned: current continues past the join with the constant offset 7 */
__msg("19: R0=map_value({{.*}}imm=7) R1=7")
__naked void step_prune_miss_const_off_line(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = r0;					\
	r1 = 0;						\
	*(u32*)(r10 - 4) = r1;				\
	r2 = r10;					\
	r2 += -4;					\
	r1 = %[step_map] ll;				\
	call %[bpf_map_lookup_elem];			\
	if r0 == 0 goto l_out_%=;			\
	r7 = r0;					\
	r1 = r6;					\
	r1 &= 0xff;					\
	if r6 > 0 goto l_cur_%=;			\
	r1 *= 3;			/* old: step 3 */	\
	goto l_join_%=;					\
l_cur_%=:						\
	r1 = 7;				/* cur: const off line */	\
l_join_%=:						\
	r0 = r7;					\
	r0 += r1;			/* r1 forced precise */	\
	r2 = *(u8 *)(r0 + 0);				\
l_out_%=:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  __imm(bpf_map_lookup_elem),
	  __imm_addr(step_map)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
