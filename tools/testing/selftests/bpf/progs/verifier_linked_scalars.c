// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <limits.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

SEC("socket")
__description("scalars: find linked scalars")
__failure
__msg("math between fp pointer and 2147483647 is not allowed")
__naked void scalars(void)
{
	asm volatile ("				\
	r0 = 0;					\
	r1 = 0x80000001 ll;			\
	r1 /= 1;				\
	r2 = r1;				\
	r4 = r1;				\
	w2 += 0x7FFFFFFF;			\
	w4 += 0;				\
	if r2 == 0 goto l0_%=;			\
	exit;					\
l0_%=:						\
	r4 >>= 63;				\
	r3 = 1;					\
	r3 -= r4;				\
	r3 *= 0x7FFFFFFF;			\
	r3 += r10;				\
	*(u8*)(r3 - 1) = r0;			\
	exit;					\
"	::: __clobber_all);
}

/*
 * Test that sync_linked_regs() preserves register IDs.
 *
 * The sync_linked_regs() function copies bounds from known_reg to linked
 * registers. When doing so, it must preserve each register's original id
 * to allow subsequent syncs from the same source to work correctly.
 *
 */
SEC("socket")
__success
__naked void sync_linked_regs_preserves_id(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r0 &= 0xff;	/* r0 in [0, 255] */			\
	r1 = r0;	/* r0, r1 linked with id 1 */		\
	r1 += 4;	/* r1 has id=1 and off=4 in [4, 259] */ \
	if r1 < 10 goto l0_%=;					\
	/* r1 in [10, 259], r0 synced to [6, 255] */		\
	r2 = r0;	/* r2 has id=1 and in [6, 255] */	\
	if r1 < 14 goto l0_%=;					\
	/* r1 in [14, 259], r0 synced to [10, 255] */		\
	if r0 >= 10 goto l0_%=;					\
	/* Never executed */					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__success
__naked void scalars_neg(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += -4;					\
	if r1 s< 0 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Same test but using BPF_SUB instead of BPF_ADD with negative immediate */
SEC("socket")
__success
__naked void scalars_neg_sub(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 -= 4;					\
	if r1 s< 0 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* alu32 with negative offset */
SEC("socket")
__success
__naked void scalars_neg_alu32_add(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 += -4;					\
	if w1 s< 0 goto l0_%=;				\
	if w0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* alu32 with negative offset using SUB */
SEC("socket")
__success
__naked void scalars_neg_alu32_sub(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 -= 4;					\
	if w1 s< 0 goto l0_%=;				\
	if w0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Positive offset: r1 = r0 + 4, then if r1 >= 6, r0 >= 2, so r0 != 0 */
SEC("socket")
__success
__naked void scalars_pos(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += 4;					\
	if r1 < 6 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* SUB with negative immediate: r1 -= -4 is equivalent to r1 += 4 */
SEC("socket")
__success
__naked void scalars_sub_neg_imm(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 -= -4;					\
	if r1 < 6 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Double ADD clears the ID (can't accumulate offsets) */
SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_double_add(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r1 += 2;					\
	r1 += 2;					\
	if r1 < 6 goto l0_%=;				\
	if r0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that sync_linked_regs() correctly handles large offset differences.
 * r1.off = S32_MIN, r2.off = 1, delta = S32_MIN - 1 requires 64-bit math.
 */
SEC("socket")
__success
__naked void scalars_sync_delta_overflow(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r2 = r0;					\
	r1 += %[s32_min];				\
	r2 += 1;					\
	if r2 s< 100 goto l0_%=;			\
	if r1 s< 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  [s32_min]"i"(INT_MIN)
	: __clobber_all);
}

/*
 * Another large delta case: r1.off = S32_MAX, r2.off = -1.
 * delta = S32_MAX - (-1) = S32_MAX + 1 requires 64-bit math.
 */
SEC("socket")
__success
__naked void scalars_sync_delta_overflow_large_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r0 &= 0xff;					\
	r1 = r0;					\
	r2 = r0;					\
	r1 += %[s32_max];				\
	r2 += -1;					\
	if r2 s< 0 goto l0_%=;				\
	if r1 s>= 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  [s32_max]"i"(INT_MAX)
	: __clobber_all);
}

/*
 * Test linked scalar tracking with alu32 and large positive offset (0x7FFFFFFF).
 * After w1 += 0x7FFFFFFF, w1 wraps to negative for any r0 >= 1.
 * If w1 is signed-negative, then r0 >= 1, so r0 != 0.
 */
SEC("socket")
__success
__naked void scalars_alu32_big_offset(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 &= 0xff;					\
	w1 = w0;					\
	w1 += 0x7FFFFFFF;				\
	if w1 s>= 0 goto l0_%=;				\
	if w0 != 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_alu32_basic(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = r0;					\
	w1 += 1;					\
	if r1 > 10 goto 1f;				\
	r0 >>= 32;					\
	if r0 == 0 goto 1f;				\
	r0 /= 0;					\
1:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test alu32 linked register tracking with wrapping.
 * R0 is bounded to [0xffffff00, 0xffffffff] (high 32-bit values)
 * w1 += 0x100 causes R1 to wrap to [0, 0xff]
 *
 * After sync_linked_regs, if bounds are computed correctly:
 *   R0 should be [0x00000000_ffffff00, 0x00000000_ffffff80]
 *   R0 >> 32 == 0, so div by zero is unreachable
 *
 * If bounds are computed incorrectly (64-bit underflow):
 *   R0 becomes [0xffffffff_ffffff00, 0xffffffff_ffffff80]
 *   R0 >> 32 == 0xffffffff != 0, so div by zero is reachable
 */
SEC("socket")
__success
__naked void scalars_alu32_wrap(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	w0 |= 0xffffff00;				\
	r1 = r0;					\
	w1 += 0x100;					\
	if r1 > 0x80 goto l0_%=;			\
	r2 = r0;					\
	r2 >>= 32;					\
	if r2 == 0 goto l0_%=;				\
	r0 /= 0;					\
l0_%=:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that sync_linked_regs() consults reg->flags (the linked target
 * register) for BPF_FLAG_ADD_CONST32, not just known_reg->flags (the branch
 * register): the gate is (reg->flags | known_reg->flags).
 */
SEC("socket")
__success
__naked void scalars_alu32_zext_linked_reg(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;		/* r6 in [0, 0xFFFFFFFF] */	\
	r7 = r6;		/* linked: same id as r6 */	\
	w7 += 1;		/* alu32: r7.flags |= BPF_FLAG_ADD_CONST32 */ \
	r8 = 0xFFFFffff ll;					\
	if r6 < r8 goto l0_%=;					\
	/* r6 in [0xFFFFFFFF, 0xFFFFFFFF] */			\
	/* sync_linked_regs: known_reg=r6, reg=r7 */		\
	/* CPU: w7 = (u32)(0xFFFFFFFF + 1) = 0, zext -> r7 = 0 */ \
	/* With fix: r7 64-bit = [0, 0] (zext applied) */	\
	/* Without fix: r7 64-bit = [0x100000000] (no zext) */	\
	r7 >>= 32;						\
	if r7 == 0 goto l0_%=;					\
	r0 /= 0;		/* unreachable with fix */	\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that sync_linked_regs() skips propagation when one register used
 * alu32 (BPF_FLAG_ADD_CONST32) and the other used alu64 (BPF_FLAG_ADD_CONST64).
 * The delta relationship doesn't hold across different ALU widths.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void scalars_alu32_alu64_cross_type(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;		/* r6 in [0, 0xFFFFFFFF] */	\
	r7 = r6;		/* linked: same id as r6 */	\
	w7 += 1;		/* alu32: BPF_FLAG_ADD_CONST32, delta = 1 */ \
	r8 = r6;		/* linked: same id as r6 */	\
	r8 += 2;		/* alu64: BPF_FLAG_ADD_CONST64, delta = 2 */ \
	r9 = 0xFFFFffff ll;					\
	if r7 < r9 goto l0_%=;					\
	/* r7 = 0xFFFFFFFF */					\
	/* sync: known_reg=r7 (ADD_CONST32), reg=r8 (ADD_CONST64) */ \
	/* Without fix: r8 = zext(0xFFFFFFFF + 1) = 0 */	\
	/* With fix: r8 stays [2, 0x100000001] (r8 >= 2) */	\
	if r8 > 0 goto l1_%=;					\
	goto l0_%=;						\
l1_%=:								\
	r0 /= 0;		/* div by zero */		\
l0_%=:								\
	r0 = 0;						\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that regsafe() prevents pruning when two paths reach the same program
 * point with linked registers carrying different ADD_CONST flags (one
 * BPF_FLAG_ADD_CONST32 from alu32, another BPF_FLAG_ADD_CONST64 from alu64).
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void scalars_alu32_alu64_regsafe_pruning(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;		/* r6 in [0, 0xFFFFFFFF] */	\
	r7 = r6;		/* linked: same id as r6 */	\
	/* Get another random value for the path branch */	\
	call %[bpf_get_prandom_u32];				\
	if r0 > 0 goto l_pathb_%=;				\
	/* Path A: alu32 */					\
	w7 += 1;		/* BPF_FLAG_ADD_CONST32, delta = 1 */\
	goto l_merge_%=;					\
l_pathb_%=:							\
	/* Path B: alu64 */					\
	r7 += 1;		/* BPF_FLAG_ADD_CONST64, delta = 1 */\
l_merge_%=:							\
	/* Merge point: regsafe() compares path B against cached path A. */ \
	/* Narrow r6 to trigger sync_linked_regs for r7 */	\
	r9 = 0xFFFFffff ll;					\
	if r6 < r9 goto l0_%=;					\
	/* r6 = 0xFFFFFFFF */					\
	/* sync: r7 = 0xFFFFFFFF + 1 = 0x100000000 */		\
	/* Path A: zext -> r7 = 0 */				\
	/* Path B: no zext -> r7 = 0x100000000 */		\
	r7 >>= 32;						\
	if r7 == 0 goto l0_%=;					\
	r0 /= 0;		/* div by zero on path B */	\
l0_%=:								\
	r0 = 0;						\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

SEC("socket")
__success
void alu32_negative_offset(void)
{
	volatile char path[5];
	volatile int offset = bpf_get_prandom_u32();
	int off = offset;

	if (off >= 5 && off < 10)
		path[off - 5] = '.';

	/* So compiler doesn't say: error: variable 'path' set but not used */
	__sink(path[0]);
}

void dummy_calls(void)
{
	bpf_iter_num_new(0, 0, 0);
	bpf_iter_num_next(0);
	bpf_iter_num_destroy(0);
}

SEC("socket")
__success
__flag(BPF_F_TEST_STATE_FREQ)
int spurious_precision_marks(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile(
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 4f;"
		"r7 = *(u32 *)(r0 + 0);"
		"r8 = *(u32 *)(r0 + 0);"
		/* This jump can't be predicted and does not change r7 or r8 state. */
		"if r7 > r8 goto 2f;"
		/* Branch explored first ties r2 and r7 as having the same id. */
		"r2 = r7;"
		"goto 3f;"
	"2:"
		/* Branch explored second does not tie r2 and r7 but has a function call. */
		"call %[bpf_get_prandom_u32];"
	"3:"
		/*
		 * A checkpoint.
		 * When first branch is explored, this would inject linked registers
		 * r2 and r7 into the jump history.
		 * When second branch is explored, this would be a cache hit point,
		 * triggering propagate_precision().
		 */
		"if r7 <= 42 goto +0;"
		/*
		 * Mark r7 as precise using an if condition that is always true.
		 * When reached via the second branch, this triggered a bug in the backtrack_insn()
		 * because r2 (tied to r7) was propagated as precise to a call.
		 */
		"if r7 <= 0xffffFFFF goto +0;"
		"goto 1b;"
	"4:"
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter),
		  __imm(bpf_iter_num_new),
		  __imm(bpf_iter_num_next),
		  __imm(bpf_iter_num_destroy),
		  __imm(bpf_get_prandom_u32)
		: __clobber_common, "r7", "r8"
	);

	return 0;
}

/*
 * Test that r += r (self-add, src_reg == dst_reg) clears the scalar ID
 * so that sync_linked_regs() does not propagate an incorrect delta.
 */
SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_self_add_clears_id(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 unknown, id A */		\
	r7 = r6;		/* r7 linked to r6, id A */	\
	call %[bpf_get_prandom_u32];				\
	r8 = r0;		/* r8 unknown, id B */		\
	r9 = r8;		/* r9 linked to r8, id B */	\
	if r7 != 1 goto l_exit_%=;				\
	/* r7 == 1; sync propagates: r6 = 1 (known, id A) */	\
	r6 += r6;		/* r6 = 2; should clear id */	\
	if r7 == r9 goto l_exit_%=;				\
	/* Bug: r6 synced to r7(1)+delta(2)=3; Fix: r6 = 2 */	\
	if r6 == 3 goto l_exit_%=;				\
	r0 /= 0;						\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Same as above but with alu32 such that w6 += w6 also clears id. */
SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_self_add_alu32_clears_id(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;						\
	w7 = w6;						\
	call %[bpf_get_prandom_u32];				\
	w8 = w0;						\
	w9 = w8;						\
	if w7 != 1 goto l_exit_%=;				\
	w6 += w6;						\
	if w7 == w9 goto l_exit_%=;				\
	if w6 == 3 goto l_exit_%=;				\
	r0 /= 0;						\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that stale delta from a cleared BPF_FLAG_ADD_CONST does not leak
 * through assign_scalar_id_before_mov() into a new id, causing
 * sync_linked_regs() to compute an incorrect offset.
 */
SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_stale_delta_from_cleared_id(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 unknown, gets id A */	\
	r6 += 5;		/* id A|ADD_CONST, delta 5 */	\
	r6 ^= 0;		/* id cleared; delta stays 5 */	\
	r8 = r6;		/* new id B, stale delta 5 */	\
	r8 += 3;		/* id B|ADD_CONST, delta 3 */	\
	r9 = r6;		/* id B, stale delta 5 */	\
	if r9 != 10 goto l_exit_%=;				\
	/* Bug: r8 = 10+(3-5) = 8; Fix: r8 = 10+(3-0) = 13 */	\
	if r8 == 8 goto l_exit_%=;				\
	r0 /= 0;						\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* Same as above but with alu32. */
SEC("socket")
__failure
__msg("div by zero")
__naked void scalars_stale_delta_from_cleared_id_alu32(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;						\
	w6 += 5;						\
	w6 ^= 0;						\
	w8 = w6;						\
	w8 += 3;						\
	w9 = w6;						\
	if w9 != 10 goto l_exit_%=;				\
	if w8 == 8 goto l_exit_%=;				\
	r0 /= 0;						\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Test that regsafe() verifies base_id consistency for BPF_FLAG_ADD_CONST
 * linked scalars during state pruning.
 *
 * The false branch (explored first) links R3 to R2 via ADD_CONST.
 * The true branch (runtime path) links R3 to R4 (unrelated base_id).
 * At the merge point, pruning must fail because the linkage topology
 * differs.
 */
SEC("socket")
__description("linked scalars: add_const base_id must be consistent for pruning")
__failure __msg("invalid variable-offset")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void add_const_base_id_pruning(void)
{
	asm volatile ("						\
	r1 = 0;							\
	*(u64*)(r10 - 16) = r1;					\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 &= 1;						\
	if r6 >= 1 goto l_true_%=;				\
								\
	/* False branch (explored first, old state) */		\
	call %[bpf_get_prandom_u32];				\
	r2 = r0;						\
	r2 &= 0xff;		/* R2 = scalar(id=A) [0,255] */	\
	r3 = r2;		/* R3 linked to R2 (id=A) */	\
	r3 += 10;		/* R3 id=A|ADD_CONST, delta=10 */\
	r6 = 0;							\
	goto l_merge_%=;					\
								\
l_true_%=:							\
	/* True branch (runtime path, cur state) */		\
	call %[bpf_get_prandom_u32];				\
	r2 = r0;						\
	r2 &= 0xff;		/* R2 = scalar [0,255], id=0 */	\
	r4 = r0;						\
	r4 &= 0xff;		/* R4 = scalar [0,255], id=0 */	\
	r3 = r4;		/* R3 linked to R4 (new id=C) */\
	r3 += 10;		/* R3 id=C|ADD_CONST, delta=10 */\
	r6 = 0;							\
								\
l_merge_%=:							\
	/* At merge, old R3 linked to R2, cur R3 linked to R4. */\
	/* Pruning must fail: base_ids A vs C inconsistent. */	\
	if r2 >= 6 goto l_exit_%=;				\
	/* sync_linked_regs: R2<6 => R3<16 in old state. */	\
	/* Without fix: R3 in [10,15] from incorrect pruning. */\
	/* With fix: R3 in [10,265], not synced from R2. */	\
	r3 -= 10;		/* [0,5] vs [0,255] */		\
	r9 = r10;						\
	r9 += -16;						\
	r9 += r3;		/* fp-16+[0,5] vs fp-16+[0,255] */\
	*(u8*)(r9 + 0) = r6;	/* within 16B vs past fp */	\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit zero-extending mov (w7 = w6) from a source with unknown high bits
 * shares only the low 32 bits (w7.lo == w6.lo, w7.hi == 0). A later narrowing of
 * the source's low 32 bits must propagate to the destination via the
 * BPF_FLAG_SUBREG_ZEXT (low-32-only) link. This is the pattern bpf-gcc emits when it
 * reuses "w0 = idx" for "return 0" on the idx==0 path of a callback.
 */
SEC("socket")
__success
__naked void subreg_eq_zext_mov_narrow(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 = 64-bit unknown (helper ret is unbounded) */ \
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;		/* r0 = unknown high bits */	\
	r6 |= r0;		/* still 64-bit unknown; makes it explicit */ \
	w7 = w6;		/* 32-bit zero-extend mov, wide src */	\
	if w6 != 0 goto l_out_%=;	/* w6 low == 0 on fall-through */ \
	/* w7 = zext32(w6 low) must be 0 here */		\
	if w7 == 0 goto l_out_%=;	/* provably 0 iff linked */	\
	r0 /= 0;		/* reached only if w7 not deduced 0 */	\
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit zero-extending mov (w7 = w5) whose SOURCE is a wide ADD_CONST-linked
 * register (r5 = base + K) must NOT disturb that source. Forming the low-32
 * BPF_FLAG_SUBREG_ZEXT link on the destination would need assign_scalar_id_before_mov()
 * on the source, which clears its base+delta link -- and a combined
 * subreg+delta link isn't modeled anyway (sync_linked_regs() skips it). So for a
 * wide ADD_CONST src the mov leaves the source's link intact and just clears the
 * destination.
 *
 * Here r5 = r6 + 3 (ADD_CONST, wide). After the mov, narrowing the base r6 must
 * still reach r5 through the preserved link: r6 in [0, 10] => r5 in [3, 13], so
 * the guarded div-by-zero is unreachable. Had the mov cleared r5's link (calling
 * assign_scalar_id_before_mov() unconditionally), r5 would stay unbounded and the
 * div would be reachable (rejected).
 *
 * Note this is a no-regression guard rather than coverage of the new link:
 * before this feature the wide-source path also left the source untouched, so
 * the test passes either way. What it pins is the choice not to call
 * assign_scalar_id_before_mov() unconditionally.
 *
 * Written in asm so the bytecode is identical regardless of the host BPF compiler.
 */
SEC("socket")
__success
__naked void zext_mov_keeps_add_const_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 low = unknown u32 */	\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown (base) */ \
	r5 = r6;		/* r5, r6 linked (shared id) */	\
	r5 += 3;		/* r5 = base + 3: ADD_CONST, still wide */ \
	w7 = w5;		/* 32-bit zext mov, wide ADD_CONST src */ \
	if r6 > 10 goto l_out_%=;/* r6 in [0, 10] */		\
	/* r5 = r6 + 3 must be in [3, 13] here (needs the kept link) */ \
	if r5 > 13 goto l_err_%=;/* taken only if r5 not narrowed */ \
	goto l_out_%=;						\
l_err_%=:							\
	r0 /= 0;		/* reachable iff r5's link was cleared */ \
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Dest-driven direction, zero-extend flavour: narrowing the LINKED register
 * must not narrow the wide base.
 *
 * w7 = w6 shares only r6's low 32 bits; r7's high half is zero, r6's is
 * unknown. Learning r7 == 0 therefore says nothing about r6, and
 * sync_linked_regs() must not copy r7's state onto it. Rejected iff the base
 * is left alone.
 *
 * This is the shape that catches a lost BPF_FLAG_SUBREG_ZEXT: if the flag is
 * dropped while the shared ->id survives, the pair looks like a full 64-bit
 * equality, the dest-driven guard is bypassed and r6 wrongly becomes 0.
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void zext_dest_driven_does_not_narrow_base(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 low = unknown u32 */	\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown (base) */ \
	w7 = w6;		/* low-32 ZEXT link */		\
	if r7 != 0 goto l_out_%=;/* r7 == 0: low 32 bits are 0 */ \
	if r6 != 0 goto l_out_%=;/* r6 may still have high bits set */ \
	r0 /= 0;		/* must stay reachable */	\
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The tests below use the cpuv4 32-bit sign extension (r0 = (s32)r0), so they
 * need a compiler that can emit it and a JIT that can run it. Same gate as
 * verifier_movsx.c, except the compiler clause also accepts bpf-gcc, which
 * does not define __clang_major__ but does define __BPF_FEATURE_MOVSX.
 *
 * The tests above do not need cpuv4, so the guard starts here rather than
 * covering the whole file.
 */
#if (defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_x86) || \
	(defined(__TARGET_ARCH_riscv) && __riscv_xlen == 64) || \
	defined(__TARGET_ARCH_arm) || defined(__TARGET_ARCH_s390) || \
	defined(__TARGET_ARCH_loongarch)) && \
	(__clang_major__ >= 18 || defined(__BPF_FEATURE_MOVSX))

/*
 * Sign-extension linked-register tracking, in-place narrow-to-zero.
 *
 * r1 = r0 ties r0,r1 with a shared id. r0 = (s32)r0 sign-extends r0's low 32
 * bits; the helper return is a full 64-bit unknown so the sign bit isn't
 * provably 0, and r0 keeps a BPF_FLAG_SUBREG_SEXT link to r1. On the w1 == 0
 * fall-through, r1's low 32 bits are 0; r0's low 32 bits equal r1's and r0's
 * upper bits are the sign-extension of that (0) -- so r0 == 0.
 *
 * The guarded div-by-zero is unreachable iff the verifier deduces r0 == 0.
 */
SEC("socket")
__success
__naked void sext_linked_low_narrow_to_zero(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r1 = r0;		/* r1 == r0, shared id */	\
	r0 = (s32)r0;		/* r0 = sext32(r0) */		\
	if w1 != 0 goto l0_%=;	/* fall-through: w1 == 0 */	\
	/* want deduced here: r0 == 0 */			\
	if r0 == 0 goto l0_%=;	/* always taken iff r0==0 known */ \
	r0 /= 0;		/* unreachable iff r0==0 deduced */ \
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Separate-dest sign-extension: r3 = (s32)r2 (dst != src). r2,r3 share a base
 * id (r3 with BPF_FLAG_SUBREG_SEXT). On the w2 == 0 fall-through, r2's low 32 bits are
 * 0, so r3 = sext32(0) = 0 and the guarded div-by-zero is unreachable.
 *
 * Runs with BPF_F_TEST_STATE_FREQ to force checkpointing between the sext and
 * the branch: the sext linkage (BPF_FLAG_SUBREG_SEXT) must survive state
 * cleaning so sync_linked_regs() can still reconstruct r3. bpf_clear_singular_ids()
 * strips the link flags when counting base ids; otherwise r3's compound id looks
 * singular and gets cleared, and r3 stays wide.
 */
SEC("socket")
__success
__flag(BPF_F_TEST_STATE_FREQ)
__naked void sext_linked_separate_dest_narrow_to_zero(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r2 = r0;		/* r2,(r0) linked, id N */	\
	r3 = (s32)r2;		/* r3 = sext32(r2): SEXT link base N */	\
	if w2 != 0 goto l0_%=;	/* fall-through: w2 == 0 */	\
	/* want deduced here: r3 == 0 */			\
	if r3 == 0 goto l0_%=;	/* always taken iff r3==0 known */ \
	r0 /= 0;		/* unreachable iff r3==0 deduced */ \
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Coverage derived from real "R0 ... should have been in [0, 1]" exit
 * rejections. Each sign-extends a value, then a branch proves its low 32 bits
 * are 0 so the sext result must be 0. Expressed with the div-by-zero idiom (same
 * deduced range the return-code check reads): the div is unreachable iff the
 * verifier deduces the sext register is 0.
 */

/* 1: branch on the SOURCE reg; separate dest (value stands in for a u32 load). */
SEC("socket")
__success
__naked void sext_narrow_branch_on_source(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r2 = r0;		/* r2 = value (proxy for u32 load) */	\
	r0 = (s32)r2;		/* r0 = sext32(r2) */		\
	if w2 != 0 goto l0_%=;	/* w2 != 0: r0 unknown, skip */	\
	if r0 == 0 goto l0_%=;	/* w2 == 0: r0 must be 0 */	\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 2: sext into r7, prove via w0, then copy r7 back into r0. */
SEC("socket")
__success
__naked void sext_narrow_copied_back(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r7 = (s32)r0;		/* r7 = sext32(r0) */		\
	if w0 != 0 goto l0_%=;	/* w0 != 0: skip */		\
	r0 = r7;		/* w0 == 0: r0 = r7 (must be 0) */ \
	if r0 == 0 goto l0_%=;					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 3: in-place sext; branch on the pre-sext copy r1 (== direction). */
SEC("socket")
__success
__naked void sext_narrow_inplace_pre_copy(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r1 = r0;		/* pre-sext copy, linked */	\
	r0 = (s32)r0;		/* in-place sext32 */		\
	if w1 == 0 goto l_chk_%=;/* w1 == 0: r0 must be 0 */	\
	goto l0_%=;		/* w1 != 0: nothing to check */	\
l_chk_%=:							\
	if r0 == 0 goto l0_%=;					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/* 4: sext, prove via w0, spill to stack across a call, reload, use. */
SEC("socket")
__success
__naked void sext_narrow_spill_fill(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r9 = (s32)r0;		/* r9 = sext32(r0) */		\
	if w0 != 0 goto l0_%=;	/* w0 != 0: skip */		\
	/* w0 == 0: r9 must be 0 */				\
	*(u64 *)(r10 - 8) = r9;	/* spill r9 */			\
	call %[bpf_get_prandom_u32];/* clobbers r0-r5 */	\
	r5 = *(u64 *)(r10 - 8);	/* reload -> must be 0 */	\
	if r5 == 0 goto l0_%=;					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A redundant 32-bit sign-extension of an already-narrowed value must preserve
 * the range. This is the errno-or-zero return pattern (set_if_not_errno_or_zero()
 * followed by "return ret" on an int): the value is clamped to [-4095, 0] and
 * then sign-extended again, e.g. verify_pkcs7_sig / many lsm.s progs under
 * bpf-gcc. coerce_reg_to_size_sx() bails to the full [S32_MIN, S32_MAX] range
 * when the range straddles the sign boundary (smin<0, smax>=0), so without the
 * sext-self reconstruction the final "r0 = (s32)r0" widens [-4095, 0] back to
 * the full range and the program is rejected. Knowing the high half is the
 * sign-extension of the low 32 bits lets the verifier rebuild the tight range.
 */
SEC("socket")
__success
__naked void sext_resext_preserves_range(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r0 = (s32)r0;		/* r0 = [S32_MIN, S32_MAX] */	\
	if r0 s> 0 goto l_out_%=;	/* r0 <= 0 */		\
	if r0 s< -4095 goto l_out_%=;	/* r0 in [-4095, 0] */	\
	r0 = (s32)r0;		/* redundant re-sext (pkcs7 pattern) */ \
	if r0 s>= -4095 goto l_lo_ok_%=;/* must hold if range kept */ \
	r0 /= 0;		/* reached only if lower bound lost */	\
l_lo_ok_%=:							\
	if r0 s<= 0 goto l_out_%=;	/* must hold if range kept */ \
	r0 /= 0;		/* reached only if upper bound lost */	\
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit sign-extension INSIDE a loop must verify and converge. This is the
 * bytecode pattern bpf-gcc emits for a cond_break loop (see cond_break4): a
 * counter is incremented with an ALU32 add (which zero-extends the high half)
 * and then sign-extended in place every iteration.
 *
 * The verifier links dst<->src on a sign-extension. Doing that for a sext on a
 * register carried across the loop back-edge mints/refreshes the linked scalar
 * id and its BPF_FLAG_SUBREG_SEXT metadata each iteration; combined with the
 * ALU32 add's BPF_FLAG_ADD_CONST delta the loop-carried state never repeats, so state
 * pruning can't converge and verification runs to the 1M instruction limit.
 *
 * The regsafe() guard on the low-32 link flags is what prevents this: it only demands a
 * match when the OLD state already carries a link (rold->id), so a register that
 * first picks up a sext link inside the loop can still match its pre-loop state.
 * Without that guard the loop-carried r2 never matches and the load fails at
 * 1,000,001 insns, i.e. this __success flips to a load failure -- so this is the
 * regression test for it. (See sext_in_loop_separate_dest_index for the
 * companion case, a fresh in-loop temp that keeps its link for precision.)
 *
 * The pattern is written in asm so the bytecode is identical regardless of the
 * host BPF compiler.
 */
SEC("socket")
__success
__naked void sext_in_loop_converges(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r2 = r0;		/* r2 = 64-bit unknown (helper ret) */	\
l_body_%=:							\
	.byte 0xe5; /* may_goto l_exit (loop bound) */	\
	.byte 0;						\
	.short 3;						\
	.long 0;						\
	w2 += 1;		/* ALU32 add: low += 1, high = 0 */ \
	r2 = (s32)r2;		/* in-place in-loop sign-extend */ \
	goto l_body_%=;						\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A separate-destination 32-bit sign extension INSIDE a loop keeps its low-32
 * link, so a later bounds check on the source narrows the sign-extended
 * destination too. This is the bytecode a bpf-gcc build emits for array indexing
 * in a bpf_for loop -- a fresh 32-bit index load, a separate "r1 = (s32)r0",
 * then a bounds check on the index (verifier_global_subprogs' syscall_array_bpf_for).
 *
 * Both in-loop cases form the link -- subreg_link is just (sz == 4), with no
 * liveness or loop-carried exclusion. What differs is what the link buys. Here
 * the destination is a fresh temp, dead across the back-edge, so the link is
 * pure precision: "if w0 > 99" narrows r1 to [0, 99] and the guarded
 * div-by-zero is unreachable. In sext_in_loop_converges the target is the
 * loop-carried counter, so the link is re-formed every iteration and the
 * question is convergence instead -- answered by the regsafe() rold->id guard,
 * not by declining to link.
 *
 * Written in asm so the bytecode is identical regardless of the host BPF
 * compiler.
 */
SEC("socket")
__success
__naked void sext_in_loop_separate_dest_index(void)
{
	asm volatile ("						\
l_body_%=:							\
	.byte 0xe5; /* may_goto l_exit (loop bound) */	\
	.byte 0;						\
	.short 7;						\
	.long 0;						\
	call %[bpf_get_prandom_u32];/* r0 = fresh u32 each iter */ \
	r1 = (s32)r0;		/* in-loop separate-dest sext */ \
	if w0 > 0x63 goto l_body_%=;/* fall-through: w0 <= 99 */	\
	/* want r1 = sext32(r0 low) == [0, 99] here (needs the link) */ \
	if r1 > 0x63 goto l_err_%=;/* taken unless r1 narrowed */ \
	goto l_body_%=;						\
l_err_%=:							\
	r0 /= 0;		/* reachable iff r1 not narrowed */	\
	goto l_body_%=;						\
l_exit_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit zero-extending mov (w2 = w1) whose SOURCE is a sign-extended register
 * must still zero-extend: dst's high bits are 0, not the sign-extension of the
 * low field. Regression test for the zext link clearing BPF_FLAG_SUBREG_SEXT (otherwise
 * dst would inherit SUBREG_SEXT from the sext'd source, and sync_linked_regs()
 * would later rebuild it with reconstruct_sext32() -- computing a negative value
 * for what is actually a large positive zero-extended one).
 *
 * r1 = (s32)r6 makes r1 a sext-linked wide source; w2 = w1 forms the zext link.
 * After "if w6 s>= 0" falls through, r6's low 32 bits have bit 31 set, so the
 * zero-extended r2 must be in [0x80000000, 0xffffffff]. Two guards assert that
 * whole range, so the test needs the feature present, not merely the absence of
 * the sext-leak bug: "r2 s< 0" catches the leak (r2 rebuilt negative), and
 * "w2 s>= 0" catches the low-32 link being absent entirely (r2 not narrowed to
 * the high half, so bit 31 is not known set). Either makes the div reachable.
 */
SEC("socket")
__success
__naked void zext_mov_from_sext_src_zero_extends(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 low = unknown u32 (callee-saved) */ \
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown (width 64) */ \
	r1 = (s32)r6;		/* r1 = sext32(r6 low): SUBREG_SEXT, wide */ \
	w2 = w1;		/* zext mov from sext-linked wide src */ \
	if w6 s>= 0 goto l_out_%=;/* fall-through: r6 low has bit 31 set */ \
	/* r2 = zext32(r6 low) must be in [0x80000000, 0xffffffff]: */	\
	if r2 s< 0 goto l_err_%=;/* sext leak: r2 wrongly negative */ \
	if w2 s>= 0 goto l_err_%=;/* link absent: r2 low bit 31 not known set */ \
	goto l_out_%=;						\
l_err_%=:							\
	r0 /= 0;		/* r2 not proven in [0x80000000, 0xffffffff] */ \
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Mirror of zext_mov_keeps_add_const_src for the sign-extending mov: a sext
 * whose source carries an ADD_CONST delta must not destroy that link.
 *
 * Forming a low-32 link calls assign_scalar_id_before_mov(), which clears an
 * ADD_CONST src, so the sext arm excludes such a source exactly as the zext
 * arm does. Without that exclusion r5 loses its base+delta relationship to r6
 * here, "if r6 > 10" no longer narrows r5, and the guarded div becomes
 * reachable.
 */
SEC("socket")
__success
__naked void sext_mov_keeps_add_const_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 low = unknown u32 */	\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown (base) */ \
	r5 = r6;		/* r5, r6 linked (shared id) */	\
	r5 += 3;		/* r5 = base + 3: ADD_CONST, still wide */ \
	r7 = (s32)r5;		/* 32-bit sext mov, ADD_CONST src */ \
	if r6 > 10 goto l_out_%=;/* r6 in [0, 10] */		\
	/* r5 = r6 + 3 must be in [3, 13] here (needs the kept link) */ \
	if r5 > 13 goto l_err_%=;/* taken only if r5 not narrowed */ \
	goto l_out_%=;						\
l_err_%=:							\
	r0 /= 0;		/* reachable iff r5's link was cleared */ \
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Dest-driven direction, sign-extend flavour: narrowing the LINKED register
 * must not narrow the wide base.
 *
 * r7 = (s32)r6 shares only r6's low 32 bits. Learning r7 == 0 says nothing
 * about r6's high half, so sync_linked_regs() must leave r6 alone -- that is
 * the "known_reg is subreg-linked" continue. If it ever propagated, r6 would
 * be known 0 here and the div would be treated as unreachable, so the program
 * must be REJECTED.
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void sext_dest_driven_does_not_narrow_base(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;		/* r6 low = unknown u32 */	\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown (base) */ \
	r7 = (s32)r6;		/* low-32 SEXT link */		\
	if r7 != 0 goto l_out_%=;/* r7 == 0: low 32 bits are 0 */ \
	if r6 != 0 goto l_out_%=;/* r6 may still have high bits set */ \
	r0 /= 0;		/* must stay reachable */	\
l_out_%=:							\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#endif /* cpuv4 sign extension */

char _license[] SEC("license") = "GPL";
