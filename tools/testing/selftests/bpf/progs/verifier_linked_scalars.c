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

#ifdef CAN_USE_MOVSX
/*
 * A sign-extending mov reads only the low 32 bits, so it shares them with
 * whatever its source shares them with -- including a delta the source
 * picked up. Here r8 is (s32)(r6 + 5): narrowing r6 to 0xfffffffb makes
 * (u32)(r6 + 5) zero, so r8 is zero and the divide is unreachable.
 */
SEC("socket")
__success
__retval(0)
__naked void sext_mov_inherits_delta(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 <<= 32;						\
	call %[bpf_get_prandom_u32];				\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	w7 = w6;		/* BPF_REG_LINK_ZEXT, delta 0 */	\
	w7 += 5;		/* BPF_REG_LINK_ZEXT, delta 5 */	\
	r8 = (s32)r7;		/* BPF_REG_LINK_SEXT, delta 5 */	\
	r1 = 0xfffffffb ll;					\
	if r6 != r1 goto l0_%=;	/* (u32)(r6 + 5) == 0 */	\
	if r8 == 0 goto l0_%=;					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#endif /* CAN_USE_MOVSX */

SEC("socket")
__success
__retval(0)
__naked void zext_reverse_pins_low_half(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 <<= 32;						\
	call %[bpf_get_prandom_u32];				\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	w7 = w6;						\
	w7 += 5;		/* r7 = (u32)(r6 + 5) */	\
	if w7 != 15 goto l0_%=;	/* so (u32)r6 == 10 */		\
	if w6 == 10 goto l0_%=;					\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
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
 * Test that sync_linked_regs() checks the linked target register (reg) for
 * BPF_REG_LINK_ZEXT rather than the branch register (known_reg).
 */
SEC("socket")
__success
__naked void scalars_alu32_zext_linked_reg(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;		/* r6 in [0, 0xFFFFFFFF] */	\
	r7 = r6;		/* linked: same id as r6 */	\
	w7 += 1;		/* BPF_REG_LINK_ZEXT delta */ \
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
 * Test that sync_linked_regs() does not carry the delta relationship across
 * registers that used different ALU widths: r7 used alu32 (BPF_REG_LINK_ZEXT) and r8
 * alu64 (BPF_REG_LINK_FULL), so the relationship does not hold over all 64 bits. The
 * low half is recovered -- r8 comes out exactly 0x100000000 -- which is why
 * the div is still reachable and this is a __failure.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void scalars_alu32_alu64_cross_type(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;		/* r6 in [0, 0xFFFFFFFF] */	\
	r7 = r6;		/* linked: same id as r6 */	\
	w7 += 1;		/* BPF_REG_LINK_ZEXT delta */ \
	r8 = r6;		/* linked: same id as r6 */	\
	r8 += 2;		/* BPF_REG_LINK_FULL delta */ \
	r9 = 0xFFFFffff ll;					\
	if r7 < r9 goto l0_%=;					\
	/* r7 = 0xFFFFFFFF */					\
	/* sync: known_reg=r7 (BPF_REG_LINK_ZEXT), reg=r8 (BPF_REG_LINK_FULL) */ \
	/* Without fix: r8 = zext(0xFFFFFFFF + 1) = 0 */	\
	/* With fix: r8 == 0x100000000, so still > 0 */		\
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
 * BPF_REG_LINK_ZEXT from alu32, another BPF_REG_LINK_FULL from alu64).
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
	w7 += 1;		/* BPF_REG_LINK_ZEXT delta */\
	goto l_merge_%=;					\
l_pathb_%=:							\
	/* Path B: alu64 */					\
	r7 += 1;		/* BPF_REG_LINK_FULL delta */\
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
 * Test that a stale delta from a cleared link does not leak
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
	r6 += 5;		/* id A, BPF_REG_LINK_FULL delta */	\
	r6 ^= 0;		/* id cleared; delta stays 5 */	\
	r8 = r6;		/* new id B, stale delta 5 */	\
	r8 += 3;		/* id B, BPF_REG_LINK_FULL delta */	\
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
 * Test that regsafe() verifies id consistency for linked scalars
 * during state pruning.
 *
 * The false branch (explored first) links R3 to R2 via BPF_REG_LINK_FULL.
 * The true branch (runtime path) links R3 to R4 (unrelated id).
 * At the merge point, pruning must fail because the linkage topology
 * differs.
 */
SEC("socket")
__description("linked scalars: add_const id must be consistent for pruning")
__failure __msg("invalid variable-offset")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void add_const_id_pruning(void)
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
	r3 += 10;		/* BPF_REG_LINK_FULL delta */\
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
	r3 += 10;		/* BPF_REG_LINK_FULL delta */\
	r6 = 0;							\
								\
l_merge_%=:							\
	/* At merge, old R3 linked to R2, cur R3 linked to R4. */\
	/* Pruning must fail: ids A vs C inconsistent. */	\
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
 * A 32-bit mov from a wide source shares only the low 32 bits. Narrowing the
 * source must reach the destination through that link.
 */
SEC("socket")
__success
__naked void zext_mov_narrow_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	if w6 != 0 goto 1f;	/* narrows r6, propagates to r7 */ \
	if w7 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Pinning the base's low 32 bits makes the member a known constant over all
 * 64, not merely over its low half: the member is the zero-extension, so its
 * high half is zero by construction. Checked with a 64-bit compare, which
 * zext_mov_narrow_src above does not do. Code that needs a provable constant
 * -- a helper argument such as bpf_rdonly_cast()'s btf_id, say -- depends on
 * this and not on the 32-bit form.
 */
SEC("socket")
__success
__naked void zext_sync_makes_member_const(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	if w6 != 0 goto 1f;	/* narrows r6's low 32 to 0 */	\
	if r7 == 0 goto 1f;	/* r7 is 0 over all 64 bits */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A contradiction between the two sides must not leave an empty range behind.
 * The branch really is dead -- (u32)7 is not 5 -- but an empty range is a
 * shape nothing downstream handles.
 *
 * The mod by a known-zero divisor validates r7 without recomputing it, so an
 * empty range would survive into the check; under BPF_F_TEST_REG_INVARIANTS
 * that is a load failure, which is what __success asserts. A later patch
 * prunes this branch, so the test pins this patch standing alone.
 */
SEC("socket")
__success
__flag(BPF_F_TEST_REG_INVARIANTS)
__naked void zext_contradiction_keeps_range_sane(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	if w7 != 5 goto 1f;	/* r7 == 5 */			\
	if r6 != 7 goto 1f;	/* r6 is wide, so this is explored */ \
	r9 = 0;							\
	r7 %%= r9;		/* validates r7 without touching it */ \
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The reverse does not hold: narrowing the low-32 link says nothing about the
 * base's high bits, so r6 must stay unknown and the div stays reachable.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void zext_narrow_dst_keeps_base(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	if r7 != 0 goto 1f;	/* narrows r7, must not propagate to r6 */ \
	if r6 == 0 goto 1f;	/* taken only if r6 wrongly narrowed */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A provably-u32 source takes the full-equality path, not the low-32 one:
 * narrowing the destination must reach the source.
 */
SEC("socket")
__success
__naked void zext_u32_src_is_full_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	w6 = w0;		/* r6 provably u32 */		\
	w7 = w6;		/* full link, not low-32 */	\
	if r7 > 10 goto 1f;	/* narrows r7, propagates to r6 */ \
	if r6 > 10 goto 2f;					\
	goto 1f;						\
2:								\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A self-mov has nothing to link, so it must not mint an id for r6.
 */
SEC("socket")
__success __log_level(2)
/* an id would print as R6=scalar(id=N+0,smin=... */
__msg("(bc) w6 = w6 {{.*}} R6=scalar(smin=0,")
__naked void zext_self_mov_no_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 ^= 0;		/* drop the id */		\
	w6 = w6;		/* forms no link */		\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A second 32-bit mov drops the link: assign_scalar_id_before_mov() clears
 * any link kind on the source, and the zero-extending link is one, so
 * narrowing the base no longer reaches the end of the chain. Same rule as
 * scalars_double_add above -- a delta of zero is not special.
 */
SEC("socket")
__failure
__msg("div by zero")
__naked void zext_chain_drops_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	w8 = w7;		/* the 2nd mov breaks the link */ \
	if w6 != 0 goto 1f;	/* narrows r6, does not reach r8 */ \
	if w8 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Two members of one id set carrying different link kinds do not propagate
 * to each other: r7 is (u32)base and r8 is base + 3, and the deltas were
 * added at different ALU widths, so narrowing r8 says nothing about r7.
 * sync_linked_regs() declines the pair on the kinds before the deltas are
 * ever consulted. Note neither register is the base -- that is r6.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void zext_no_sync_between_mixed_kinds(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	r8 = r6;						\
	r8 += 3;		/* r8 is BPF_REG_LINK_FULL, r7 is BPF_REG_LINK_ZEXT */	\
	if r8 != 3 goto 1f;	/* must not propagate to r7 */	\
	if w7 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * ... and here the low-32 link is the branch register. Its low half does
 * reach the register carrying the delta, but the high half must not: r8's
 * low 32 bits become 3 while the rest stays unknown, so r8 == 3 is still
 * not provable and the div stays reachable.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void zext_no_sync_from_subreg_base(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* forms the link */		\
	r8 = r6;						\
	r8 += 3;		/* delta on r8 */		\
	if w7 != 0 goto 1f;	/* must not propagate to r8 */	\
	if r8 == 3 goto 1f;	/* taken only if r8 wrongly narrowed */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Two low-32 links on the same base do propagate to each other: both are the
 * zero-extension of the same low 32 bits.
 */
SEC("socket")
__success
__naked void zext_sync_between_two_subregs(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w7 = w6;		/* two links on one base */	\
	w8 = w6;						\
	if w7 != 0 goto 1f;	/* narrows r7, propagates to r8 */ \
	if w8 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A narrowing of the base must not widen a member that has already proved
 * itself tighter. The low-32 link does not propagate back to the base, so the
 * base can be the wider of the two; rebuilding the member from it has to
 * refine what the member knows rather than replace it.
 */
SEC("socket")
__success
__naked void zext_sync_keeps_narrower_member(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	w7 = w6;		/* forms the link */		\
	if w7 > 7 goto 1f;	/* r7 low 32 bits in [0, 7] */	\
	if r6 > 100 goto 1f;	/* narrows the base, syncs to r7 */ \
	if r7 <= 7 goto 1f;	/* still provable if r7 kept [0, 7] */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Only one of the two paths links r7 to r8, so narrowing w8 reaches r7 on one
 * and not the other, and the div stays reachable. This pins the outcome, not
 * any one check: the two states differ in several ways, so no single
 * regsafe() test is load-bearing here.
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void zext_unlinked_path_stays_reachable(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 &= 1;						\
	if r6 >= 1 goto 2f;					\
	/* explored first: r7 is a low-32 link of r8 */		\
	call %[bpf_get_prandom_u32];				\
	r8 = r0;						\
	w7 = w8;		/* forms the link */		\
	goto 1f;						\
2:								\
	/* runtime path: r7 unrelated to r8 */			\
	call %[bpf_get_prandom_u32];				\
	r8 = r0;						\
	call %[bpf_get_prandom_u32];				\
	w7 = w0;		/* no link here */		\
1:								\
	if w8 != 0 goto 3f;	/* propagates to r7 only if linked */ \
	if w7 == 0 goto 3f;					\
	r0 /= 0;						\
3:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Forming the link calls assign_scalar_id_before_mov(), which drops whatever
 * link the source already carries. That is what the narrow-source path has
 * always done, so a wide source behaves the same: r5 stops tracking r6.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void zext_mov_breaks_linked_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r5 = r6;		/* r5, r6 linked */		\
	r5 += 3;		/* r5 = base + 3 */		\
	w7 = w5;		/* breaks r5's delta link */	\
	if r6 > 9 goto 1f;	/* r6 in [0, 9] */		\
	if r5 < 13 goto 1f;	/* taken only if r5 still linked */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A narrowing fill keeps only the slot's low 32 bits, so a later narrowing of
 * the spilled value must still reach the filled register. Same relation as a
 * 32-bit mov from a wide source, with the stack slot as the base.
 */
SEC("socket")
__success
__naked void zext_fill_narrow_from_wide_spill(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	*(u64 *)(r10 - 8) = r6;	/* slot linked to r6 */		\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(u32 *)(r10 - 8);	/* narrowing fill, forms the link */ \
"
#else
"	r2 = *(u32 *)(r10 - 4);				\
"
#endif
"	if w6 != 0 goto 1f;	/* narrows r6, propagates to r2 */ \
	if r2 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A full-width fill of a wide slot is a plain 64-bit equality, not a low-32
 * link, so it must keep propagating exactly as before.
 */
SEC("socket")
__success
__naked void zext_fill_full_width_keeps_full_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;						\
	*(u64 *)(r10 - 8) = r6;					\
	r2 = *(u64 *)(r10 - 8);	/* no narrowing */		\
	if r6 != 0 goto 1f;					\
	if r2 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A sub-word fill is below the low-32 model, so no link is formed and the
 * relation is dropped as before.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void zext_fill_byte_forms_no_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;						\
	*(u64 *)(r10 - 8) = r6;					\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(u8 *)(r10 - 8);	/* 1-byte fill: no link */	\
"
#else
"	r2 = *(u8 *)(r10 - 1);					\
"
#endif
"	if w6 != 0 goto 1f;					\
	if r2 == 0 goto 1f;	/* not deduced */		\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#ifdef CAN_USE_MOVSX

/*
 * A BPF_REG_LINK_SEXT register carries a delta, so anything forming a low-32 link off
 * it must inherit that delta rather than assume zero: r9 is (u32)(r6 + 5), not
 * (u32)(r6 + 0). Resetting it recorded r9 == r6, and the verifier then read a
 * constant the program never computes.
 */
SEC("socket")
__success
__naked void sext_delta_survives_zext_mov(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 <<= 32;						\
	call %[bpf_get_prandom_u32];				\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	w7 = w6;		/* BPF_REG_LINK_ZEXT, delta 0 */	\
	w7 += 5;		/* BPF_REG_LINK_ZEXT, delta 5 */	\
	r8 = (s32)r7;		/* BPF_REG_LINK_SEXT, delta 5 */	\
	w9 = w8;		/* must stay (u32)(r6 + 5) */	\
	if r6 != 0 goto 1f;	/* r6 == 0, so r9 == 5 */	\
	if r9 == 5 goto 1f;	/* always taken: r9 is 5 */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A 32-bit sign extension keeps the low 32 bits, so narrowing the source
 * reaches the destination the same way it does for a zero extension. The high
 * half follows the sign, so the value seen here is negative.
 */
SEC("socket")
__success
__naked void sext_mov_wide_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r7 = (s32)r6;		/* forms the link */		\
	if w6 != -1 goto 1f;	/* narrows r6, propagates to r7 */ \
	if r7 == -1 goto 1f;	/* sign-extended, not 0xffffffff */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The source need not already be in a set. A call return or a load has no
 * id, so the sign-extending mov is what mints one -- which is the shape the
 * failures that motivated this take, rather than a prior pairing.
 */
SEC("socket")
__success
__retval(0)
__naked void sext_mov_unlinked_src(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r7 = (s32)r0;		/* r0 has no id; mint one */	\
	if w0 != -1 goto l0_%=;	/* narrows r0, propagates to r7 */ \
	if r7 == -1 goto l0_%=;	/* sign-extended, not 0xffffffff */ \
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * r0 = (s32)r0 is how a sign-extended int return lands. src and dst are the
 * same register, but r0 is already linked, so there is a set for it to stay
 * in and the narrowing still propagates.
 */
SEC("socket")
__success
__naked void sext_self_mov_keeps_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r7 = r6;		/* r6, r7 linked */		\
	r7 = (s32)r7;		/* self-mov, keeps the id */	\
	if w6 != -1 goto 1f;	/* narrows r6, propagates to r7 */ \
	if r7 == -1 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The same self-mov on an unlinked register has nothing to link to, so it
 * must not mint an id that would leave r6 describing itself.
 */
SEC("socket")
__success __log_level(2)
/* an id would print as R6=scalar(id=N+0.sx,smin=... */
__msg("(bf) r6 = (s32)r6 {{.*}} R6=scalar(smin=")
__naked void sext_self_mov_no_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 ^= 0;		/* drop the id */		\
	r6 = (s32)r6;		/* forms no link */		\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The shape a sign-extended return takes when it crosses a helper call: the
 * branch narrows it first, then it is spilled. No link is needed past the
 * spill -- r7 is already known by then -- but the value has to survive the
 * round trip.
 */
SEC("socket")
__success
__retval(0)
__naked void sext_value_survives_spill_across_call(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r7 = (s32)r6;		/* sext link to r6 */		\
	if w6 != -1 goto l0_%=;	/* narrows r6, so r7 is -1 */	\
	*(u64 *)(r10 - 8) = r7;	/* spill the known value */	\
	call %[bpf_get_prandom_u32];				\
	r8 = *(u64 *)(r10 - 8);	/* fill it back */		\
	if r8 == -1 goto l0_%=;	/* survived the round trip */	\
	r0 /= 0;						\
l0_%=:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A delta on the branch register is not modelled together with a low-32
 * link, so the propagation is skipped rather than guessed at.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_no_sync_when_base_has_delta(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r7 = (s32)r6;		/* forms the link */		\
	r8 = r6;						\
	r8 += 3;		/* delta on the branch reg */	\
	if r8 != 3 goto 1f;	/* must not propagate to r7 */	\
	if r7 == 0 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * ... and with the link as the branch register the propagation must not run
 * backwards over the high half: a BPF_REG_LINK_SEXT register knows nothing about the
 * base's high bits. The low half is recovered, so r8's low 32 bits do become
 * 2, but treating that as the whole value -- r8 == 2, as if r7 were the base
 * -- must not happen.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_no_sync_from_subreg_base(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r7 = (s32)r6;		/* forms the link */		\
	r8 = r6;						\
	r8 += 3;		/* delta on r8 */		\
	if r7 != -1 goto 1f;	/* must not propagate to r8 */	\
	if r8 == 2 goto 1f;	/* taken only if r8 wrongly narrowed */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Two different kinds can share one id: r2 is (u32)(r6 + 1) and r7 is
 * (s32)(r6 + 1). Pinning r2 really does pin r7 -- the deltas are equal, so
 * w2 == 1 means r7 == 1 -- but sync_linked_regs() skips any pair of
 * differing kinds, and here that imprecision is load-bearing. bpf-gcc
 * builds "i += 1" for an int loop counter into exactly this shape, and
 * deducing r7 makes the counter a fresh constant on every iteration, so the
 * state never converges and iters.c:iter_obfuscate_counter runs to the 1M
 * instruction limit.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_no_sync_from_zext_sibling(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 <<= 32;						\
	call %[bpf_get_prandom_u32];				\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	r2 = r6;						\
	w2 += 1;		/* r2 = (u32)(r6 + 1) */	\
	r7 = (s32)r2;		/* r7 = (s32)(r6 + 1) */	\
	if w2 != 1 goto 1f;	/* must not propagate to r7 */	\
	if r7 == 1 goto 1f;					\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The two link kinds rebuild the high half differently: the same low half
 * reaches -1 through a sign extension and 0xffffffff through a zero
 * extension, so only one path clears the guard. As above this checks the outcome -- the differing
 * ranges keep the states apart on their own.
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void sext_kinds_reach_different_values(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 &= 1;						\
	if r6 >= 1 goto 2f;					\
	/* explored first: r7 is a sign-extended link of r8 */	\
	call %[bpf_get_prandom_u32];				\
	r8 = r0;						\
	r7 = (s32)r8;						\
	goto 1f;						\
2:								\
	/* runtime path: r7 is a zero-extended link of r8 */	\
	call %[bpf_get_prandom_u32];				\
	r8 = r0;						\
	w7 = w8;						\
1:								\
	if w8 != -1 goto 3f;					\
	if r7 == -1 goto 3f;	/* only the sign-extended path */ \
	r0 /= 0;						\
3:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The sign-extending counterpart: a narrowing of the base must not widen a
 * member that already proved itself tighter.
 */
SEC("socket")
__success
__naked void sext_sync_keeps_narrower_member(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	r7 = (s32)r6;		/* forms the link */		\
	if w7 > 7 goto 1f;	/* r7 low 32 bits in [0, 7] */	\
	if r6 > 100 goto 1f;	/* narrows the base, syncs to r7 */ \
	if r7 <= 7 goto 1f;	/* still provable if r7 kept [0, 7] */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The reverse direction is only refused because the base is wider than 32
 * bits. Narrow it first -- "w6 = w6" leaves r6 in [0, U32_MAX] -- and
 * sync_linked_regs() does run, with r6 carrying no kind of its own and the
 * member carrying BPF_REG_LINK_SEXT. The reconstruction there has to be the zero
 * extension: r6 is below 2^32 and equal to the member's low half, so a
 * signed compare on the member must not hand r6 the sign-extended value.
 * Forgetting that dropped every r6 >= 2^31 from the range and made the
 * guarded div provably dead.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_narrow_base_keeps_high_values(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w6 = w6;		/* r6 in [0, U32_MAX] */	\
	r7 = (s32)r6;		/* forms the link */		\
	r8 = 1;							\
	r8 <<= 31;		/* 0x80000000 */		\
	if r7 s> 100 goto 1f;	/* r6 is [0,100] or >= 2^31 */	\
	if r6 < r8 goto 1f;	/* reachable: r6 may be >= 2^31 */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A base/step line does not survive the sign extension: the reconstruction
 * subtracts 2^32, and 2^32 is not a multiple of 3. Keeping the line let
 * __update_bounds_from_step() snap r7's bounds onto the wrong congruence
 * class -- r6 = 0x80000007 is a multiple of 3, so r7 = -2147483641 is
 * reachable, but the stale line excluded it.
 */
SEC("socket")
__failure __msg("div by zero")
__naked void sext_drops_stale_step(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	w6 = w6;						\
	r6 *= 3;		/* base 0, step 3 */		\
	r7 = (s32)r6;		/* forms the link */		\
	r8 = 1;							\
	r8 <<= 31;						\
	r9 = r8;						\
	r9 += 7;						\
	if r6 < r8 goto 1f;					\
	if r6 > r9 goto 1f;	/* r6 in [0x80000000, 0x80000007] */ \
	if r7 != -2147483641 goto 1f; /* reachable: r6 == 0x80000007 */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * Same for a narrowing fill: the slot is (s32)(r6 + 5), so the filled register
 * is (u32)(r6 + 5). Forcing the delta to 0 made the verifier believe r2 == r6.
 */
SEC("socket")
__success
__naked void sext_delta_survives_narrowing_fill(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 <<= 32;						\
	call %[bpf_get_prandom_u32];				\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	w7 = w6;		/* BPF_REG_LINK_ZEXT, delta 0 */	\
	w7 += 5;		/* BPF_REG_LINK_ZEXT, delta 5 */	\
	r8 = (s32)r7;		/* BPF_REG_LINK_SEXT, delta 5 */	\
	*(u64 *)(r10 - 8) = r8;	/* full spill keeps the link */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(u32 *)(r10 - 8);	/* narrowing fill inherits delta */ \
"
#else
"	r2 = *(u32 *)(r10 - 4);					\
"
#endif
"	if r6 != 0 goto 1f;	/* r6 == 0, so r2 == 5 */	\
	if r2 == 5 goto 1f;	/* always taken: r2 is 5 */	\
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

#endif /* CAN_USE_MOVSX */

#ifdef CAN_USE_LDSX

/*
 * The sign-extending counterpart: the filled register is the sign extension of
 * the slot's low 32 bits, so a narrowing of those bits arrives sign-extended.
 */
SEC("socket")
__success
__naked void sext_fill_narrow_from_wide_spill(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	*(u64 *)(r10 - 8) = r6;	/* slot linked to r6 */		\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(s32 *)(r10 - 8);	/* narrowing sx fill */		\
"
#else
"	r2 = *(s32 *)(r10 - 4);				\
"
#endif
"	if w6 != -1 goto 1f;	/* narrows r6, propagates to r2 */ \
	if r2 == -1 goto 1f;	/* sign-extended, not 0xffffffff */ \
	r0 /= 0;						\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * The same, for the two link kinds off one slot.
 */
SEC("socket")
__failure __msg("div by zero")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void fill_kinds_reach_different_values(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	r6 &= 1;						\
	call %[bpf_get_prandom_u32];				\
	r8 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r8 |= r0;						\
	*(u64 *)(r10 - 8) = r8;					\
	if r6 >= 1 goto 2f;					\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(s32 *)(r10 - 8);	/* sign-extending fill */	\
"
#else
"	r2 = *(s32 *)(r10 - 4);				\
"
#endif
"	goto 1f;						\
2:								\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(u32 *)(r10 - 8);	/* zero-extending fill */	\
"
#else
"	r2 = *(u32 *)(r10 - 4);				\
"
#endif
"1:								\
	if w8 != -1 goto 3f;					\
	if r2 == -1 goto 3f;	/* only the sign-extending path */ \
	r0 /= 0;						\
3:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * A sign-extending fill must not come away with a zero-extending link. The
 * slot below already fits 32 bits, so the fill is not narrowing and assigns
 * no link kind of its own, and "state->regs[dst] = *reg" copies the slot's
 * verbatim; check_mem_access() is what has to drop it, since it would leave
 * r2 recording a zero-extension of a value it has just sign-extended.
 * Asserted on the register dump rather than on a guarded branch, so it pins
 * the rule itself and not a downstream effect.
 */
SEC("socket")
__success __log_level(2)
/* a copied link would print as R2=scalar(id=N+0,smin=... */
__msg("(81) r2 = *(s32 *)(r10 {{.*}} R2=scalar(smin=")
__naked void sext_fill_does_not_inherit_zext_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	w7 = w6;		/* r7 = zext32(r6), fits 32 bits */ \
	*(u64 *)(r10 - 8) = r7;					\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(s32 *)(r10 - 8);	/* sign-extending, not narrowing */ \
"
#else
"	r2 = *(s32 *)(r10 - 4);					\
"
#endif
"	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

/*
 * BPF_REG_LINK_SEXT says the register is (s32)(base + delta) -- a 32-bit sign
 * extension specifically. An 8- or 16-bit ldsx is a different relation, so
 * the exemption that keeps a sign-extending link across a sign-extending
 * load has to be gated on the load width. Ungated, r2 below claims to be
 * (s32)r6 when it is really (s8)((s32)r6).
 */
SEC("socket")
__success __log_level(2)
#ifdef CAN_USE_MOVSX
/*
 * Needs MOVSX as well as LDSX: the BPF_REG_LINK_SEXT under test is built with
 * r7 = (s32)r6, and only the byte fill below is an ldsx.
 */
/* a surviving link would print as R2=scalar(id=N+0.sx,smin=... */
__msg("(91) r2 = *(s8 *)(r10 {{.*}} R2=scalar(smin=")
__naked void sext_byte_fill_drops_sext_link(void)
{
	asm volatile ("						\
	call %[bpf_get_prandom_u32];				\
	r6 = r0;						\
	call %[bpf_get_prandom_u32];				\
	r0 <<= 32;						\
	r6 |= r0;		/* r6 = full 64-bit unknown */	\
	r7 = (s32)r6;		/* r7 = BPF_REG_LINK_SEXT, delta 0 */	\
	if r7 > 255 goto 1f;	/* r7 fits a byte */		\
	*(u64 *)(r10 - 8) = r7;	/* full spill keeps the link */	\
"
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
"	r2 = *(s8 *)(r10 - 8);	/* 8-bit ldsx: no link survives */ \
"
#else
"	r2 = *(s8 *)(r10 - 1);					\
"
#endif
"	r0 = r2;		/* keep r2 live so the fill prints it */ \
	r0 &= 1;						\
	exit;							\
1:								\
	r0 = 0;							\
	exit;							\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}
#endif /* CAN_USE_MOVSX */

#endif /* CAN_USE_LDSX */

char _license[] SEC("license") = "GPL";
