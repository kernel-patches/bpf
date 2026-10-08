// SPDX-License-Identifier: GPL-2.0
/*
 * Verifier selftests for symmetric register-form NULL-pointer checks.
 *
 * The BPF verifier's check_cond_jmp_op() handles "if R == 0" NULL checks by
 * calling mark_ptr_or_null_regs() to mark the nullable pointer as either safe
 * or unknown in each branch.  Historically only the forward case was covered:
 *   dst_reg = nullable pointer,  src_reg = known-zero scalar
 * i.e. "if (map_val == 0)".
 *
 * The symmetric case was missing:
 *   dst_reg = known-zero scalar, src_reg = nullable pointer
 * i.e. "if (0 == map_val)" or "if (r0 == map_val)" where r0 is proven zero.
 *
 * Without the fix the verifier leaves src_reg as PTR_MAYBE_NULL in both
 * branches, either rejecting a valid program or silently missing a required
 * null check.  With the fix, nullness is propagated correctly in both
 * directions.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} sym_null_map SEC(".maps");

/* ---- Forward case (already worked before the fix) ---- */

/*
 * "if (map_val == 0)" -- dst_reg holds the nullable pointer,
 * src_reg is the literal-zero immediate (BPF_K).  Should be accepted.
 */
SEC("socket")
__description("null check: forward form (dst nullable, imm 0) accepted")
__success __retval(0)
__naked void null_check_forward_imm(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64 *)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[sym_null_map] ll;			\
	call %[bpf_map_lookup_elem];			\
	/* r0 = nullable ptr; forward case: if (r0 == 0) */	\
	if r0 == 0 goto exit_fwd;			\
	/* r0 is non-null here -- safe to dereference */\
	r1 = *(u32 *)(r0 + 0);				\
exit_fwd:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(sym_null_map)
	: __clobber_all);
}

/* ---- Symmetric case (required the new fix) ---- */

/*
 * "if (0 == map_val)" -- src_reg holds the nullable pointer,
 * dst_reg is a register that the verifier has proven equals zero.
 * Should be accepted; before the fix it was rejected because nullness
 * was never propagated for src_reg.
 */
SEC("socket")
__description("null check: symmetric form (src nullable, dst zero reg) accepted")
__success __retval(0)
__naked void null_check_symmetric_reg(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64 *)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[sym_null_map] ll;			\
	call %[bpf_map_lookup_elem];			\
	/* r0 = nullable ptr, r6 = known 0 */		\
	r6 = 0;						\
	/* Symmetric check: if (r6 == r0), i.e. dst=r6 (zero), src=r0 (nullable) */\
	if r6 == r0 goto exit_sym;			\
	/* r0 is non-null here -- safe to dereference */\
	r1 = *(u32 *)(r0 + 0);				\
exit_sym:						\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(sym_null_map)
	: __clobber_all);
}

/*
 * BPF_JNE symmetric form: "if (r6 != r0) goto use_r0;"
 * In the fall-through branch r0 == r6 == 0, so it is null.
 * In the taken branch r0 is non-null and safe to dereference.
 */
SEC("socket")
__description("null check: symmetric JNE form (src nullable, dst zero reg) accepted")
__success __retval(0)
__naked void null_check_symmetric_jne(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64 *)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[sym_null_map] ll;			\
	call %[bpf_map_lookup_elem];			\
	r6 = 0;						\
	/* if (r6 != r0) goto use_r0 */			\
	if r6 != r0 goto use_r0;			\
	/* fall-through: r0 is null here, just exit */	\
	r0 = 0;						\
	exit;						\
use_r0:							\
	/* r0 is non-null here -- safe to dereference */\
	r1 = *(u32 *)(r0 + 0);				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(sym_null_map)
	: __clobber_all);
}

/*
 * Negative test: src_reg is nullable, dst_reg is non-zero scalar.
 * This must NOT be treated as a null check -- the verifier should
 * still reject a dereference of r0 without a proper null guard.
 */
SEC("socket")
__description("null check: symmetric form with non-zero dst must not elide null check")
__failure __msg("R0 invalid mem access 'map_value_or_null'")
__naked void null_check_symmetric_nonzero_dst_rejected(void)
{
	asm volatile ("					\
	r1 = 0;						\
	*(u64 *)(r10 - 8) = r1;				\
	r2 = r10;					\
	r2 += -8;					\
	r1 = %[sym_null_map] ll;			\
	call %[bpf_map_lookup_elem];			\
	/* r6 = 1 (non-zero) -- this is NOT a null check */\
	r6 = 1;						\
	if r6 == r0 goto skip;				\
	/* r0 still PTR_MAYBE_NULL here, dereference must fail */\
	r1 = *(u32 *)(r0 + 0);				\
skip:							\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_map_lookup_elem),
	  __imm_addr(sym_null_map)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
