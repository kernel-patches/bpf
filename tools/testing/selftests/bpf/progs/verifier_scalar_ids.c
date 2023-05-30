// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* Verify that check_ids() is used by regsafe() for scalars.
 *
 * r9 = ... some pointer with range X ...
 * r6 = ... unbound scalar ID=a ...
 * r7 = ... unbound scalar ID=b ...
 * if (r6 > r7) goto +1
 * r6 = r7
 * if (r6 > X) goto exit
 * r9 += r7
 * *(u8 *)r9 = Y
 *
 * The memory access is safe only if r7 is bounded,
 * which is true for one branch and not true for another.
 */
SEC("socket")
__failure __msg("register with unbounded min value")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void ids_id_mapping_in_regsafe(void)
{
	asm volatile (
	/* Bump allocated stack */
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	/* r9 = pointer to stack */
	"r9 = r10;"
	"r9 += -8;"
	/* r7 = ktime_get_ns() */
	"call %[bpf_ktime_get_ns];"
	"r7 = r0;"
	/* r6 = ktime_get_ns() */
	"call %[bpf_ktime_get_ns];"
	"r6 = r0;"
	/* if r6 > r7 is an unpredictable jump */
	"if r6 > r7 goto l1_%=;"
	"r6 = r7;"
"l1_%=:"
	/* a noop to get to add new parent state */
	"r0 = r0;"
	/* if r6 > 4 exit(0) */
	"if r6 > 4 goto l2_%=;"
	/* Access memory at r9[r7] */
	"r9 += r7;"
	"r0 = *(u8*)(r9 + 0);"
"l2_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* Similar to a previous one, but shows that bpf_reg_state::precise
 * could not be used to filter out registers subject to check_ids() in
 * verifier.c:regsafe(). At 'l0' register 'r6' does not have 'precise'
 * flag set but it is important to have this register in the idmap.
 */
SEC("socket")
__failure __msg("register with unbounded min value")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void ids_id_mapping_in_regsafe_2(void)
{
	asm volatile (
	/* Bump allocated stack */
	"r1 = 0;"
	"*(u64*)(r10 - 8) = r1;"
	/* r9 = pointer to stack */
	"r9 = r10;"
	"r9 += -8;"
	/* r8 = ktime_get_ns() */
	"call %[bpf_ktime_get_ns];"
	"r8 = r0;"
	/* r7 = ktime_get_ns() */
	"call %[bpf_ktime_get_ns];"
	"r7 = r0;"
	/* r6 = ktime_get_ns() */
	"call %[bpf_ktime_get_ns];"
	"r6 = r0;"
	/* scratch .id from r0 */
	"r0 = 0;"
	/* if r6 > r7 is an unpredictable jump */
	"if r6 > r7 goto l1_%=;"
	/* tie r6 and r7 .id */
	"r6 = r7;"
"l0_%=:"
	/* if r7 > 4 exit(0) */
	"if r7 > 4 goto l2_%=;"
	/* Access memory at r9[r7] */
	"r9 += r6;"
	"r0 = *(u8*)(r9 + 0);"
"l2_%=:"
	"r0 = 0;"
	"exit;"
"l1_%=:"
	/* tie r6 and r8 .id */
	"r6 = r8;"
	"goto l0_%=;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* Label l1 could be reached in two combinations:
 *
 *   (1) r6{.id=A}, r7{.id=A}, r8{.id=B}
 *   (2) r6{.id=B}, r7{.id=A}, r8{.id=B}
 *
 * However neither A nor B are used in find_equal_scalars()
 * to transfer range information in this test.
 * Thus states (1) and (2) should be considered identical due
 * to bpf_verifier_env::range_transfer_ids handling.
 *
 * Make sure that this is the case by checking that second jump
 * to l1 hits cached state.
 */
SEC("socket")
__success __log_level(7) __msg("14: safe")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void no_range_transfer_ids(void)
{
	asm volatile (
	/* Bump allocated stack */
	"r1 = 0;"
	"*(u64*)(r10 - 16) = r1;"
	/* r9 = pointer to stack */
	"r9 = r10;"
	"r9 += -16;"
	/* r7 = ktime_get_ns() & 0b11 */
	"call %[bpf_ktime_get_ns];"
	"r8 = r0;"
	"r8 &= 3;"
	/* r6 = ktime_get_ns() & 0b11 */
	"call %[bpf_ktime_get_ns];"
	"r7 = r0;"
	"r7 &= 3;"
	/* if r6 > r7 is an unpredictable jump */
	"if r7 > r8 goto l0_%=;"
	"r6 = r7;"
	"goto l1_%=;"
"l0_%=:"
	"r6 = r8;"
"l1_%=:"
	/* insn #14 */
	"r9 += r6;"
	"r9 += r7;"
	"r9 += r8;"
	"r0 = *(u8*)(r9 + 0);"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

/* Same as above, but cached state for l1 has id used for
 * range transfer:
 *
 *   (1) r6{.id=A}, r7{.id=A}, r8{.id=B}
 *   (2) r6{.id=B}, r7{.id=A}, r8{.id=B}
 *
 * If (A) is used for range transfer (1) and (2) should not
 * be considered identical.
 *
 * Check this by verifying that instruction immediately following l1
 * is visited twice.
 */
SEC("socket")
__success __log_level(7) __msg("r9 = r9") __msg("r9 = r9")
__flag(BPF_F_TEST_STATE_FREQ)
__naked void has_range_transfer_ids(void)
{
	asm volatile (
	/* Bump allocated stack */
	"r1 = 0;"
	"*(u64*)(r10 - 16) = r1;"
	/* r9 = pointer to stack */
	"r9 = r10;"
	"r9 += -16;"
	/* r7 = ktime_get_ns() & 0b11 */
	"call %[bpf_ktime_get_ns];"
	"r8 = r0;"
	/* r6 = ktime_get_ns() & 0b11 */
	"call %[bpf_ktime_get_ns];"
	"r7 = r0;"
	/* if r6 > r7 is an unpredictable jump */
	"if r7 > r8 goto l0_%=;"
	"r6 = r7;"
	"goto l1_%=;"
"l0_%=:"
	"r6 = r8;"
"l1_%=:"
	/* just a unique marker, this insn should be verified twice */
	"r9 = r9;"
	/* one of the instructions below transfers range for r6 */
	"if r7 > 2 goto l2_%=;"
	"if r8 > 2 goto l2_%=;"
	"r9 += r6;"
	"r9 += r7;"
	"r9 += r8;"
	"r0 = *(u8*)(r9 + 0);"
"l2_%=:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_ktime_get_ns)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
