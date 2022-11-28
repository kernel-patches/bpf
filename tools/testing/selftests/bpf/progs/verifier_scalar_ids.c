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
__description("scalar ids: ID mapping in regsafe()")
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

char _license[] SEC("license") = "GPL";
