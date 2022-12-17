// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

struct map_struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, int);
} map SEC(".maps");

/* Make sure that verifier.c:check_ids() can handle (almost) maximal
 * number of ids.
 */
SEC("?raw_tp")
__naked __test_state_freq __log_level(2) __msg("43 to 45: safe")
int allocate_many_ids(void)
{
	/* Use bpf_map_lookup_elem() as a way to get a bunch of values
	 * with unique ids.
	 */
#define __lookup(dst)				\
		"r1 = %[map] ll;"		\
		"r2 = r10;"			\
		"r2 += -8;"			\
		"call %[bpf_map_lookup_elem];"	\
		dst " = r0;"
	asm volatile(
		"r0 = 0;"
		"*(u64*)(r10 - 8) = r0;"
		"r7 = r10;"
		"r8 = 0;"
		/* Spill 64 bpf_map_lookup_elem() results to stack,
		 * each lookup gets its own unique id.
		 */
	"write_loop:"
		"r7 += -8;"
		"r8 += -8;"
		__lookup("*(u64*)(r7 + 0)")
		"if r8 != -512 goto write_loop;"
		/* No way to source unique ids for r1-r5 as these
		 * would be clobbered by bpf_map_lookup_elem call,
		 * so make do with 64+5 unique ids.
		 */
		__lookup("r6")
		__lookup("r7")
		__lookup("r8")
		__lookup("r9")
		__lookup("r0")
		/* Create a branching point for states comparison. */
/* 43: */	"if r0 != 0 goto skip_one;"
		/* Read all registers and stack spills to make these
		 * persist in the checkpoint state.
		 */
		"r0 = r0;"
	"skip_one:"
/* 45: */	"r0 = r6;"
		"r0 = r7;"
		"r0 = r8;"
		"r0 = r9;"
		"r0 = r10;"
		"r1 = 0;"
	"read_loop:"
		"r0 += -8;"
		"r1 += -8;"
		"r2 = *(u64*)(r0 + 0);"
		"if r1 != -512 goto read_loop;"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_map_lookup_elem),
		  __imm_addr(map)
		: __clobber_all);
#undef __lookup
}
