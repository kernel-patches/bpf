// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Meta Platforms, Inc. and affiliates. */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/*
 * kernel/bpf/loops.c:compute_loops() distinguish between
 * the following cases:
 * - B: backedge -> simple loop
 * - C: cross edge to non-loop node -> no-op
 * - D: edge to node whose header is in DFS path -> nested loop
 * - E: edge to node whose header is NOT in DFS path -> irreducible
 *
 * Below test cases cover the above branches in various combinations.
 */

/* Case B: single bounded loop. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 0")
__msg("  1       1: {{.*}} (07) r0 += 1")
__msg("  1   1   2: {{.*}} (a5) if r0 < 0xa goto pc-2")
__msg("          3: {{.*}} (95) exit")
__naked void loop_single(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

/* Case B: two independent loops at the same nesting level. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 0")
__msg("  2       1: {{.*}} (07) r0 += 1")
__msg("  2   1   2: {{.*}} (a5) if r0 < 0xa goto pc-2")
__msg("          3: {{.*}} (b7) r1 = 0")
__msg("  1       4: {{.*}} (07) r1 += 1")
__msg("  1   4   5: {{.*}} (a5) if r1 < 0xa goto pc-2")
__msg("          6: {{.*}} (95) exit")
__naked void loop_two_independent(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	if r0 < 10 goto 1b;				\
	r1 = 0;						\
2:	r1 += 1;					\
	if r1 < 10 goto 2b;				\
	exit;						\
"	::: __clobber_all);
}

/* Case B + D: nested loops. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 0")
__msg("  1       1: {{.*}} (07) r0 += 1")		/* outer loop header */
__msg("  1   1   2: {{.*}} (b7) r1 = 0")		/* outer loop insn */
__msg("  1   1   3: {{.*}} (07) r1 += 1")		/* inner loop header */
__msg("  1   3   4: {{.*}} (a5) if r1 < 0x5 goto pc-2") /* inner loop insn */
__msg("  1   1   5: {{.*}} (a5) if r0 < 0xa goto pc-5") /* outer loop insn */
__msg("          6: {{.*}} (95) exit")
__naked void loop_nested(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	r1 = 0;						\
2:	r1 += 1;					\
	if r1 < 5 goto 2b;				\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

/* Case C: forward edges, no loops. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 1")
__msg("          1: {{.*}} (05) goto pc+2")
__msg("          2: {{.*}} (b7) r0 = 2")
__msg("          3: {{.*}} (05) goto pc+1")
__msg("          4: {{.*}} (b7) r0 = 3")
__msg("          5: {{.*}} (95) exit")
__naked void fwd_edges_no_loop(void)
{
	asm volatile ("					\
	r0 = 1;						\
	if r0 > 0 goto 1f;				\
	r0 = 2;						\
	goto 2f;					\
1:	r0 = 3;						\
2:	exit;						\
"	::: __clobber_all);
}

/* Case B + D: two sibling inner loops within one outer loop. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 0")
__msg("  1       1: {{.*}} (07) r0 += 1")
__msg("  1   1   2: {{.*}} (b7) r1 = 0")
__msg("  1   1   3: {{.*}} (07) r1 += 1")
__msg("  1   3   4: {{.*}} (a5) if r1 < 0x5 goto pc-2")
__msg("  1   1   5: {{.*}} (b7) r2 = 0")
__msg("  1   1   6: {{.*}} (07) r2 += 1")
__msg("  1   6   7: {{.*}} (a5) if r2 < 0x5 goto pc-2")
__msg("  1   1   8: {{.*}} (a5) if r0 < 0xa goto pc-8")
__msg("          9: {{.*}} (95) exit")
__naked void loop_nested_siblings(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	r1 = 0;						\
2:	r1 += 1;					\
	if r1 < 5 goto 2b;				\
	r2 = 0;						\
3:	r2 += 1;					\
	if r2 < 5 goto 3b;				\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

/* Three levels of nesting. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 0")
__msg("  1       1: {{.*}} (07) r0 += 1")
__msg("  1   1   2: {{.*}} (b7) r1 = 0")
__msg("  1   1   3: {{.*}} (07) r1 += 1")
__msg("  1   3   4: {{.*}} (b7) r2 = 0")
__msg("  1   3   5: {{.*}} (07) r2 += 1")
__msg("  1   5   6: {{.*}} (a5) if r2 < 0x3 goto pc-2")
__msg("  1   3   7: {{.*}} (a5) if r1 < 0x5 goto pc-5")
__msg("  1   1   8: {{.*}} (a5) if r0 < 0xa goto pc-8")
__msg("          9: {{.*}} (95) exit")
__naked void loop_three_levels(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	r1 = 0;						\
2:	r1 += 1;					\
	r2 = 0;						\
3:	r2 += 1;					\
	if r2 < 3 goto 3b;				\
	if r1 < 5 goto 2b;				\
	if r0 < 10 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

/* Loop with an if-else body (forward branch inside loop, Case C). */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (b7) r0 = 0")
__msg("  1       1: {{.*}} (07) r0 += 1")
__msg("  1   1   2: {{.*}} (bf) r1 = r0")
__msg("  1   1   3: {{.*}} (25) if r1 > 0x5 goto pc+1")
__msg("  1   1   4: {{.*}} (b7) r1 = 1")
__msg("  1   1   5: {{.*}} (0f) r0 += r1")
__msg("  1   1   6: {{.*}} (a5) if r0 < 0x64 goto pc-6")
__msg("          7: {{.*}} (95) exit")
__naked void loop_with_if_else(void)
{
	asm volatile ("					\
	r0 = 0;						\
1:	r0 += 1;					\
	r1 = r0;					\
	if r1 > 5 goto 2f;				\
	r1 = 1;						\
2:	r0 += r1;					\
	if r0 < 100 goto 1b;				\
	exit;						\
"	::: __clobber_all);
}

/* Case E: irreducible loop. */
SEC("socket")
__success
__log_level(2)
__msg("          0: {{.*}} (85) call bpf_get_prandom_u32")
__msg("          1: {{.*}} (b7) r1 = 0")
__msg("          2: {{.*}} (25) if r0 > 0x5 goto pc+2")
__msg("  1       3: {{.*}} (b7) r1 = 1")
__msg("  1   3   4: {{.*}} (05) goto pc+1")
__msg("          5: {{.*}} (b7) r1 = 2")
__msg("  1   3   6: {{.*}} (0f) r0 += r1")
__msg("  1   3   7: {{.*}} (a5) if r0 < 0x10 goto pc-5")
__msg("          8: {{.*}} (95) exit")
__naked void loop_irreducible(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r1 = 0;						\
	if r0 > 5 goto 2f;				\
1:	r1 = 1;						\
	goto 3f;					\
2:	r1 = 2;						\
3:	r0 += r1;					\
	if r0 < 16 goto 1b;				\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_all);
}

char _license[] SEC("license") = "GPL";
