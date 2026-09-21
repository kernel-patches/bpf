// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */

#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

#define ITER_HELPERS						\
	  __imm(bpf_iter_num_new),				\
	  __imm(bpf_iter_num_next),				\
	  __imm(bpf_iter_num_destroy)

SEC("?raw_tp")
__success
int force_clang_to_emit_btf_for_externs(void *ctx)
{
	/* we need this as a workaround to enforce compiler emitting BTF
	 * information for bpf_iter_num_{new,next,destroy}() kfuncs,
	 * as, apparently, it doesn't emit it for symbols only referenced from
	 * assembly (or cleanup attribute, for that matter, as well)
	 */
	bpf_repeat(0);

	return 0;
}

SEC("?raw_tp")
__success
int consume_first_item_only(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"

		/* consume first item */
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"

		"if r0 == 0 goto +1;"
		"r0 = *(u32 *)(r0 + 0);"

		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common
	);

	return 0;
}

SEC("?raw_tp")
__failure __msg("R0 invalid mem access 'scalar'")
int missing_null_check_fail(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"

		/* consume first element */
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"

		/* FAIL: deref with no NULL check */
		"r1 = *(u32 *)(r0 + 0);"

		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common
	);

	return 0;
}

SEC("?raw_tp")
__failure
__msg("invalid access to memory, mem_size=4 off=0 size=8")
__msg("R0 min value is outside of the allowed memory range")
int wrong_sized_read_fail(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 1000;"
		"call %[bpf_iter_num_new];"

		/* consume first element */
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"

		"if r0 == 0 goto +1;"
		/* FAIL: deref more than available 4 bytes */
		"r0 = *(u64 *)(r0 + 0);"

		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common
	);

	return 0;
}

SEC("?raw_tp")
__success __log_level(2)
__flag(BPF_F_TEST_STATE_FREQ)
int simplest_loop(void *ctx)
{
	struct bpf_iter_num iter;

	asm volatile (
		"r6 = 0;" /* init sum */

		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"

	"1:"
		/* consume next item */
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"

		"if r0 == 0 goto 2f;"
		"r0 = *(u32 *)(r0 + 0);"
		"r6 += r0;" /* accumulate sum */
		"goto 1b;"

	"2:"
		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common, "r6"
	);

	return 0;
}

SEC("?raw_tp")
__success
__log_level(2) __log_always
__msg("processed {{[1-9][0-9]?[0-9]?}} insns")
__naked int widening_counter(void)
{
	asm volatile (
		"r6 = 0;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 2f;"
		"r6 += 1;"
		"goto 1b;"
	"2:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: ITER_HELPERS
		: __clobber_all
	);
}

SEC("?raw_tp")
__success
__log_level(2) __log_always
__naked int widening_late_precision(void)
{
	/*
	 * int arr[10], i = 0, a = 0;
	 * while (bpf_iter_num_next(&it)) {
	 *   if (a == 0) {
	 *     a = 1;
	 *     i = 7;
	 *   } else {
	 *     arr[i] = 42;
	 *   }
	 * }
	 *
	 * R7 must retain 7 across the next iter_next call, so that the
	 * following body can use it as a stack-array index in R1.
	 */
	asm volatile (
		"r6 = 0;"
		"r7 = 0;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 3f;"
		"if r6 != 0 goto 2f;"
		"r6 = 1;"
		"r7 = 7;"
		"goto 1b;"
	"2:"
		"r1 = r7;"
		"r1 <<= 2;"
		"r2 = r10;"
		"r2 += -48;"
		"r2 += r1;"
		"*(u32 *)(r2 + 0) = 42;"
		"goto 1b;"
	"3:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: ITER_HELPERS
		: __clobber_all
	);
}

SEC("?raw_tp")
__success
__log_level(2) __log_always
__naked int widening_late_precision_large_init(void)
{
	asm volatile (
		"r6 = 0;"
		"r7 = 1000;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 3f;"
		"if r6 != 0 goto 2f;"
		"r6 = 1;"
		"r7 = 7;"
		"goto 1b;"
	"2:"
		"r1 = r7;"
		"r1 <<= 2;"
		"r2 = r10;"
		"r2 += -48;"
		"r2 += r1;"
		"*(u32 *)(r2 + 0) = 42;"
		"goto 1b;"
	"3:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: ITER_HELPERS
		: __clobber_all
	);
}

SEC("?raw_tp")
__failure __msg("invalid read from stack R0 off=-520 size=8")
__log_level(2) __log_always
__naked int widening_delayed_precision_unsafe(void)
{
	/* The unsafe loop from commit 2793a8b015f7 ("bpf: exact states
	 * comparison for iterator convergence checks"). Explore the update
	 * of r7 before the branch that uses it as a stack offset, while read
	 * and precision marks are still incomplete. Use -520 instead of -32
	 * to remain unsafe even when uninitialized stack reads are allowed.
	 */
	asm volatile (
		"*(u64 *)(r10 - 16) = 0;"
		"r7 = -16;"
		"call %[bpf_get_prandom_u32];"
		"r6 = r0;"
		"r1 = r10;"
		"r1 += -8;"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 3f;"
		"if r6 == 42 goto 2f;"
		"r7 = -520;"
		"call %[bpf_get_prandom_u32];"
		"r6 = r0;"
		"goto 1b;"
	"2:"
		"r0 = r10;"
		"r0 += r7;"
		"r8 = *(u64 *)(r0 + 0);"
		"call %[bpf_get_prandom_u32];"
		"r6 = r0;"
		"goto 1b;"
	"3:"
		"r1 = r10;"
		"r1 += -8;"
		"call %[bpf_iter_num_destroy];"
		"r0 = 0;"
		"exit;"
		:
		: ITER_HELPERS, __imm(bpf_get_prandom_u32)
		: __clobber_all
	);
}

__used
static void iterator_with_diff_stack_depth(int x)
{
	struct bpf_iter_num iter;

	asm volatile (
		"if r1 == 42 goto 0f;"
		"*(u64 *)(r10 - 128) = 0;"
	"0:"
		/* create iterator */
		"r1 = %[iter];"
		"r2 = 0;"
		"r3 = 10;"
		"call %[bpf_iter_num_new];"
	"1:"
		/* consume next item */
		"r1 = %[iter];"
		"call %[bpf_iter_num_next];"
		"if r0 == 0 goto 2f;"
		"goto 1b;"
	"2:"
		/* destroy iterator */
		"r1 = %[iter];"
		"call %[bpf_iter_num_destroy];"
		:
		: __imm_ptr(iter), ITER_HELPERS
		: __clobber_common, "r6"
	);
}

SEC("socket")
__success
__naked int widening_stack_size_bug(void *ctx)
{
	/*
	 * Depending on iterator_with_diff_stack_depth() parameter value,
	 * subprogram stack depth is either 8 or 128 bytes. Arrange values so
	 * that it is 128 on a first call and 8 on a second. This triggered a
	 * bug in verifier's widen_imprecise_scalars() logic.
	 */
	asm volatile (
		"r6 = 0;"
		"r1 = 0;"
	"1:"
		"call iterator_with_diff_stack_depth;"
		"r1 = 42;"
		"r6 += 1;"
		"if r6 < 2 goto 1b;"
		"r0 = 0;"
		"exit;"
		::: __clobber_all);
}
