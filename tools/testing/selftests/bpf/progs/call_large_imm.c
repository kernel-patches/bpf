// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * A volatile global variable is used here, so that padding_subprog()
 * will not be optimized, and it will not be really executed even if
 * it is successfully loaded (when JIT is enabled).
 */
volatile int zero = 0;

/*
 * 32765 is the exact minimum number of padding instructions needed to
 * trigger the verifier failure, because:
 * 1. Counting the wrapper instructions around the padding block (one
 *    "r0=0" and two "exit" instructions), the actual jump distance
 *    evaluates to N + 3.
 * 2. To overflow the s16 max bound (32767), we need N + 3 > 32767.
 * Thus, N = 32765 is the exact minimum padding size required.
 */
static __attribute__((noinline)) void padding_subprog(void)
{
	asm volatile ("					\
		r0 = 0;					\
		.rept 32765;				\
		r0 += 0;				\
		.endr;					\
	" ::: "r0");
}

static __attribute__((noinline)) int target_subprog(void)
{
	/* A volatile variable is used here to prevent optimization. */
	volatile int magic_ret = 3;
	return magic_ret;
}

SEC("syscall")
int call_large_imm_test(void *ctx)
{
	if (zero)
		padding_subprog();
	return target_subprog();
}

char LICENSE[] SEC("license") = "GPL";
