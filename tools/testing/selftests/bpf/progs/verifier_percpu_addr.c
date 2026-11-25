// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

#if defined(__TARGET_ARCH_x86)

int percpu_data SEC(".percpu");

/*
 * An ld_imm64 of a per-CPU map value is followed by a mov_percpu_addr that
 * reuses the same register, so check that the add resolves into the register
 * the address was loaded into, for every register.
 */
SEC("raw_tp")
__description("per-CPU address resolution")
__success
__arch_x86_64
__jited("	movabsq	$0x{{.*}}, %rax")
__jited("	addq	%gs:{{.*}}, %rax")
__jited("	movabsq	$0x{{.*}}, %rdi")
__jited("	addq	%gs:{{.*}}, %rdi")
__jited("	movabsq	$0x{{.*}}, %rsi")
__jited("	addq	%gs:{{.*}}, %rsi")
__jited("	movabsq	$0x{{.*}}, %rdx")
__jited("	addq	%gs:{{.*}}, %rdx")
__jited("	movabsq	$0x{{.*}}, %rcx")
__jited("	addq	%gs:{{.*}}, %rcx")
__jited("	movabsq	$0x{{.*}}, %r8")
__jited("	addq	%gs:{{.*}}, %r8")
__jited("	movabsq	$0x{{.*}}, %rbx")
__jited("	addq	%gs:{{.*}}, %rbx")
__jited("	movabsq	$0x{{.*}}, %r13")
__jited("	addq	%gs:{{.*}}, %r13")
__jited("	movabsq	$0x{{.*}}, %r14")
__jited("	addq	%gs:{{.*}}, %r14")
__jited("	movabsq	$0x{{.*}}, %r15")
__jited("	addq	%gs:{{.*}}, %r15")
__naked void percpu_addr(void)
{
	asm volatile ("					\
	r0 = %[percpu_data] ll;				\
	r1 = %[percpu_data] ll;				\
	r2 = %[percpu_data] ll;				\
	r3 = %[percpu_data] ll;				\
	r4 = %[percpu_data] ll;				\
	r5 = %[percpu_data] ll;				\
	r6 = %[percpu_data] ll;				\
	r7 = %[percpu_data] ll;				\
	r8 = %[percpu_data] ll;				\
	r9 = %[percpu_data] ll;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm_addr(percpu_data)
	: __clobber_all);
}

/*
 * The mov_percpu_addr is inserted behind the ld_imm64, between a jump with the
 * smallest offset and its target. The program is valid, it is only rejected
 * because the verifier can not widen a jump when it patches a program.
 */
SEC("raw_tp")
__description("per-CPU address does not fit behind a ld_imm64")
__failure __msg("cannot be patched due to 16-bit range")
__arch_x86_64
__naked void percpu_addr_jump_out_of_range(void)
{
	asm volatile ("					\
	call %[bpf_get_prandom_u32];			\
	r6 = r0;					\
	r7 = 0;						\
	goto l1_%=;					\
l0_%=:	r0 = 0;						\
	exit;						\
l1_%=:	r1 = %[percpu_data] ll;				\
	.rept 32763;					\
	r2 = 0;						\
	.endr;						\
	if r7 != r6 goto l0_%=;				\
	r0 = 0;						\
	exit;						\
"	:
	: __imm(bpf_get_prandom_u32),
	  __imm_addr(percpu_data)
	: __clobber_all);
}

#else

SEC("raw_tp")
__description("percpu addr dummy")
__skip("percpu addr tests need x86")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
