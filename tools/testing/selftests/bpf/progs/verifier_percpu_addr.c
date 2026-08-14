// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

int percpu_data SEC(".percpu");

#if defined(__TARGET_ARCH_x86)

/*
 * An ld_imm64 of a per-CPU map value is followed by a mov_percpu_addr that
 * reuses the same register, so the register the address lands in decides how
 * the JIT encodes the add. On x86 R5, R7, R8 and R9 are the extended
 * registers, whose high bit needs REX.R because the destination sits in
 * ModRM.reg. Check one program per extended register, since getting the
 * prefix wrong resolves the address into whichever register shares the low
 * three bits instead.
 */

SEC("raw_tp")
__description("per-CPU address into r5")
__success
__arch_x86_64
__jited("	addq	%gs:{{.*}}, %r8")
__naked void percpu_addr_into_r5(void)
{
	asm volatile ("					\
	r5 = %[percpu_data] ll;				\
	r0 = *(u32 *)(r5 + 0);				\
	exit;						\
"	:
	: __imm_addr(percpu_data)
	: __clobber_all);
}

SEC("raw_tp")
__description("per-CPU address into r7")
__success
__arch_x86_64
__jited("	addq	%gs:{{.*}}, %r13")
__naked void percpu_addr_into_r7(void)
{
	asm volatile ("					\
	r7 = %[percpu_data] ll;				\
	r0 = *(u32 *)(r7 + 0);				\
	exit;						\
"	:
	: __imm_addr(percpu_data)
	: __clobber_all);
}

SEC("raw_tp")
__description("per-CPU address into r8")
__success
__arch_x86_64
__jited("	addq	%gs:{{.*}}, %r14")
__naked void percpu_addr_into_r8(void)
{
	asm volatile ("					\
	r8 = %[percpu_data] ll;				\
	r0 = *(u32 *)(r8 + 0);				\
	exit;						\
"	:
	: __imm_addr(percpu_data)
	: __clobber_all);
}

SEC("raw_tp")
__description("per-CPU address into r9")
__success
__arch_x86_64
__jited("	addq	%gs:{{.*}}, %r15")
__naked void percpu_addr_into_r9(void)
{
	asm volatile ("					\
	r9 = %[percpu_data] ll;				\
	r0 = *(u32 *)(r9 + 0);				\
	exit;						\
"	:
	: __imm_addr(percpu_data)
	: __clobber_all);
}

/* A register that needs no REX.R, to catch a fix that overcorrects. */
SEC("raw_tp")
__description("per-CPU address into r1")
__success
__arch_x86_64
__jited("	addq	%gs:{{.*}}, %rdi")
__naked void percpu_addr_into_r1(void)
{
	asm volatile ("					\
	r1 = %[percpu_data] ll;				\
	r0 = *(u32 *)(r1 + 0);				\
	exit;						\
"	:
	: __imm_addr(percpu_data)
	: __clobber_all);
}

#else

SEC("raw_tp")
__description("percpu addr dummy")
__success
int dummy_test(void)
{
	return 0;
}

#endif

char _license[] SEC("license") = "GPL";
