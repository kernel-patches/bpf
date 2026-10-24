// SPDX-License-Identifier: GPL-2.0

#define BPF_NO_KFUNC_PROTOTYPES
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern __u64 bpf_rol64(__u64 x, __u32 n) __ksym;
extern __u64 bpf_select64(__u64 cond, __u64 a, __u64 b) __ksym;

/* The JIT copies bpf_rol64() and the verifier removes the spill/fill of r4.
 * On x86-64 the copy uses rcx, which holds r4, so the JIT pushes and pops it.
 */
SEC("tc")
__arch_x86_64
__xlated("0: r1 = 0x123456789abcdef")
__xlated("2: r2 = 8")
__xlated("3: r4 = 7")
__xlated("4: call")
__xlated("5: r3 = 0x23456789abcdef01")
__jited("...")
__jited("	pushq	%rcx")
__jited("...")
__jited("	rolq	%cl, %rax")
__jited("	popq	%rcx")
__arch_arm64
__jited("...")
__jited("	ror	x0, x0, x{{[0-9]+}}")
__jited("	mov	x8, x0")
__success __retval(1)
__naked void kfunc_inline_rol64_keeps_live_reg(void)
{
	asm volatile (
	"r1 = 0x0123456789abcdef ll;"
	"r2 = 8;"
	"r4 = 7;"
	"*(u64 *)(r10 - 8) = r4;"
	"call %[bpf_rol64];"
	"r4 = *(u64 *)(r10 - 8);"
	"r3 = 0x23456789abcdef01 ll;"
	"if r0 != r3 goto 1f;"
	"if r4 != 7 goto 1f;"
	"r0 = 1;"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_rol64)
	: __clobber_all);
}

/* r4 is not live after the call, so the JIT does not push/pop rcx */
SEC("tc")
__arch_x86_64
__jited("...")
__jited("	movl	$0x8, %esi")
__jited("	{{movl	%esi, %ecx|movq	%rdi, %rax}}")
__jited("	{{movl	%esi, %ecx|movq	%rdi, %rax}}")
__jited("	rolq	%cl, %rax")
__arch_arm64
__jited("...")
__jited("	ror	x0, x0, x{{[0-9]+}}")
__jited("	mov	x8, x0")
__success __retval(0x23)
__naked void kfunc_inline_rol64_dead_reg(void)
{
	asm volatile (
	"r1 = 0x0123456789abcdef ll;"
	"r2 = 8;"
	"call %[bpf_rol64];"
	"r0 >>= 56;"
	"exit;"
	:
	: __imm(bpf_rol64)
	: __clobber_all);
}

/* bpf_select64() uses only its arguments and the result register: r4 and r5
 * survive it without being saved once their spill/fill is removed.
 */
SEC("tc")
__arch_x86_64
__xlated("0: r1 = 0")
__xlated("1: r2 = 2")
__xlated("2: r3 = 3")
__xlated("3: r4 = 4")
__xlated("4: r5 = 5")
__xlated("5: call")
__xlated("6: r0 += r4")
__jited("...")
__jited("	{{cmov.*}}")
__arch_arm64
__jited("...")
__jited("	{{csel.*}}")
__jited("	mov	x8, x0")
__jited("	add	x8, x8, x3")
__success __retval(12)
__naked void kfunc_inline_select64(void)
{
	asm volatile (
	"r1 = 0;"
	"r2 = 2;"
	"r3 = 3;"
	"r4 = 4;"
	"r5 = 5;"
	"*(u64 *)(r10 - 8) = r4;"
	"*(u64 *)(r10 - 16) = r5;"
	"call %[bpf_select64];"
	"r5 = *(u64 *)(r10 - 16);"
	"r4 = *(u64 *)(r10 - 8);"
	"r0 += r4;"
	"r0 += r5;"
	"exit;"
	:
	: __imm(bpf_select64)
	: __clobber_all);
}

/* A comparison compiles to setcc on x86-64 and cset on arm64 */
SEC("tc")
__arch_x86_64
__xlated("0: r1 = 3")
__xlated("1: r2 = 5")
__xlated("2: r5 = 9")
__xlated("3: call")
__xlated("4: r0 += r5")
__jited("...")
__jited("	{{setb	%al|setae	%al|seta	%al|setbe	%al|setl	%al|setg	%al}}")
__arch_arm64
__jited("...")
__jited("	cmp	x0, x1")
__jited("	{{cset.*}}")
__jited("	mov	x8, x0")
__jited("	add	x8, x8, x4")
__success __retval(10)
__naked void kfunc_inline_byte_ops(void)
{
	asm volatile (
	"r1 = 3;"
	"r2 = 5;"
	"r5 = 9;"
	"*(u64 *)(r10 - 8) = r5;"
	"call %[bpf_kfunc_call_test_fastcall_lt];"
	"r5 = *(u64 *)(r10 - 8);"
	"r0 += r5;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_fastcall_lt)
	: __clobber_all);
}

/* The copied code uses some of r2-r5 as temporaries, the JIT keeps them */
SEC("tc")
__arch_x86_64
__arch_arm64
__xlated("0: r1 = 1000003")
__xlated("1: r2 = 2")
__xlated("2: r3 = 3")
__xlated("3: r4 = 4")
__xlated("4: r5 = 5")
__xlated("5: call")
__xlated("6: if r2 != 0x2")
__success __retval(1)
__naked void kfunc_inline_keeps_live_regs(void)
{
	asm volatile (
	"r1 = 1000003;"
	"r2 = 2;"
	"r3 = 3;"
	"r4 = 4;"
	"r5 = 5;"
	"*(u64 *)(r10 - 8) = r2;"
	"*(u64 *)(r10 - 16) = r3;"
	"*(u64 *)(r10 - 24) = r4;"
	"*(u64 *)(r10 - 32) = r5;"
	"call %[bpf_kfunc_call_test_fastcall_mix];"
	"r5 = *(u64 *)(r10 - 32);"
	"r4 = *(u64 *)(r10 - 24);"
	"r3 = *(u64 *)(r10 - 16);"
	"r2 = *(u64 *)(r10 - 8);"
	"if r2 != 2 goto 1f;"
	"if r3 != 3 goto 1f;"
	"if r4 != 4 goto 1f;"
	"if r5 != 5 goto 1f;"
	"if r0 != 0x3641cb goto 1f;"
	"r0 = 1;"
	"exit;"
"1:"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_fastcall_mix)
	: __clobber_all);
}

/* A kfunc with a branch is not copied: it is called and its spill/fill stays */
SEC("tc")
__xlated("0: r1 = 12")
__xlated("1: r2 = 4")
__xlated("2: r5 = 9")
__xlated("3: *(u64 *)(r10 -8) = r5")
__xlated("4: call")
__xlated("5: r5 = *(u64 *)(r10 -8)")
__success __retval(12)
__naked void kfunc_not_inlined_keeps_spill_fill(void)
{
	asm volatile (
	"r1 = 12;"
	"r2 = 4;"
	"r5 = 9;"
	"*(u64 *)(r10 - 8) = r5;"
	"call %[bpf_kfunc_call_test_fastcall_div];"
	"r5 = *(u64 *)(r10 - 8);"
	"r0 += r5;"
	"exit;"
	:
	: __imm(bpf_kfunc_call_test_fastcall_div)
	: __clobber_all);
}

/* BTF FUNC records are not generated for kfuncs referenced from inline
 * assembly, and libbpf needs them to link the programs: call the kfuncs from C.
 */
void kfunc_root(void)
{
	bpf_rol64(0, 0);
	bpf_select64(0, 0, 0);
	bpf_kfunc_call_test_fastcall_lt(0, 0);
	bpf_kfunc_call_test_fastcall_mix(0);
	bpf_kfunc_call_test_fastcall_div(0, 0);
}

char _license[] SEC("license") = "GPL";
