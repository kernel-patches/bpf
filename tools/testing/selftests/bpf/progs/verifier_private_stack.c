// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

/* From include/linux/filter.h */
#define MAX_BPF_STACK    512

#if defined(__TARGET_ARCH_x86)

SEC("kprobe")
__description("Private stack, single prog")
__success
__arch_x86_64
__jited("	movabsq	$0x{{.*}}, %r9")
__jited("	addq	%gs:0x{{.*}}, %r9")
__jited("	movl	$0x2a, %edi")
__jited("	movq	%rdi, -0x100(%r9)")
__naked void private_stack_single_prog(void)
{
	asm volatile (
	"r1 = 42;"
	"*(u64 *)(r10 - 256) = r1;"
	"r0 = 0;"
	"exit;"
	:
	:
	: __clobber_all);
}

__used
__naked static void cumulative_stack_depth_subprog(void)
{
        asm volatile (
	"r1 = 41;"
        "*(u64 *)(r10 - 32) = r1;"
        "call %[bpf_get_smp_processor_id];"
        "exit;"
        :: __imm(bpf_get_smp_processor_id)
	: __clobber_all);
}

SEC("kprobe")
__description("Private stack, subtree > MAX_BPF_STACK")
__success
__arch_x86_64
/* private stack fp for the main prog */
__jited("	movabsq	$0x{{.*}}, %r9")
__jited("	addq	%gs:0x{{.*}}, %r9")
__jited("	movl	$0x2a, %edi")
__jited("	movq	%rdi, -0x200(%r9)")
__jited("	pushq	%r9")
__jited("	callq	0x{{.*}}")
__jited("	popq	%r9")
__jited("	xorl	%eax, %eax")
__naked void private_stack_nested_1(void)
{
	asm volatile (
	"r1 = 42;"
	"*(u64 *)(r10 - %[max_bpf_stack]) = r1;"
	"call cumulative_stack_depth_subprog;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_const(max_bpf_stack, MAX_BPF_STACK)
	: __clobber_all);
}

SEC("kprobe")
__description("Private stack, subtree > MAX_BPF_STACK")
__success
__arch_x86_64
/* private stack fp for the subprog */
__jited("	addq	$0x20, %r9")
__naked void private_stack_nested_2(void)
{
	asm volatile (
	"r1 = 42;"
	"*(u64 *)(r10 - %[max_bpf_stack]) = r1;"
	"call cumulative_stack_depth_subprog;"
	"r0 = 0;"
	"exit;"
	:
	: __imm_const(max_bpf_stack, MAX_BPF_STACK)
	: __clobber_all);
}

SEC("raw_tp")
__description("No private stack, nested")
__success
__arch_x86_64
__jited("	subq	$0x8, %rsp")
__naked void no_private_stack_nested(void)
{
	asm volatile (
	"r1 = 42;"
	"*(u64 *)(r10 - 8) = r1;"
	"call cumulative_stack_depth_subprog;"
	"r0 = 0;"
	"exit;"
	:
	:
	: __clobber_all);
}

__naked __noinline __used
static unsigned long loop_callback()
{
	asm volatile (
	"call %[bpf_get_prandom_u32];"
	"r1 = 42;"
	"*(u64 *)(r10 - 512) = r1;"
	"call cumulative_stack_depth_subprog;"
	"r0 = 0;"
	"exit;"
	:
	: __imm(bpf_get_prandom_u32)
	: __clobber_common);
}

SEC("raw_tp")
__description("Private stack, callback")
__success
__arch_x86_64
/* for func loop_callback */
__jited("func #1")
__jited("	endbr64")
__jited("	nopl	(%rax,%rax)")
__jited("	nopl	(%rax)")
__jited("	pushq	%rbp")
__jited("	movq	%rsp, %rbp")
__jited("	endbr64")
__jited("	movabsq	$0x{{.*}}, %r9")
__jited("	addq	%gs:0x{{.*}}, %r9")
__jited("	pushq	%r9")
__jited("	callq")
__jited("	popq	%r9")
__jited("	movl	$0x2a, %edi")
__jited("	movq	%rdi, -0x200(%r9)")
__jited("	pushq	%r9")
__jited("	callq")
__jited("	popq	%r9")
__naked void private_stack_callback(void)
{
	asm volatile (
	"r1 = 1;"
	"r2 = %[loop_callback];"
	"r3 = 0;"
	"r4 = 0;"
	"call %[bpf_loop];"
	"r0 = 0;"
	"exit;"
	:
	: __imm_ptr(loop_callback),
	  __imm(bpf_loop)
	: __clobber_common);
}

SEC("fentry/bpf_fentry_test9")
__description("Private stack, exception in main prog")
__success __retval(0)
__arch_x86_64
__jited("	pushq	%r9")
__jited("	callq")
__jited("	popq	%r9")
int private_stack_exception_main_prog(void)
{
	asm volatile (
	"r1 = 42;"
	"*(u64 *)(r10 - 512) = r1;"
	::: __clobber_common);

	bpf_throw(0);
	return 0;
}

__used static int subprog_exception(void)
{
	bpf_throw(0);
	return 0;
}

SEC("fentry/bpf_fentry_test9")
__description("Private stack, exception in subprog")
__success __retval(0)
__arch_x86_64
__jited("	movq	%rdi, -0x200(%r9)")
__jited("	pushq	%r9")
__jited("	callq")
__jited("	popq	%r9")
int private_stack_exception_sub_prog(void)
{
	asm volatile (
	"r1 = 42;"
	"*(u64 *)(r10 - 512) = r1;"
	"call subprog_exception;"
	::: __clobber_common);

	return 0;
}

#else

SEC("kprobe")
__description("private stack is not supported, use a dummy test")
__success
int dummy_test(void)
{
        return 0;
}

#endif

char _license[] SEC("license") = "GPL";
