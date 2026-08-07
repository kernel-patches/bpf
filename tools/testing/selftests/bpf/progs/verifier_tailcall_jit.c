// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

int main(void);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size, sizeof(__u32));
	__array(values, void (void));
} jmp_table SEC(".maps") = {
	.values = {
		[0] = (void *) &main,
	},
};

__noinline __auxiliary
static __naked int sub(void)
{
	asm volatile (
	"r2 = %[jmp_table] ll;"
	"r3 = 0;"
	"call 12;"
	"exit;"
	:
	: __imm_addr(jmp_table)
	: __clobber_all);
}

__success
__arch_x86_64
/* program entry for main(), regular function prologue */
__jited("	endbr64")
__jited("	nopl	(%rax,%rax)")
__jited("	xorq	%rax, %rax")
__jited("	pushq	%rbp")
__jited("	movq	%rsp, %rbp")
/* tail call prologue for program:
 * - establish memory location for tail call counter at &rbp[-8];
 * - spill tail_call_cnt_ptr at &rbp[-16];
 * - expect tail call counter to be passed in rax;
 * - for entry program rax is a raw counter, value < 33;
 * - for tail called program rax is tail_call_cnt_ptr (value > 33).
 */
__jited("	endbr64")
__jited("	cmpq	$0x21, %rax")
__jited("	ja	L0")
__jited("	pushq	%rax")
__jited("	movq	%rsp, %rax")
__jited("	jmp	L1")
__jited("L0:	pushq	%rax")			/* rbp[-8]  = rax         */
__jited("L1:	pushq	%rax")			/* rbp[-16] = rax         */
/* on subprogram call restore rax to be tail_call_cnt_ptr from rbp[-16]
 * (cause original rax might be clobbered by this point)
 */
__jited("	movq	-0x10(%rbp), %rax")
__jited("...")
__jited("	callq	0x{{.*}}")		/* call to sub()          */
__jited("	xorl	%eax, %eax")
__jited("	leave")
__jited("	{{(retq|jmp	0x)}}")		/* return or jump to rethunk */
__jited("...")
/* subprogram entry for sub(), regular function prologue */
__jited("	endbr64")
__jited("	nopl	(%rax,%rax)")
__jited("	nopl	(%rax)")
__jited("	pushq	%rbp")
__jited("	movq	%rsp, %rbp")
/* tail call prologue for subprogram address of tail call counter
 * stored at rbp[-16].
 */
__jited("	endbr64")
__jited("	pushq	%rax")			/* rbp[-8]  = rax          */
__jited("	pushq	%rax")			/* rbp[-16] = rax          */
__jited("	movabsq	${{.*}}, %rsi")		/* r2 = &jmp_table         */
__jited("	xorl	%edx, %edx")		/* r3 = 0                  */
/* bpf_tail_call implementation:
 * - load tail_call_cnt_ptr from rbp[-16];
 * - if *tail_call_cnt_ptr < 33, increment it and jump to target;
 * - otherwise do nothing.
 */
__jited("	movq	-0x10(%rbp), %rax")
__jited("	cmpq	$0x21, (%rax)")
__jited("	jae	L0")
__jited("	nopl	(%rax,%rax)")
__jited("	addq	$0x1, (%rax)")		/* *tail_call_cnt_ptr += 1 */
__jited("	popq	%rax")
__jited("	popq	%rax")
__jited("	jmp	{{.*}}")		/* jump to tail call tgt   */
__jited("L0:	leave")
__jited("	{{(retq|jmp	0x)}}")		/* return or jump to rethunk */
__arch_powerpc64
/* program entry for main(), regular function prologue */
__jited("	nop")
__jited("...")                          /* ld 2, 16(13) absent with CONFIG_PPC_KERNEL_PCREL */
__jited("	li 9, 0")
__jited("	std 9, -8(1)")
__jited("	mflr 0")
__jited("	std 0, 16(1)")
__jited("	stdu 1, {{.*}}(1)")
/* load address and call sub() via count register
 *
 * Address materialization differs between PCREL and non-PCREL kernels.
 * Skip the address generation sequence and verify only that the call
 * target is loaded into CTR before branching.
 */
__jited("...")
__jited("...")
__jited("...")
__jited("...")
__jited("...")
__jited("	mtctr 12")
__jited("	bctrl")
__jited("	mr	8, 3")
__jited("	li 8, 0")
__jited("	addi 1, 1, {{.*}}")
__jited("	ld 0, 16(1)")
__jited("	mtlr 0")
__jited("	mr	3, 8")
__jited("	blr")
__jited("...")
__jited("func #1")
/* subprogram entry for sub() */
__jited("	nop")
__jited("...")                          /* ld 2, 16(13) absent with CONFIG_PPC_KERNEL_PCREL */
/* tail call prologue for subprogram */
__jited("	ld 10, 0(1)")
__jited("	ld 9, -8(10)")
__jited("	cmpldi	9, 33")
__jited("	bt	{{.*}}, {{.*}}")
__jited("	addi 9, 10, -8")
__jited("	std 9, -8(1)")
__jited("	lis {{.*}}, {{.*}}")
__jited("	sldi {{.*}}, {{.*}}, 32")
__jited("	oris {{.*}}, {{.*}}, {{.*}}")
__jited("	ori {{.*}}, {{.*}}, {{.*}}")
__jited("	li {{.*}}, 0")
__jited("	lwz 9, {{.*}}({{.*}})")
__jited("	slwi {{.*}}, {{.*}}, 0")
__jited("	cmplw	{{.*}}, 9")
__jited("	bf	0, {{.*}}")
/* bpf_tail_call implementation */
__jited("	ld 9, -8(1)")
__jited("	cmpldi	9, 33")
__jited("	bf	{{.*}}, {{.*}}")
__jited("	ld 9, 0(9)")
__jited("	cmpldi	9, 33")
__jited("	bt	{{.*}}, {{.*}}")
__jited("	addi 9, 9, 1")
__jited("	mulli 10, {{.*}}, 8")
__jited("	add 10, 10, {{.*}}")
__jited("	ld 10, {{.*}}(10)")
__jited("	cmpldi	10, 0")
__jited("	bt	{{.*}}, {{.*}}")
__jited("	ld 10, {{.*}}(10)")
__jited("	addi 10, 10, {{.*}}")    /* offset depends on CONFIG_PPC_KERNEL_PCREL */
__jited("	mtctr 10")
__jited("	ld 10, -8(1)")
__jited("	cmpldi	10, 33")
__jited("	bt	{{.*}}, {{.*}}")
__jited("	addi 10, 1, -8")
__jited("	std 9, 0(10)")
__jited("	bctr")
__jited("	mr	3, 8")
__jited("	blr")

SEC("tc")
__naked int main(void)
{
	asm volatile (
	"call %[sub];"
	"r0 = 0;"
	"exit;"
	:
	: __imm(sub)
	: __clobber_all);
}

char __license[] SEC("license") = "GPL";
