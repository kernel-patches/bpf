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
/* program entry for main(), regular function prologue */
__jit_x86("	endbr64")
__jit_x86("	nopl	(%rax,%rax)")
__jit_x86("	xorq	%rax, %rax")
__jit_x86("	pushq	%rbp")
__jit_x86("	movq	%rsp, %rbp")
/* tail call prologue for program:
 * - establish memory location for tail call counter at &rbp[-8];
 * - spill tail_call_cnt_ptr at &rbp[-16];
 * - expect tail call counter to be passed in rax;
 * - for entry program rax is a raw counter, value < 33;
 * - for tail called program rax is tail_call_cnt_ptr (value > 33).
 */
__jit_x86("	endbr64")
__jit_x86("	cmpq	$0x21, %rax")
__jit_x86("	ja	L0")
__jit_x86("	pushq	%rax")
__jit_x86("	movq	%rsp, %rax")
__jit_x86("	jmp	L1")
__jit_x86("L0:	pushq	%rax")			/* rbp[-8]  = rax         */
__jit_x86("L1:	pushq	%rax")			/* rbp[-16] = rax         */
/* on subprogram call restore rax to be tail_call_cnt_ptr from rbp[-16]
 * (cause original rax might be clobbered by this point)
 */
__jit_x86("	movq	-0x10(%rbp), %rax")
__jit_x86("	callq	0x[0-9a-f]\\+")		/* call to sub()          */
__jit_x86("	xorl	%eax, %eax")
__jit_x86("	leave")
__jit_x86("	retq")
/* subprogram entry for sub(), regular function prologue */
__jit_x86("	endbr64")
__jit_x86("	nopl	(%rax,%rax)")
__jit_x86("	nopl	(%rax)")
__jit_x86("	pushq	%rbp")
__jit_x86("	movq	%rsp, %rbp")
/* tail call prologue for subprogram address of tail call counter
 * stored at rbp[-16].
 */
__jit_x86("	endbr64")
__jit_x86("	pushq	%rax")			/* rbp[-8]  = rax          */
__jit_x86("	pushq	%rax")			/* rbp[-16] = rax          */
__jit_x86("	movabsq	$-0x[0-9a-f]\\+, %rsi")	/* r2 = &jmp_table         */
__jit_x86("	xorl	%edx, %edx")		/* r3 = 0                  */
/* bpf_tail_call implementation:
 * - load tail_call_cnt_ptr from rbp[-16];
 * - if *tail_call_cnt_ptr < 33, increment it and jump to target;
 * - otherwise do nothing.
 */
__jit_x86("	movq	-0x10(%rbp), %rax")
__jit_x86("	cmpq	$0x21, (%rax)")
__jit_x86("	jae	L0")
__jit_x86("	nopl	(%rax,%rax)")
__jit_x86("	addq	$0x1, (%rax)")		/* *tail_call_cnt_ptr += 1 */
__jit_x86("	popq	%rax")
__jit_x86("	popq	%rax")
__jit_x86("	jmp	0x[0-9a-f]\\+")		/* jump to tail call tgt   */
__jit_x86("L0:	leave")
__jit_x86("	retq")
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
