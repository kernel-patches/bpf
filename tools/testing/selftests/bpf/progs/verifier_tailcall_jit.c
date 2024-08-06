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
/* program entry for main()                                                        */
__jited_x86(" 0:	endbr64")			/* function prologue       */
__jited_x86(" 4:	nopl	(%rax,%rax)")		/*                         */
__jited_x86(" 9:	xorq	%rax, %rax")		/*                         */
__jited_x86(" c:	pushq	%rbp")			/*                         */
__jited_x86(" d:	movq	%rsp, %rbp")		/*                         */
/* tail call prologue for program: tail call counter would be stored at &rbp[-8]   */
__jited_x86("10:	endbr64")			/*                         */
__jited_x86("14:	cmpq	$0x21, %rax")		/*                         */
/* tail call counter is passed in rax:                                             */
/* - for entry program it is a raw counter, value < 33                             */
/* - for tail called program it is an address of a counter on stack (value > 33)   */
__jited_x86("18:	ja	0x20")			/* if rax < 33 goto -.     */
__jited_x86("1a:	pushq	%rax")			/* rbp[-8] = rax     |     */
__jited_x86("1b:	movq	%rsp, %rax")		/* rax = &rbp[-8]    |     */
__jited_x86("1e:	jmp	0x21")			/* ------------------|-.   */
__jited_x86("20:	pushq	%rax")			/* rbp[-8 ] = rax <--' |   */
/* ensure that rbp[-16] contains an address of the tail call counter           |   */
__jited_x86("21:	pushq	%rax")			/* rbp[-16] = rax <----'   */
/* on subprogram call restore rax to be tail_call_cnt_ptr from rbp[-16]            */
/* (cause original rax might be clobbered by this point)                           */
__jited_x86("22:	movq	-0x10(%rbp), %rax")	/* rax = rbp[-16]          */
__jited_x86("29:	callq	0x[0-9a-f]\\+")		/* call sub()              */
__jited_x86("2e:	xorl	%eax, %eax")		/* r0 = 0                  */
__jited_x86("30:	leave")				/* exit                    */
__jited_x86("31:	jmp	0x[0-9a-f]\\+")		/*                         */
/* subprogram entry for sub()                                                      */
__jited_x86("36:	endbr64")			/* function prologue       */
__jited_x86("3a:	nopl	(%rax,%rax)")		/*                         */
__jited_x86("3f:	nopl	(%rax)")		/*                         */
__jited_x86("42:	pushq	%rbp")			/*                         */
__jited_x86("43:	movq	%rsp, %rbp")		/*                         */
/* tail call prologue for subprogram:                                              */
/* address of tail call counter would be stored at rbp[-16] (rbp value for 'sub')  */
__jited_x86("46:	endbr64")			/*                         */
__jited_x86("4a:	pushq	%rax")			/* rbp[-8]  = rax          */
__jited_x86("4b:	pushq	%rax")			/* rbp[-16] = rax          */
__jited_x86("4c:	movabsq	$-0x[0-9a-f]\\+, %rsi")	/* r2 = &jmp_table         */
__jited_x86("56:	xorl	%edx, %edx")		/* r3 = 0                  */
/* bpf_tail_call implementation:                                                   */
/* - load tail call counter address;                                               */
/* - if counter value at the address < 33, increment it and jump to target;        */
/* - otherwise do nothing                                                          */
__jited_x86("58:	movq	-0x10(%rbp), %rax")	/* rax = tail_call_cnt_ptr */
__jited_x86("5f:	cmpq	$0x21, (%rax)")		/*                         */
__jited_x86("63:	jae	0x75")			/* if [rax] >= 33 goto --. */
__jited_x86("65:	nopl	(%rax,%rax)")		/*                       | */
__jited_x86("6a:	addq	$0x1, (%rax)")		/* [rax] += 1            | */
__jited_x86("6e:	popq	%rax")			/* restore rax at entry  | */
__jited_x86("6f:	popq	%rax")			/*                       | */
__jited_x86("70:	jmp	0x[0-9a-f]\\+")		/* tail call jump        | */
__jited_x86("75:	leave")				/* exit <----------------' */
__jited_x86("76:	jmp	0x[0-9a-f]\\+")		/*                         */
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
