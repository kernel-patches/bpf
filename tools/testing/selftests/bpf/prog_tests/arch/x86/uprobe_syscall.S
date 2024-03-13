/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ASM_NL
#define ASM_NL	 ;
#endif

#define SYM_ENTRY(name)			\
	.globl name ASM_NL		\
	name:

#define SYM_END(name)			\
	.type name STT_FUNC ASM_NL	\
	.size name, .-name ASM_NL

.code64
.section .text, "ax"

SYM_ENTRY(uprobe_syscall_arch_test)
	movq $0xdeadbeef, %rax
	ret
SYM_END(uprobe_syscall_arch_test)

.globl uprobe_syscall_arch
uprobe_syscall_arch:
	movq %r15,   0(%rdi)
	movq %r14,   8(%rdi)
	movq %r13,  16(%rdi)
	movq %r12,  24(%rdi)
	movq %rbp,  32(%rdi)
	movq %rbx,  40(%rdi)
	movq %r11,  48(%rdi)
	movq %r10,  56(%rdi)
	movq  %r9,  64(%rdi)
	movq  %r8,  72(%rdi)
	movq %rax,  80(%rdi)
	movq %rcx,  88(%rdi)
	movq %rdx,  96(%rdi)
	movq %rsi, 104(%rdi)
	movq %rdi, 112(%rdi)
	movq   $0, 120(%rdi) /* orig_rax */
	movq   $0, 128(%rdi) /* rip      */
	movq   $0, 136(%rdi) /* cs       */

	pushf
	pop %rax

	movq %rax, 144(%rdi) /* eflags   */
	movq %rsp, 152(%rdi) /* rsp      */
	movq   $0, 160(%rdi) /* ss       */

	pushq %rsi
	call uprobe_syscall_arch_test

	/* store return value and get second argument pointer  to rax */
	pushq %rax
	movq 8(%rsp), %rax

	movq %r15,   0(%rax)
	movq %r14,   8(%rax)
	movq %r13,  16(%rax)
	movq %r12,  24(%rax)
	movq %rbp,  32(%rax)
	movq %rbx,  40(%rax)
	movq %r11,  48(%rax)
	movq %r10,  56(%rax)
	movq  %r9,  64(%rax)
	movq  %r8,  72(%rax)
	movq %rcx,  88(%rax)
	movq %rdx,  96(%rax)
	movq %rsi, 104(%rax)
	movq %rdi, 112(%rax)
	movq   $0, 120(%rax) /* orig_rax */
	movq   $0, 128(%rax) /* rip      */
	movq   $0, 136(%rax) /* cs       */

	pop %rax
	pop %rsi
	movq %rax,  80(%rsi)

	pushf
	pop %rax

	movq %rax, 144(%rsi) /* eflags   */
	movq %rsp, 152(%rsi) /* rsp      */
	movq   $0, 160(%rsi) /* ss       */

	ret

.section .note.GNU-stack,"",@progbits
