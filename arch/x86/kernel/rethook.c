// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * x86 implementation of rethook. Mostly copied from arch/x86/kernel/kprobes/core.c.
 */
#include <linux/bug.h>
#include <linux/rethook.h>
#include <linux/kprobes.h>
#include <linux/objtool.h>

#include "kprobes/common.h"

__visible void arch_rethook_trampoline_callback(struct pt_regs *regs);

#ifndef ANNOTATE_NOENDBR
#define ANNOTATE_NOENDBR
#endif

#if defined(CONFIG_X86_64) && defined(CONFIG_UNWINDER_DWARF_CFI)
#define RETHOOK_CFI_STARTPROC		"	.cfi_startproc\n"
#define RETHOOK_CFI_ENDPROC		"	.cfi_endproc\n"
#define RETHOOK_CFI_ADJUST(off)		"	.cfi_adjust_cfa_offset " #off "\n"
#define RETHOOK_SAVE_REGS_STRING	\
	"	subq $24, %rsp\n"	\
	RETHOOK_CFI_ADJUST(24)		\
	"	pushq %rdi\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %rsi\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %rdx\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %rcx\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %rax\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r8\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r9\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r10\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r11\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %rbx\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %rbp\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	.cfi_offset rbp, -144\n"\
	"	pushq %r12\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r13\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r14\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	"	pushq %r15\n"		\
	RETHOOK_CFI_ADJUST(8)		\
	ENCODE_FRAME_POINTER
#define RETHOOK_RESTORE_REGS_STRING	\
	"	popq %r15\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r14\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r13\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r12\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %rbp\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	.cfi_restore rbp\n"	\
	"	popq %rbx\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r11\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r10\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r9\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %r8\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %rax\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %rcx\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %rdx\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %rsi\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	popq %rdi\n"		\
	RETHOOK_CFI_ADJUST(-8)		\
	"	addq $24, %rsp\n"	\
	RETHOOK_CFI_ADJUST(-24)
#else
#define RETHOOK_CFI_STARTPROC
#define RETHOOK_CFI_ENDPROC
#define RETHOOK_CFI_ADJUST(off)
#define RETHOOK_SAVE_REGS_STRING	SAVE_REGS_STRING
#define RETHOOK_RESTORE_REGS_STRING	RESTORE_REGS_STRING
#endif

/*
 * When a target function returns, this code saves registers and calls
 * arch_rethook_trampoline_callback(), which calls the rethook handler.
 */
asm(
	".text\n"
	".global arch_rethook_trampoline\n"
	".type arch_rethook_trampoline, @function\n"
	"arch_rethook_trampoline:\n"
#ifdef CONFIG_X86_64
	ANNOTATE_NOENDBR "\n"	/* This is only jumped from ret instruction */
	/* Push a fake return address to tell the unwinder it's a rethook. */
	"	pushq $arch_rethook_trampoline\n"
	UNWIND_HINT_FUNC
	RETHOOK_CFI_STARTPROC
	"       pushq $" __stringify(__KERNEL_DS) "\n"
	RETHOOK_CFI_ADJUST(8)
	/* Save the 'sp - 16', this will be fixed later. */
	"	pushq %rsp\n"
	RETHOOK_CFI_ADJUST(8)
	"	pushfq\n"
	RETHOOK_CFI_ADJUST(8)
	RETHOOK_SAVE_REGS_STRING
	"	movq %rsp, %rdi\n"
	"	call arch_rethook_trampoline_callback\n"
	RETHOOK_RESTORE_REGS_STRING
	/* In the callback function, 'regs->flags' is copied to 'regs->ss'. */
	"	addq $16, %rsp\n"
	RETHOOK_CFI_ADJUST(-16)
	"	popfq\n"
	RETHOOK_CFI_ADJUST(-8)
#else
	/* Push a fake return address to tell the unwinder it's a rethook. */
	"	pushl $arch_rethook_trampoline\n"
	UNWIND_HINT_FUNC
	"	pushl %ss\n"
	/* Save the 'sp - 8', this will be fixed later. */
	"	pushl %esp\n"
	"	pushfl\n"
	SAVE_REGS_STRING
	"	movl %esp, %eax\n"
	"	call arch_rethook_trampoline_callback\n"
	RESTORE_REGS_STRING
	/* In the callback function, 'regs->flags' is copied to 'regs->ss'. */
	"	addl $8, %esp\n"
	"	popfl\n"
#endif
	ASM_RET
	RETHOOK_CFI_ENDPROC
	".size arch_rethook_trampoline, .-arch_rethook_trampoline\n"
);
NOKPROBE_SYMBOL(arch_rethook_trampoline);

/*
 * Called from arch_rethook_trampoline
 */
__used __visible void arch_rethook_trampoline_callback(struct pt_regs *regs)
{
	unsigned long *frame_pointer;

	/* fixup registers */
	regs->cs = __KERNEL_CS;
#ifdef CONFIG_X86_32
	regs->gs = 0;
#endif
	regs->ip = (unsigned long)&arch_rethook_trampoline;
	regs->orig_ax = ~0UL;
	regs->sp += 2*sizeof(long);
	frame_pointer = (long *)(regs + 1);

	/*
	 * The return address at 'frame_pointer' is recovered by the
	 * arch_rethook_fixup_return() which called from this
	 * rethook_trampoline_handler().
	 */
	rethook_trampoline_handler(regs, (unsigned long)frame_pointer);

	/*
	 * Copy FLAGS to 'pt_regs::ss' so that arch_rethook_trapmoline()
	 * can do RET right after POPF.
	 */
	*(unsigned long *)&regs->ss = regs->flags;
}
NOKPROBE_SYMBOL(arch_rethook_trampoline_callback);

/*
 * arch_rethook_trampoline() skips updating frame pointer. The frame pointer
 * saved in arch_rethook_trampoline_callback() points to the real caller
 * function's frame pointer. Thus the arch_rethook_trampoline() doesn't have
 * a standard stack frame with CONFIG_FRAME_POINTER=y.
 * Let's mark it non-standard function. Anyway, FP unwinder can correctly
 * unwind without the hint.
 */
STACK_FRAME_NON_STANDARD_FP(arch_rethook_trampoline);

/* This is called from rethook_trampoline_handler(). */
void arch_rethook_fixup_return(struct pt_regs *regs,
			       unsigned long correct_ret_addr)
{
	unsigned long *frame_pointer = (void *)(regs + 1);

	/* Replace fake return address with real one. */
	*frame_pointer = correct_ret_addr;
}
NOKPROBE_SYMBOL(arch_rethook_fixup_return);

void arch_rethook_prepare(struct rethook_node *rh, struct pt_regs *regs, bool mcount)
{
	unsigned long *stack = (unsigned long *)regs->sp;

	rh->ret_addr = stack[0];
	rh->frame = regs->sp;

	/* Replace the return addr with trampoline addr */
	stack[0] = (unsigned long) arch_rethook_trampoline;
}
NOKPROBE_SYMBOL(arch_rethook_prepare);
