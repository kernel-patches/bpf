/* SPDX-License-Identifier: GPL-2.0 */
/*
 *  Copyright (C) 2014  Steven Rostedt, Red Hat Inc
 */

#include <linux/export.h>
#include <linux/cfi_types.h>
#include <linux/linkage.h>
#include <linux/kfunc_md.h>
#include <asm/asm-offsets.h>
#include <asm/ptrace.h>
#include <asm/ftrace.h>
#include <asm/nospec-branch.h>
#include <asm/unwind_hints.h>
#include <asm/frame.h>

	.code64
	.section .text, "ax"

#ifdef CONFIG_FRAME_POINTER
/* Save parent and function stack frames (rip and rbp) */
#  define MCOUNT_FRAME_SIZE	(8+16*2)
#else
/* No need to save a stack frame */
# define MCOUNT_FRAME_SIZE	0
#endif /* CONFIG_FRAME_POINTER */

/* Size of stack used to save mcount regs in save_mcount_regs */
#define MCOUNT_REG_SIZE		(FRAME_SIZE + MCOUNT_FRAME_SIZE)

/*
 * gcc -pg option adds a call to 'mcount' in most functions.
 * When -mfentry is used, the call is to 'fentry' and not 'mcount'
 * and is done before the function's stack frame is set up.
 * They both require a set of regs to be saved before calling
 * any C code and restored before returning back to the function.
 *
 * On boot up, all these calls are converted into nops. When tracing
 * is enabled, the call can jump to either ftrace_caller or
 * ftrace_regs_caller. Callbacks (tracing functions) that require
 * ftrace_regs_caller (like kprobes) need to have pt_regs passed to
 * it. For this reason, the size of the pt_regs structure will be
 * allocated on the stack and the required mcount registers will
 * be saved in the locations that pt_regs has them in.
 */

/*
 * @added: the amount of stack added before calling this
 *
 * After this is called, the following registers contain:
 *
 *  %rdi - holds the address that called the trampoline
 *  %rsi - holds the parent function (traced function's return address)
 *  %rdx - holds the original %rbp
 */
.macro save_mcount_regs added=0

#ifdef CONFIG_FRAME_POINTER
	/* Save the original rbp */
	pushq %rbp

	/*
	 * Stack traces will stop at the ftrace trampoline if the frame pointer
	 * is not set up properly. If fentry is used, we need to save a frame
	 * pointer for the parent as well as the function traced, because the
	 * fentry is called before the stack frame is set up, where as mcount
	 * is called afterward.
	 */

	/* Save the parent pointer (skip orig rbp and our return address) */
	pushq \added+8*2(%rsp)
	pushq %rbp
	movq %rsp, %rbp
	/* Save the return address (now skip orig rbp, rbp and parent) */
	pushq \added+8*3(%rsp)
	pushq %rbp
	movq %rsp, %rbp
#endif /* CONFIG_FRAME_POINTER */

	/*
	 * We add enough stack to save all regs.
	 */
	subq $(FRAME_SIZE), %rsp
	movq %rax, RAX(%rsp)
	movq %rcx, RCX(%rsp)
	movq %rdx, RDX(%rsp)
	movq %rsi, RSI(%rsp)
	movq %rdi, RDI(%rsp)
	movq %r8, R8(%rsp)
	movq %r9, R9(%rsp)
	movq $0, ORIG_RAX(%rsp)
	/*
	 * Save the original RBP. Even though the mcount ABI does not
	 * require this, it helps out callers.
	 */
#ifdef CONFIG_FRAME_POINTER
	movq MCOUNT_REG_SIZE-8(%rsp), %rdx
#else
	movq %rbp, %rdx
#endif
	movq %rdx, RBP(%rsp)

	/* Copy the parent address into %rsi (second parameter) */
	movq MCOUNT_REG_SIZE+8+\added(%rsp), %rsi

	 /* Move RIP to its proper location */
	movq MCOUNT_REG_SIZE+\added(%rsp), %rdi
	movq %rdi, RIP(%rsp)

	/*
	 * Now %rdi (the first parameter) has the return address of
	 * where ftrace_call returns. But the callbacks expect the
	 * address of the call itself.
	 */
	subq $MCOUNT_INSN_SIZE, %rdi
	.endm

.macro restore_mcount_regs save=0

	/* ftrace_regs_caller or frame pointers require this */
	movq RBP(%rsp), %rbp

	movq R9(%rsp), %r9
	movq R8(%rsp), %r8
	movq RDI(%rsp), %rdi
	movq RSI(%rsp), %rsi
	movq RDX(%rsp), %rdx
	movq RCX(%rsp), %rcx
	movq RAX(%rsp), %rax

	addq $MCOUNT_REG_SIZE-\save, %rsp

	.endm

SYM_TYPED_FUNC_START(ftrace_stub)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub)

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_TYPED_FUNC_START(ftrace_stub_graph)
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub_graph)
#endif

#ifdef CONFIG_DYNAMIC_FTRACE

SYM_FUNC_START(__fentry__)
	ANNOTATE_NOENDBR
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(__fentry__)
EXPORT_SYMBOL(__fentry__)

SYM_FUNC_START(ftrace_caller)
	ANNOTATE_NOENDBR
	/* save_mcount_regs fills in first two parameters */
	save_mcount_regs

	CALL_DEPTH_ACCOUNT

	/* Stack - skipping return address of ftrace_caller */
	leaq MCOUNT_REG_SIZE+8(%rsp), %rcx
	movq %rcx, RSP(%rsp)

SYM_INNER_LABEL(ftrace_caller_op_ptr, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* Load the ftrace_ops into the 3rd parameter */
	movq function_trace_op(%rip), %rdx

	/* regs go into 4th parameter */
	leaq (%rsp), %rcx

	/* Only ops with REGS flag set should have CS register set */
	movq $0, CS(%rsp)

	/* Account for the function call below */
	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_call, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	call ftrace_stub

	/* Handlers can change the RIP */
	movq RIP(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	restore_mcount_regs

	/*
	 * The code up to this label is copied into trampolines so
	 * think twice before adding any new code or changing the
	 * layout here.
	 */
SYM_INNER_LABEL(ftrace_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET
SYM_FUNC_END(ftrace_caller);
STACK_FRAME_NON_STANDARD_FP(ftrace_caller)

SYM_FUNC_START(ftrace_regs_caller)
	ANNOTATE_NOENDBR
	/* Save the current flags before any operations that can change them */
	pushfq

	/* added 8 bytes to save flags */
	save_mcount_regs 8
	/* save_mcount_regs fills in first two parameters */

	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_regs_caller_op_ptr, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	/* Load the ftrace_ops into the 3rd parameter */
	movq function_trace_op(%rip), %rdx

	/* Save the rest of pt_regs */
	movq %r15, R15(%rsp)
	movq %r14, R14(%rsp)
	movq %r13, R13(%rsp)
	movq %r12, R12(%rsp)
	movq %r11, R11(%rsp)
	movq %r10, R10(%rsp)
	movq %rbx, RBX(%rsp)
	/* Copy saved flags */
	movq MCOUNT_REG_SIZE(%rsp), %rcx
	movq %rcx, EFLAGS(%rsp)
	/* Kernel segments */
	movq $__KERNEL_DS, %rcx
	movq %rcx, SS(%rsp)
	movq $__KERNEL_CS, %rcx
	movq %rcx, CS(%rsp)
	/* Stack - skipping return address and flags */
	leaq MCOUNT_REG_SIZE+8*2(%rsp), %rcx
	movq %rcx, RSP(%rsp)

	ENCODE_FRAME_POINTER

	/* regs go into 4th parameter */
	leaq (%rsp), %rcx

	/* Account for the function call below */
	CALL_DEPTH_ACCOUNT

SYM_INNER_LABEL(ftrace_regs_call, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	call ftrace_stub

	/* Copy flags back to SS, to restore them */
	movq EFLAGS(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	/* Handlers can change the RIP */
	movq RIP(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE+8(%rsp)

	/* restore the rest of pt_regs */
	movq R15(%rsp), %r15
	movq R14(%rsp), %r14
	movq R13(%rsp), %r13
	movq R12(%rsp), %r12
	movq R10(%rsp), %r10
	movq RBX(%rsp), %rbx

	movq ORIG_RAX(%rsp), %rax
	movq %rax, MCOUNT_REG_SIZE-8(%rsp)

	/*
	 * If ORIG_RAX is anything but zero, make this a call to that.
	 * See arch_ftrace_set_direct_caller().
	 */
	testq	%rax, %rax
SYM_INNER_LABEL(ftrace_regs_caller_jmp, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	jnz	1f

	restore_mcount_regs
	/* Restore flags */
	popfq

	/*
	 * The trampoline will add the return.
	 */
SYM_INNER_LABEL(ftrace_regs_caller_end, SYM_L_GLOBAL)
	ANNOTATE_NOENDBR
	RET

	/* Swap the flags with orig_rax */
1:	movq MCOUNT_REG_SIZE(%rsp), %rdi
	movq %rdi, MCOUNT_REG_SIZE-8(%rsp)
	movq %rax, MCOUNT_REG_SIZE(%rsp)

	restore_mcount_regs 8
	/* Restore flags */
	popfq
	UNWIND_HINT_FUNC

	/*
	 * The above left an extra return value on the stack; effectively
	 * doing a tail-call without using a register. This PUSH;RET
	 * pattern unbalances the RSB, inject a pointless CALL to rebalance.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	CALL .Ldo_rebalance
	int3
.Ldo_rebalance:
	add $8, %rsp
	ALTERNATIVE __stringify(RET), \
		    __stringify(ANNOTATE_UNRET_SAFE; ret; int3), \
		    X86_FEATURE_CALL_DEPTH

SYM_FUNC_END(ftrace_regs_caller)
STACK_FRAME_NON_STANDARD_FP(ftrace_regs_caller)

SYM_FUNC_START(ftrace_stub_direct_tramp)
	ANNOTATE_NOENDBR
	CALL_DEPTH_ACCOUNT
	RET
SYM_FUNC_END(ftrace_stub_direct_tramp)

#else /* ! CONFIG_DYNAMIC_FTRACE */

SYM_FUNC_START(__fentry__)
	ANNOTATE_NOENDBR
	CALL_DEPTH_ACCOUNT

	cmpq $ftrace_stub, ftrace_trace_function
	jnz trace
	RET

trace:
	/* save_mcount_regs fills in first two parameters */
	save_mcount_regs

	/*
	 * When DYNAMIC_FTRACE is not defined, ARCH_SUPPORTS_FTRACE_OPS is not
	 * set (see include/asm/ftrace.h and include/linux/ftrace.h).  Only the
	 * ip and parent ip are used and the list function is called when
	 * function tracing is enabled.
	 */
	movq ftrace_trace_function, %r8
	CALL_NOSPEC r8
	restore_mcount_regs

	jmp ftrace_stub
SYM_FUNC_END(__fentry__)
EXPORT_SYMBOL(__fentry__)
STACK_FRAME_NON_STANDARD_FP(__fentry__)

#endif /* CONFIG_DYNAMIC_FTRACE */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
SYM_CODE_START(return_to_handler)
	UNWIND_HINT_UNDEFINED
	ANNOTATE_NOENDBR

	/* Save ftrace_regs for function exit context  */
	subq $(FRAME_SIZE), %rsp

	movq %rax, RAX(%rsp)
	movq %rdx, RDX(%rsp)
	movq %rbp, RBP(%rsp)
	movq %rsp, %rdi

	call ftrace_return_to_handler

	movq %rax, %rdi
	movq RDX(%rsp), %rdx
	movq RAX(%rsp), %rax

	addq $(FRAME_SIZE), %rsp
	/*
	 * Jump back to the old return address. This cannot be JMP_NOSPEC rdi
	 * since IBT would demand that contain ENDBR, which simply isn't so for
	 * return addresses. Use a retpoline here to keep the RSB balanced.
	 */
	ANNOTATE_INTRA_FUNCTION_CALL
	call .Ldo_rop
	int3
.Ldo_rop:
	mov %rdi, (%rsp)
	ALTERNATIVE __stringify(RET), \
		    __stringify(ANNOTATE_UNRET_SAFE; ret; int3), \
		    X86_FEATURE_CALL_DEPTH
SYM_CODE_END(return_to_handler)
#endif

/*
 * the stack layout for bpf_global_caller:
 *
 *	callee rip
 *	rbp
 *	---------------------- rbp
 *	return value	- for origin call
 *	arg6
 *	......
 *	arg1
 *	arg count
 *	origin ip	- for bpf_get_func_ip()
 *	rbx		- keep pointer to kfunc_md_tramp_prog
 *	bpf_tramp_run_ctx
 *	kfunc_md_ptr
 *	kfunc_md_flags
 *	r12		- keep the start time
 *	r13		- keep the return value address, for origin call
 *
 * Note: the return value can be in the position of arg6, arg5, etc,
 *       depending on the number of args. That's why we need the %r13
 */

#define FUNC_RETURN_OFFSET	(-8)

#define FUNC_ARGS_SIZE		(6 * 8)
#define FUNC_ARGS_OFFSET	(FUNC_RETURN_OFFSET - FUNC_ARGS_SIZE)
#define FUNC_ARGS_1		(FUNC_ARGS_OFFSET + 0 * 8)
#define FUNC_ARGS_2		(FUNC_ARGS_OFFSET + 1 * 8)
#define FUNC_ARGS_3		(FUNC_ARGS_OFFSET + 2 * 8)
#define FUNC_ARGS_4		(FUNC_ARGS_OFFSET + 3 * 8)
#define FUNC_ARGS_5		(FUNC_ARGS_OFFSET + 4 * 8)
#define FUNC_ARGS_6		(FUNC_ARGS_OFFSET + 5 * 8)

/* the args count, rbp - 8 * 8 */
#define FUNC_ARGS_COUNT_OFFSET	(FUNC_ARGS_OFFSET - 1 * 8)
#define FUNC_ORIGIN_IP		(FUNC_ARGS_OFFSET - 2 * 8) /* -9 * 8 */
#define RBX_OFFSET		(FUNC_ARGS_OFFSET - 3 * 8)

/* bpf_tramp_run_ctx, rbp - RUN_CTX_OFFSET */
#define RUN_CTX_OFFSET		(RBX_OFFSET - RUN_CTX_SIZE)
#define KFUNC_MD_OFFSET		(RUN_CTX_OFFSET - 1 * 8)
#define KFUNC_MD_FLAGS_OFFSET	(KFUNC_MD_OFFSET - 8)
#define R12_OFFSET		(KFUNC_MD_OFFSET - 16)
#define R13_OFFSET		(KFUNC_MD_OFFSET - 24)
#define STACK_SIZE		(-1 * R13_OFFSET)

/* restore the regs before we return or before we do the origin call */
.macro tramp_restore_regs
	movq FUNC_ARGS_1(%rbp), %rdi
	movq FUNC_ARGS_2(%rbp), %rsi
	movq FUNC_ARGS_3(%rbp), %rdx
	movq FUNC_ARGS_4(%rbp), %rcx
	movq FUNC_ARGS_5(%rbp), %r8
	movq FUNC_ARGS_6(%rbp), %r9
	.endm

/* save the args to stack, only regs is supported for now */
.macro tramp_save_regs
	movq %rdi, FUNC_ARGS_1(%rbp)
	movq %rsi, FUNC_ARGS_2(%rbp)
	movq %rdx, FUNC_ARGS_3(%rbp)
	movq %rcx, FUNC_ARGS_4(%rbp)
	movq %r8, FUNC_ARGS_5(%rbp)
	movq %r9, FUNC_ARGS_6(%rbp)
	.endm

#define BPF_TRAMP_FENTRY	0
#define BPF_TRAMP_FEXIT		1
#define BPF_TRAMP_MODIFY_RETURN	2

.macro bpf_caller_prog_run type
	/* check if the prog list is NULL */
1:	testq %rbx, %rbx
	jz 3f

	/* load bpf prog to the 1st arg */
	movq KFUNC_MD_PROG_prog(%rbx), %rdi

	/* load the pointer of tramp_run_ctx to the 2nd arg */
	leaq RUN_CTX_OFFSET(%rbp), %rsi
	/* save the bpf cookie to the tramp_run_ctx */
	movq KFUNC_MD_PROG_cookie(%rbx), %rax
	movq %rax, RUN_CTX_cookie(%rsi)
	call __bpf_prog_enter_recur
	/* save the start time to r12 */
	movq %rax, %r12
	testq %rax, %rax
	jz 2f

	movq KFUNC_MD_PROG_prog(%rbx), %rdi
	/* load the JITed prog to rax */
	movq BPF_PROG_func(%rdi), %rax
	/* load func args array to the 1st arg */
	leaq FUNC_ARGS_OFFSET(%rbp), %rdi

	/* load and call the JITed bpf func */
	CALL_NOSPEC rax
.if \type==BPF_TRAMP_MODIFY_RETURN
	/* modify_return case, save the return value */
	movq %rax, (%r13)
.endif

	/* load bpf prog to the 1st arg */
2:	movq KFUNC_MD_PROG_prog(%rbx), %rdi
	/* load the rbx(start time) to the 2nd arg */
	movq %r12, %rsi
	/* load the pointer of tramp_run_ctx to the 3rd arg */
	leaq RUN_CTX_OFFSET(%rbp), %rdx
	call __bpf_prog_exit_recur

.if \type==BPF_TRAMP_MODIFY_RETURN
	/* modify_return case, break the loop and skip the origin function call */
	cmpq $0, (%r13)
	jne do_bpf_fexit
.endif
	/* load the next tramp prog to rbx */
	movq 0(%rbx), %rbx
	jmp 1b

3:
	.endm

SYM_FUNC_START(bpf_global_caller)
	ANNOTATE_NOENDBR

	/* prepare the stack space and store the args to the stack */
	pushq %rbp
	movq %rsp, %rbp
	subq $STACK_SIZE, %rsp
	tramp_save_regs

	CALL_DEPTH_ACCOUNT

	/* save rbx and r12, which will be used later */
	movq %rbx, RBX_OFFSET(%rbp)
	movq %r12, R12_OFFSET(%rbp)

	/* get the function address */
	movq 8(%rbp), %rdi
	/* for x86_64, the function is 16-bytes aligned */
	andq $0xfffffffffffffff0, %rdi
	/* save the origin function ip */
	movq %rdi, FUNC_ORIGIN_IP(%rbp)

	/* get the function meta data */
	call kfunc_md_get_noref
	testq %rax, %rax
	jz do_bpf_out
	movq %rax, %rbx
	movq %rbx, KFUNC_MD_OFFSET(%rbp)

	/* save the function args count */
	movzbq KFUNC_MD_nr_args(%rbx), %rax
	movq %rax, FUNC_ARGS_COUNT_OFFSET(%rbp)

	/* call kfunc_md_enter only if we need origin call */
	movl KFUNC_MD_flags(%rbx), %edi
	movl %edi, KFUNC_MD_FLAGS_OFFSET(%rbp)
	andl $KFUNC_MD_FL_TRACING_ORIGIN, %edi
	jz 1f

	/* save the address of the return value to r13 */
	movq %r13, R13_OFFSET(%rbp)
	leaq FUNC_ARGS_OFFSET(%rbp, %rax, 8), %r13

	movq %rbx, %rdi
	call kfunc_md_enter

	/* try run fentry progs */
1:	movq (KFUNC_MD_progs + BPF_TRAMP_FENTRY * 8)(%rbx), %rbx
	bpf_caller_prog_run BPF_TRAMP_FENTRY

	/* check if we need to do the origin call */
	movl KFUNC_MD_FLAGS_OFFSET(%rbp), %eax
	andl $KFUNC_MD_FL_TRACING_ORIGIN, %eax
	jz do_bpf_out

	/* try run modify_return progs */
	movq KFUNC_MD_OFFSET(%rbp), %r12
	movq (KFUNC_MD_progs + BPF_TRAMP_MODIFY_RETURN * 8)(%r12), %rbx
	movq $0, (%r13)
	bpf_caller_prog_run BPF_TRAMP_MODIFY_RETURN

	/* do the origin call */
	tramp_restore_regs
	/* call the origin function from the stack, just like BPF_TRAMP_F_ORIG_STACK */
	movq 8(%rbp), %rax
	CALL_NOSPEC rax
	movq %rax, (%r13)

do_bpf_fexit:
	/* for origin case, run fexit and return */
	movq KFUNC_MD_OFFSET(%rbp), %r12
	movq (KFUNC_MD_progs + BPF_TRAMP_FEXIT * 8)(%r12), %rbx
	bpf_caller_prog_run BPF_TRAMP_FEXIT
	movq KFUNC_MD_OFFSET(%rbp), %rdi
	call kfunc_md_exit

	movq (%r13), %rax
	movq RBX_OFFSET(%rbp), %rbx
	movq R12_OFFSET(%rbp), %r12
	movq R13_OFFSET(%rbp), %r13
	leave

	/* rebalance the RSB. We can simply use:
	 *
	 *   leaq 8(%rsp), %rsp
	 *   RET
	 *
	 * instead here if we don't want do the rebalance.
	 */
	movq $bpf_global_caller_rsb, (%rsp)
	RET
SYM_INNER_LABEL(bpf_global_caller_rsb, SYM_L_LOCAL)
	ANNOTATE_NOENDBR
	RET

do_bpf_out:
	/* for no origin call case, restore regs and return */
	tramp_restore_regs

	movq RBX_OFFSET(%rbp), %rbx
	movq R12_OFFSET(%rbp), %r12
	leave
	RET

SYM_FUNC_END(bpf_global_caller)
STACK_FRAME_NON_STANDARD(bpf_global_caller)
