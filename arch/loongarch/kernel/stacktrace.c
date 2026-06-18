// SPDX-License-Identifier: GPL-2.0
/*
 * Stack trace management functions
 *
 * Copyright (C) 2022 Loongson Technology Corporation Limited
 */
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/stacktrace.h>
#include <linux/uaccess.h>

#include <asm/stacktrace.h>
#include <asm/unwind.h>

void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
		     struct task_struct *task, struct pt_regs *regs)
{
	unsigned long addr;
	struct pt_regs dummyregs;
	struct unwind_state state;

	if (!regs) {
		regs = &dummyregs;

		if (task == current) {
			regs->regs[3] = (unsigned long)__builtin_frame_address(0);
			regs->csr_era = (unsigned long)__builtin_return_address(0);
		} else {
			regs->regs[3] = thread_saved_fp(task);
			regs->csr_era = thread_saved_ra(task);
		}
		regs->regs[1] = 0;
		regs->regs[22] = 0;
	}

	for (unwind_start(&state, task, regs);
	     !unwind_done(&state); unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		if (!addr || !consume_entry(cookie, addr))
			break;
	}
}

#ifdef CONFIG_UNWINDER_ORC
/*
 * Used by BPF exception support (bpf_throw) to find the exception boundary
 * frame. The ORC unwinder reports the stack and frame pointer of each frame
 * and, via its generated-code fallback, can walk JITed BPF frames, which set
 * up the expected frame record ($ra at fp-8, previous fp at fp-16).
 */
static noinline void walk_stackframe_bpf(bool (*consume_fn)(void *cookie, u64 ip, u64 sp, u64 bp),
					 void *cookie, unsigned long fp)
{
	unsigned long addr;
	struct pt_regs dummyregs;
	struct pt_regs *regs = &dummyregs;
	struct unwind_state state;

	regs->regs[3] = (unsigned long)__builtin_frame_address(0);
	regs->csr_era = (unsigned long)__builtin_return_address(0);
	regs->regs[1] = 0;
	regs->regs[22] = fp;

	for (unwind_start(&state, current, regs);
	     !unwind_done(&state); unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);
		if (!addr || !consume_fn(cookie, (u64)addr, (u64)state.sp, (u64)state.fp))
			break;
	}
}

void arch_bpf_stack_walk(bool (*consume_fn)(void *cookie, u64 ip, u64 sp, u64 bp),
			 void *cookie)
{
	unsigned long fp;

	/*
	 * Capture the live frame pointer ($r22/$fp) here, before handing off to
	 * the worker. The kernel is built with -fomit-frame-pointer, so $fp is
	 * an ordinary callee-saved register that is preserved across the call
	 * from the JITed BPF program into bpf_throw() down to here, and thus
	 * still points at the innermost BPF frame. The ORC frame-pointer
	 * fallback walks the BPF frames up to the exception boundary from it.
	 *
	 * This must be a thin wrapper with no large stack locals: the worker
	 * uses $r22 to address its frame, which would clobber the live $fp
	 * before it could be read. __builtin_frame_address() cannot be used
	 * either, as it is $sp-derived and would yield a kernel-stack frame.
	 */
	asm volatile("move %0, $r22" : "=r"(fp));
	walk_stackframe_bpf(consume_fn, cookie, fp);
}
#endif /* CONFIG_UNWINDER_ORC */

int arch_stack_walk_reliable(stack_trace_consume_fn consume_entry,
			     void *cookie, struct task_struct *task)
{
	unsigned long addr;
	struct pt_regs dummyregs;
	struct pt_regs *regs = &dummyregs;
	struct unwind_state state;

	if (task == current) {
		regs->regs[3] = (unsigned long)__builtin_frame_address(0);
		regs->csr_era = (unsigned long)__builtin_return_address(0);
		regs->regs[22] = 0;
	} else {
		regs->regs[3] = thread_saved_fp(task);
		regs->csr_era = thread_saved_ra(task);
		regs->regs[22] = task->thread.reg22;
	}
	regs->regs[1] = 0;

	for (unwind_start(&state, task, regs);
	     !unwind_done(&state) && !unwind_error(&state); unwind_next_frame(&state)) {
		addr = unwind_get_return_address(&state);

		/*
		 * A NULL or invalid return address probably means there's some
		 * generated code which __kernel_text_address() doesn't know about.
		 */
		if (!addr)
			return -EINVAL;

		if (!consume_entry(cookie, addr))
			return -EINVAL;
	}

	/* Check for stack corruption */
	if (unwind_error(&state))
		return -EINVAL;

	return 0;
}

static int
copy_stack_frame(unsigned long fp, struct stack_frame *frame)
{
	int ret = 1;
	unsigned long err;
	unsigned long __user *user_frame_tail;

	user_frame_tail = (unsigned long *)(fp - sizeof(struct stack_frame));
	if (!access_ok(user_frame_tail, sizeof(*frame)))
		return 0;

	pagefault_disable();
	err = (__copy_from_user_inatomic(frame, user_frame_tail, sizeof(*frame)));
	if (err || (unsigned long)user_frame_tail >= frame->fp)
		ret = 0;
	pagefault_enable();

	return ret;
}

void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
			  const struct pt_regs *regs)
{
	unsigned long fp = regs->regs[22];

	while (fp && !((unsigned long)fp & 0xf)) {
		struct stack_frame frame;

		frame.fp = 0;
		frame.ra = 0;
		if (!copy_stack_frame(fp, &frame))
			break;
		if (!frame.ra)
			break;
		if (!consume_entry(cookie, frame.ra))
			break;
		fp = frame.fp;
	}
}
