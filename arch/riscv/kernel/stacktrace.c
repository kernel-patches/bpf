// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2008 ARM Limited
 * Copyright (C) 2014 Regents of the University of California
 */

#include <linux/export.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/rethook.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/ftrace.h>
#include <linux/unwind_dwarf_cfi.h>

#include <asm/irq_stack.h>
#include <asm/sections.h>
#include <asm/stacktrace.h>

/*
 * This disables KASAN checking when reading a value from another task's stack,
 * since the other task could be running on another CPU and could have poisoned
 * the stack in the meantime.
 */
#define READ_ONCE_TASK_STACK(task, x)			\
({							\
	unsigned long val;				\
	unsigned long addr = x;				\
	if ((task) == current)				\
		val = READ_ONCE(addr);			\
	else						\
		val = READ_ONCE_NOCHECK(addr);		\
	val;						\
})

extern asmlinkage void handle_exception(void);
extern unsigned long ret_from_exception_end;

#ifdef CONFIG_UNWINDER_DWARF_CFI

static const struct dwarf_cfi_arch riscv_cfi_arch = {
	.ws	= sizeof(unsigned long),
	.sp_reg	= 2,	/* sp (x2) */
	.fp_reg	= 8,	/* s0/fp (x8) */
	.ra_reg	= 1,	/* ra (x1) */
};

#ifdef CONFIG_MODULES
/**
 * riscv_unwind_module_init() - Build Minimal DWARF CFI index for a module
 * @mod: Module being loaded.
 * @eh_frame: Pointer to the module's SHF_ALLOC .eh_frame section.
 * @eh_frame_size: Size in bytes of @eh_frame.
 *
 * Scans and sorts the module's FDEs and publishes the index to
 * @mod->arch.dwarf_cfi_index for RCU-protected lockless unwinding.
 */
void riscv_unwind_module_init(struct module *mod, void *eh_frame,
			      size_t eh_frame_size)
{
	struct mod_dwarf_cfi_index *idx;

	idx = dwarf_cfi_mod_alloc(eh_frame, eh_frame_size, &riscv_cfi_arch);
	if (idx)
		rcu_assign_pointer(mod->arch.dwarf_cfi_index, idx);
}

/**
 * riscv_unwind_module_cleanup() - Unpublish and RCU-free module DWARF CFI index
 * @mod: Module being unloaded or cleaned up after a failed load.
 */
void riscv_unwind_module_cleanup(struct module *mod)
{
	struct mod_dwarf_cfi_index *idx;

	idx = rcu_replace_pointer(mod->arch.dwarf_cfi_index, /*ptr=*/NULL,
				  /*c=*/true);
	dwarf_cfi_mod_free_rcu(idx);
}

/**
 * riscv_dwarf_cfi_module_find() - Look up Minimal DWARF CFI in loadable modules
 * @pc: Kernel instruction pointer to evaluate.
 * @row: Output evaluated Minimal DWARF CFI row.
 *
 * Uses rcu_read_lock_sched_notrace() and rcu_dereference_raw() so lookups are
 * safe inside noinstr stack walks and NMI contexts.
 *
 * Return: 0 on success, -ENOENT if @pc is not in a module FDE, or a negative
 * errno on invalid FDE bytecode.
 */
static __always_inline int
riscv_dwarf_cfi_module_find(unsigned long pc, struct dwarf_cfi_row *row)
{
	struct mod_dwarf_cfi_index *idx;
	struct module *mod;
	int ret;

	rcu_read_lock_sched_notrace();
	mod = __module_address(pc);
	if (!mod) {
		rcu_read_unlock_sched_notrace();
		return -ENOENT;
	}
	idx = rcu_dereference_raw(mod->arch.dwarf_cfi_index);
	ret = dwarf_cfi_mod_eval(idx, pc, &riscv_cfi_arch, row);
	rcu_read_unlock_sched_notrace();
	return ret;
}
#else
static __always_inline int
riscv_dwarf_cfi_module_find(unsigned long pc, struct dwarf_cfi_row *row)
{
	return -ENOENT;
}
#endif /* CONFIG_MODULES */

/**
 * riscv_dwarf_cfi_find() - Evaluate Minimal DWARF CFI for core or module @pc
 * @pc: Kernel instruction pointer to look up.
 * @row: Output evaluated Minimal DWARF CFI row.
 *
 * Return: 0 on success, -ENOENT if no FDE covers @pc, or a negative errno on
 * malformed CFI data.
 */
static __always_inline int
riscv_dwarf_cfi_find(unsigned long pc, struct dwarf_cfi_row *row)
{
	size_t hdr_size = __stop_eh_frame_hdr - __start_eh_frame_hdr;
	int err;

	err = dwarf_cfi_unwind_eh_frame_hdr(__start_eh_frame_hdr, hdr_size,
					    __start_eh_frame, __stop_eh_frame,
					    pc, &riscv_cfi_arch, row);
	if (!err)
		return 0;

	return riscv_dwarf_cfi_module_find(pc, row);
}

/**
 * riscv_fgraph_recover() - Recover original return address from ftrace_graph
 * @task: Task being unwound.
 * @graph_idx: Shadow-stack index cursor for ftrace_graph_ret_addr().
 * @pc: Candidate return address (potentially &return_to_handler).
 * @cfa: Callee frame's Canonical Frame Address (entry SP).
 * @ra_slot: Stack slot where @pc was saved (overridden when DYNAMIC_FTRACE_WITH_ARGS).
 *
 * Return: Restored caller PC if @pc matched &return_to_handler, or @pc.
 */
static __always_inline unsigned long
riscv_fgraph_recover(struct task_struct *task, int *graph_idx,
		     unsigned long pc, unsigned long cfa,
		     unsigned long *ra_slot)
{
#if defined(CONFIG_FUNCTION_GRAPH_TRACER) && defined(CONFIG_DYNAMIC_FTRACE_WITH_ARGS)
	unsigned long fregs_addr = cfa - ALIGN(sizeof(struct __arch_ftrace_regs),
					       STACK_ALIGN);

	ra_slot = &((struct __arch_ftrace_regs *)fregs_addr)->ra;
#endif
	return ftrace_graph_ret_addr(task, graph_idx, pc, ra_slot);
}

/**
 * riscv_recover_ret_addr() - Recover ftrace_graph and rethook return addresses
 * @task: Task being unwound.
 * @graph_idx: Shadow-stack cursor for ftrace_graph_ret_addr().
 * @kr_cur: Shadow-list cursor for rethook_find_ret_addr().
 * @pc: Candidate return address to recover.
 * @cfa: Callee frame's Canonical Frame Address (entry SP).
 * @ra_slot: Stack slot where @pc was saved (or NULL if still in ra).
 *
 * Recovers original caller PCs across both ftrace_graph and rethook shadow
 * stacks in either hooking order, keying rethook lookups on @cfa (matching
 * arch_rethook_prepare() under CONFIG_UNWINDER_DWARF_CFI).
 *
 * Return: Restored caller PC, or 0 if recovery failed.
 */
static __always_inline unsigned long
riscv_recover_ret_addr(struct task_struct *task, int *graph_idx,
		       struct llist_node **kr_cur, unsigned long pc,
		       unsigned long cfa, unsigned long *ra_slot)
{
	pc = riscv_fgraph_recover(task, graph_idx, pc, cfa, ra_slot);
#ifdef CONFIG_RETHOOK
	if (is_rethook_trampoline(pc)) {
		pc = rethook_find_ret_addr(task, cfa, kr_cur);
		if (!pc || is_rethook_trampoline(pc))
			return 0;
	}
#endif
	pc = riscv_fgraph_recover(task, graph_idx, pc, cfa, ra_slot);
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (pc == (unsigned long)return_to_handler)
		return 0;
#endif
	return pc;
}

#define RISCV_STACK_TASK	BIT(0)
#define RISCV_STACK_IRQ		BIT(1)
#define RISCV_STACK_OVERFLOW	BIT(2)

/**
 * riscv_stack_bounds() - Validate that [@addr, @addr + @size) lies on a stack
 * @task: Task whose stacks are checked.
 * @addr: Start virtual address of the stack access.
 * @size: Access size in bytes.
 * @out_low: Output lower bound of the matched stack.
 * @out_high: Output upper bound of the matched stack.
 *
 * Checks @task's task stack, and when unwinding @current in non-preemptible
 * context, also checks the per-CPU IRQ and vmap overflow stacks.
 *
 * Return: RISCV_STACK_* bit for the matched stack, or 0 if out of bounds.
 */
static __always_inline unsigned int
riscv_stack_bounds(struct task_struct *task, unsigned long addr,
		   size_t size, unsigned long *out_low,
		   unsigned long *out_high)
{
	unsigned long low, high;

	low = (unsigned long)task_stack_page(task);
	high = low + THREAD_SIZE;
	if (addr >= low && (addr < high || (!size && addr == high)) &&
	    addr + size >= addr && addr + size <= high) {
		*out_low = low;
		*out_high = high;
		return RISCV_STACK_TASK;
	}

	if (task == current && !preemptible()) {
#ifdef CONFIG_IRQ_STACKS
		low = (unsigned long)raw_cpu_read(irq_stack_ptr);
		high = low + IRQ_STACK_SIZE;
		if (low && addr >= low &&
		    (addr < high || (!size && addr == high)) &&
		    addr + size >= addr && addr + size <= high) {
			*out_low = low;
			*out_high = high;
			return RISCV_STACK_IRQ;
		}
#endif
#ifdef CONFIG_VMAP_STACK
		low = (unsigned long)raw_cpu_ptr(overflow_stack);
		high = low + OVERFLOW_STACK_SIZE;
		if (addr >= low && (addr < high || (!size && addr == high)) &&
		    addr + size >= addr && addr + size <= high) {
			*out_low = low;
			*out_high = high;
			return RISCV_STACK_OVERFLOW;
		}
#endif
	}

	return 0;
}

/**
 * walk_stackframe_cfi() - Unwind a RISC-V kernel stack via Minimal DWARF CFI
 * @task: Target task to unwind (NULL defaults to current).
 * @regs: Optional starting register state (rejected when @require_reliable).
 * @fn: Callback invoked for each unwound PC; returning false stops the walk.
 * @arg: Opaque cookie passed to @fn.
 * @require_reliable: When true, reject exception boundaries, unannotated leaf
 *                    fallbacks, and non-CFI frame-pointer guesses.
 *
 * Return: 0 on clean stack termination (or early callback stop when
 * !@require_reliable), or -EINVAL when a reliable walk cannot be guaranteed.
 */
static __always_inline int
walk_stackframe_cfi(struct task_struct *task, struct pt_regs *regs,
		    bool (*fn)(void *, unsigned long), void *arg,
		    bool require_reliable)
{
	unsigned long fp, sp, pc, ra = 0, min_sp = 0, caller_fp = 0, caller_pc = 0;
	bool ra_valid = false, exact_pc = false, unreliable = false;
	struct llist_node *kr_cur = NULL;
	unsigned int used_stacks = 0;
	int graph_idx = 0;
	int level = 0;

	if (!task)
		task = current;

	if (regs && regs->cause == ~0UL && !regs->ra) {
		if (require_reliable || task != current)
			return -EINVAL;
		min_sp = regs->sp;
		caller_fp = regs->s0;
		caller_pc = regs->epc;
		regs = NULL;
	}

	if (regs) {
		if (require_reliable)
			return -EINVAL;
		fp = frame_pointer(regs);
		sp = kernel_stack_pointer(regs);
		pc = instruction_pointer(regs);
		ra = regs->ra;
		ra_valid = !!ra;
		exact_pc = true;
	} else if (task == current) {
		asm volatile("1: auipc %0, 0\n\t"
			     "mv %1, s0"
			     : "=r"(pc), "=r"(fp));
		sp = current_stack_pointer;
		ra = (unsigned long)__builtin_return_address(0);
		ra_valid = true;
		exact_pc = true;
		level = -1;
	} else {
		fp = task->thread.s[0];
		sp = task->thread.sp;
		pc = task->thread.ra;
	}

	for (;;) {
		unsigned long lookup_pc, cfa, next_pc, next_fp = fp;
		unsigned long cur_low = 0, cur_high = 0, low = 0, high = 0;
		unsigned long tsk_low = (unsigned long)task_stack_page(task);
		unsigned int cur_stk, next_stk;
		struct dwarf_cfi_row row;
		bool skip_emit;
		int err;

		if (!pc) {
			if (exact_pc && ra_valid && !require_reliable) {
				pc = ra;
				ra_valid = false;
				exact_pc = false;
				unreliable = true;
				continue;
			}
			return require_reliable ? -EINVAL : 0;
		}

		/*
		 * Boot and secondary CPU idle tasks enter C code from
		 * .head.text ([_start, _stext)), which precedes _stext.
		 */
		if (is_idle_task(task) &&
		    sp >= (unsigned long)task_pt_regs(task) &&
		    sp <= tsk_low + THREAD_SIZE &&
		    pc >= (unsigned long)_start &&
		    pc < (unsigned long)_stext)
			return 0;

		if (!__kernel_text_address(pc))
			return require_reliable ? -EINVAL : 0;

		skip_emit = (level++ < 0) ||
			    (min_sp && (sp < min_sp ||
					(sp == min_sp && sp < caller_fp &&
					 pc != caller_pc)));

		if (sp == (unsigned long)task_pt_regs(task) &&
		    pc >= (unsigned long)ret_from_fork_kernel_asm &&
		    pc < (unsigned long)&ret_from_fork_asm_end) {
			if (!skip_emit && !fn(arg, pc))
				return require_reliable ? -EINVAL : 0;
			return 0;
		}

		if (!skip_emit && !fn(arg, pc))
			return require_reliable ? -EINVAL : 0;
		if (!skip_emit)
			min_sp = 0;

		if (pc >= (unsigned long)handle_exception &&
		    pc < (unsigned long)&ret_from_exception_end) {
			struct pt_regs *er = (struct pt_regs *)sp;
			unsigned long status, next_sp, next_ra;

			if (sp & (sizeof(long) - 1))
				return -EINVAL;
			cur_stk = riscv_stack_bounds(task, sp, sizeof(*er),
						     &cur_low, &cur_high);
			if (!cur_stk)
				return -EINVAL;
			status = READ_ONCE_TASK_STACK(task, er->status);
			if ((status & SR_PP) == 0)
				return 0;
			if (require_reliable)
				return -EINVAL;

			next_pc = READ_ONCE_TASK_STACK(task, er->epc);
			next_sp = READ_ONCE_TASK_STACK(task, er->sp);
			next_fp = READ_ONCE_TASK_STACK(task, er->s0);
			next_ra = READ_ONCE_TASK_STACK(task, er->ra);
			if (next_sp & (sizeof(long) - 1))
				return -EINVAL;
			next_stk = riscv_stack_bounds(task, next_sp,
						      /*size=*/0,
						      &low, &high);
			if (!next_stk)
				return -EINVAL;
			if (low == cur_low) {
				if (next_sp <= sp)
					return -EINVAL;
			} else {
				if (used_stacks & next_stk)
					return -EINVAL;
				used_stacks |= cur_stk;
			}
			pc = next_pc;
			sp = next_sp;
			fp = next_fp;
			ra = next_ra;
			ra_valid = true;
			exact_pc = true;
			unreliable = true;
			continue;
		}

		lookup_pc = exact_pc ? pc : pc - 2;
		err = riscv_dwarf_cfi_find(lookup_pc, &row);
		if (err) {
#ifdef CONFIG_DYNAMIC_FTRACE_WITH_ARGS
			if (lookup_pc >= (unsigned long)ftrace_caller_saved &&
			    lookup_pc < (unsigned long)ftrace_caller_restore &&
			    (!exact_pc || !require_reliable)) {
				size_t fsize = ALIGN(sizeof(struct __arch_ftrace_regs),
						     STACK_ALIGN);
				struct __arch_ftrace_regs *fregs = (void *)sp;

				if ((sp & (sizeof(long) - 1)) ||
				    !riscv_stack_bounds(task, sp, fsize,
							&cur_low, &cur_high) ||
				    READ_ONCE_TASK_STACK(task, fregs->sp) != sp + fsize)
					return -EINVAL;
				pc = READ_ONCE_TASK_STACK(task, fregs->epc);
				fp = READ_ONCE_TASK_STACK(task, fregs->s0);
				ra = READ_ONCE_TASK_STACK(task, fregs->ra);
				sp += fsize;
				ra_valid = true;
				exact_pc = true;
				if (!pc)
					return -EINVAL;
				continue;
			}
#endif
#ifdef CONFIG_IRQ_STACKS
			/*
			 * call_on_irq_stack() saves {fp, ra} below s0 on the
			 * task stack before switching sp to irq_stack_ptr.
			 */
			if (!require_reliable &&
			    task == current && !preemptible() &&
			    !(used_stacks & RISCV_STACK_TASK) &&
			    pc >= (unsigned long)call_on_irq_stack &&
			    pc < (unsigned long)&call_on_irq_stack_end) {
				unsigned long irq_low =
					(unsigned long)raw_cpu_read(irq_stack_ptr);

				if (irq_low && sp > irq_low &&
				    sp <= irq_low + IRQ_STACK_SIZE &&
				    fp && !(fp & 0x7) &&
				    fp >= tsk_low + sizeof(struct stackframe) &&
				    fp <= tsk_low + THREAD_SIZE) {
					struct stackframe *fr =
						(struct stackframe *)fp - 1;
					unsigned long old_fp = fp;

					next_fp = READ_ONCE_TASK_STACK(task, fr->fp);
					next_pc = READ_ONCE_TASK_STACK(task, fr->ra);
					next_pc =
						riscv_recover_ret_addr(task, &graph_idx,
								       &kr_cur, next_pc,
								       old_fp, &fr->ra);
					if (!next_pc)
						return 0;
					used_stacks |= RISCV_STACK_IRQ;
					fp = next_fp;
					pc = next_pc;
					sp = old_fp;
					ra_valid = false;
					exact_pc = false;
					unreliable = true;
					continue;
				}
			}
#endif
			if (exact_pc && ra_valid && !require_reliable &&
			    pc >= (unsigned long)_stext &&
			    pc < (unsigned long)_etext) {
				pc = riscv_recover_ret_addr(task, &graph_idx,
							    &kr_cur, ra, sp,
							    /*ra_slot=*/NULL);
				if (!pc)
					return 0;
				ra_valid = false;
				exact_pc = false;
				unreliable = true;
				continue;
			}

			/*
			 * Fallback to frame-pointer record at (fp - 16) for
			 * JITed BPF programs and BPF trampolines.
			 */
			if (!require_reliable && !(sp & 0x7) &&
			    riscv_stack_bounds(task, sp, /*size=*/0, &cur_low,
					       &cur_high) &&
			    !(fp & 0x7) &&
			    fp >= sp + sizeof(struct stackframe) &&
			    fp <= cur_high) {
				struct stackframe *fr = (struct stackframe *)fp - 1;
				unsigned long old_fp = fp;

				next_fp = READ_ONCE_TASK_STACK(task, fr->fp);
				next_pc = READ_ONCE_TASK_STACK(task, fr->ra);
				next_pc = riscv_recover_ret_addr(task,
								 &graph_idx, &kr_cur,
								 next_pc, old_fp, &fr->ra);
				if (!next_pc)
					return 0;
				fp = next_fp;
				pc = next_pc;
				sp = old_fp;
				ra_valid = false;
				exact_pc = false;
				unreliable = true;
				continue;
			}

			if (exact_pc && ra_valid && !require_reliable) {
				pc = riscv_recover_ret_addr(task, &graph_idx,
							    &kr_cur, ra, sp,
							    /*ra_slot=*/NULL);
				if (!pc)
					return 0;
				ra_valid = false;
				exact_pc = false;
				unreliable = true;
				continue;
			}
			return -EINVAL;
		}

		if (row.ra_rule == DWARF_CFI_RULE_UNDEFINED)
			return require_reliable ? -EINVAL : 0;

		if ((sp & (sizeof(long) - 1)) ||
		    !riscv_stack_bounds(task, sp, /*size=*/0, &cur_low,
					&cur_high))
			return -EINVAL;

		switch (row.cfa_base) {
		case DWARF_CFI_BASE_SP:
			cfa = sp + row.cfa_off;
			break;
		case DWARF_CFI_BASE_FP:
			cfa = fp + row.cfa_off;
			break;
		case DWARF_CFI_BASE_FP_INDIRECT:
			if (((fp + row.cfa_off) & (sizeof(long) - 1)) ||
			    !riscv_stack_bounds(task, fp + row.cfa_off,
						sizeof(long), &low, &high) ||
			    low != cur_low)
				return -EINVAL;
			cfa = READ_ONCE_TASK_STACK(task,
						   *(unsigned long *)(fp + row.cfa_off));
			break;
		default:
			return -EINVAL;
		}

		if ((cfa & (sizeof(long) - 1)) || cfa < cur_low || cfa > cur_high)
			return -EINVAL;

		if (row.fp_rule == DWARF_CFI_RULE_OFFSET) {
			unsigned long fp_addr = cfa + row.fp_off;

			if ((fp_addr & (sizeof(long) - 1)) ||
			    !riscv_stack_bounds(task, fp_addr, sizeof(long),
						&low, &high) ||
			    low != cur_low)
				return -EINVAL;
			next_fp = READ_ONCE_TASK_STACK(task, *(unsigned long *)fp_addr);
		} else if (row.fp_rule == DWARF_CFI_RULE_FP_OFFSET) {
			unsigned long fp_addr = fp + row.fp_off;

			if ((fp_addr & (sizeof(long) - 1)) ||
			    !riscv_stack_bounds(task, fp_addr, sizeof(long),
						&low, &high) ||
			    low != cur_low)
				return -EINVAL;
			next_fp = READ_ONCE_TASK_STACK(task, *(unsigned long *)fp_addr);
		}

		if (row.ra_rule == DWARF_CFI_RULE_SAME) {
			if (!ra_valid) {
				/*
				 * Non-struct_ops BPF trampolines push a
				 * synthetic parent frame record above the
				 * inner traced-function frame record.
				 */
				if (!require_reliable && unreliable &&
				    row.cfa_base == DWARF_CFI_BASE_SP &&
				    row.cfa_off == 0 &&
				    fp == sp + sizeof(struct stackframe) &&
				    fp <= cur_high) {
					struct stackframe *fr =
						(struct stackframe *)fp - 1;
					unsigned long old_fp = fp;

					next_fp = READ_ONCE_TASK_STACK(task, fr->fp);
					next_pc = READ_ONCE_TASK_STACK(task, fr->ra);
					next_pc =
						riscv_recover_ret_addr(task, &graph_idx,
								       &kr_cur, next_pc,
								       old_fp, &fr->ra);
					if (!next_pc)
						return 0;
					sp = old_fp;
					fp = next_fp;
					pc = next_pc;
					ra_valid = false;
					exact_pc = false;
					continue;
				}
				return -EINVAL;
			}
			if (cfa < sp)
				return -EINVAL;
			next_pc = riscv_recover_ret_addr(task, &graph_idx,
							 &kr_cur, ra, cfa,
							 /*ra_slot=*/NULL);
		} else if (row.ra_rule == DWARF_CFI_RULE_OFFSET) {
			unsigned long *ra_p = (unsigned long *)(cfa + row.ra_off);

			if (cfa <= sp ||
			    ((unsigned long)ra_p & (sizeof(long) - 1)) ||
			    !riscv_stack_bounds(task, (unsigned long)ra_p,
						sizeof(long), &low, &high) ||
			    low != cur_low)
				return -EINVAL;
			next_pc = READ_ONCE_TASK_STACK(task, *ra_p);
			next_pc = riscv_recover_ret_addr(task, &graph_idx,
							 &kr_cur, next_pc, cfa,
							 ra_p);
		} else {
			return -EINVAL;
		}

		if (!next_pc)
			return require_reliable ? -EINVAL : 0;

		sp = cfa;
		fp = next_fp;
		pc = next_pc;
		ra_valid = false;
		exact_pc = row.signal;
	}
}

noinline void notrace walk_stackframe(struct task_struct *task,
				      struct pt_regs *regs,
				      bool (*fn)(void *, unsigned long),
				      void *arg)
{
	walk_stackframe_cfi(task, regs, fn, arg, /*require_reliable=*/false);
}

noinline noinstr int arch_stack_walk_reliable(stack_trace_consume_fn consume_entry,
					      void *cookie,
					      struct task_struct *task)
{
	return walk_stackframe_cfi(task, /*regs=*/NULL, consume_entry, cookie,
				   /*require_reliable=*/true);
}

#elif defined(CONFIG_FRAME_POINTER)

static inline int fp_is_valid(unsigned long fp, unsigned long sp)
{
	unsigned long low, high;

	low = sp + sizeof(struct stackframe);
	high = ALIGN(sp, THREAD_SIZE);

	return !(fp < low || fp > high || fp & 0x07);
}

void notrace walk_stackframe(struct task_struct *task, struct pt_regs *regs,
			     bool (*fn)(void *, unsigned long), void *arg)
{
	unsigned long fp, sp, pc;
	int graph_idx = 0;
	int level = 0;

	if (regs) {
		fp = frame_pointer(regs);
		sp = user_stack_pointer(regs);
		pc = instruction_pointer(regs);
	} else if (task == NULL || task == current) {
		fp = (unsigned long)__builtin_frame_address(0);
		sp = current_stack_pointer;
		pc = (unsigned long)walk_stackframe;
		level = -1;
	} else {
		/* task blocked in __switch_to */
		fp = task->thread.s[0];
		sp = task->thread.sp;
		pc = task->thread.ra;
	}

	for (;;) {
		struct stackframe *frame;

		if (unlikely(!__kernel_text_address(pc) || (level++ >= 0 && !fn(arg, pc))))
			break;

		if (unlikely(!fp_is_valid(fp, sp)))
			break;

		/* Unwind stack frame */
		frame = (struct stackframe *)fp - 1;
		sp = fp;
		if (regs && (regs->epc == pc) && fp_is_valid(frame->ra, sp)) {
			/* We hit function where ra is not saved on the stack */
			fp = frame->ra;
			pc = regs->ra;
		} else {
			fp = READ_ONCE_TASK_STACK(task, frame->fp);
			pc = READ_ONCE_TASK_STACK(task, frame->ra);
			pc = ftrace_graph_ret_addr(task, &graph_idx, pc,
						   &frame->ra);
			if (pc >= (unsigned long)handle_exception &&
			    pc < (unsigned long)&ret_from_exception_end) {
				if (unlikely(!fn(arg, pc)))
					break;

				pc = ((struct pt_regs *)sp)->epc;
				fp = ((struct pt_regs *)sp)->s0;
			}
		}

	}
}

#else /* !CONFIG_FRAME_POINTER && !CONFIG_UNWINDER_DWARF_CFI */

void notrace walk_stackframe(struct task_struct *task,
	struct pt_regs *regs, bool (*fn)(void *, unsigned long), void *arg)
{
	unsigned long sp, pc;
	unsigned long *ksp;

	if (regs) {
		sp = user_stack_pointer(regs);
		pc = instruction_pointer(regs);
	} else if (task == NULL || task == current) {
		sp = current_stack_pointer;
		pc = (unsigned long)walk_stackframe;
	} else {
		/* task blocked in __switch_to */
		sp = task->thread.sp;
		pc = task->thread.ra;
	}

	if (unlikely(sp & 0x7))
		return;

	ksp = (unsigned long *)sp;
	while (!kstack_end(ksp)) {
		if (__kernel_text_address(pc) && unlikely(!fn(arg, pc)))
			break;
		pc = READ_ONCE_NOCHECK(*ksp++);
	}
}

#endif /* CONFIG_FRAME_POINTER */

static bool print_trace_address(void *arg, unsigned long pc)
{
	const char *loglvl = arg;

	print_ip_sym(loglvl, pc);
	return true;
}

noinline void dump_backtrace(struct pt_regs *regs, struct task_struct *task,
		    const char *loglvl)
{
	walk_stackframe(task, regs, print_trace_address, (void *)loglvl);
}

void show_stack(struct task_struct *task, unsigned long *sp, const char *loglvl)
{
	pr_cont("%sCall Trace:\n", loglvl);
	dump_backtrace(NULL, task, loglvl);
}

static bool save_wchan(void *arg, unsigned long pc)
{
	if (!in_sched_functions(pc)) {
		unsigned long *p = arg;
		*p = pc;
		return false;
	}
	return true;
}

unsigned long __get_wchan(struct task_struct *task)
{
	unsigned long pc = 0;

	if (!try_get_task_stack(task))
		return 0;
	walk_stackframe(task, NULL, save_wchan, &pc);
	put_task_stack(task);
	return pc;
}

noinline noinstr void arch_stack_walk(stack_trace_consume_fn consume_entry, void *cookie,
		     struct task_struct *task, struct pt_regs *regs)
{
	walk_stackframe(task, regs, consume_entry, cookie);
}

/*
 * Get the return address for a single stackframe and return a pointer to the
 * next frame tail.
 */
static unsigned long unwind_user_frame(stack_trace_consume_fn consume_entry,
				       void *cookie, unsigned long fp,
				       unsigned long reg_ra)
{
	struct stackframe buftail;
	unsigned long ra = 0;
	unsigned long __user *user_frame_tail =
		(unsigned long __user *)(fp - sizeof(struct stackframe));

	/* Check accessibility of one struct frame_tail beyond */
	if (!access_ok(user_frame_tail, sizeof(buftail)))
		return 0;
	if (__copy_from_user_inatomic(&buftail, user_frame_tail,
				      sizeof(buftail)))
		return 0;

	ra = reg_ra ? : buftail.ra;

	fp = buftail.fp;
	if (!ra || !consume_entry(cookie, ra))
		return 0;

	return fp;
}

void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
			  const struct pt_regs *regs)
{
	unsigned long fp = 0;

	fp = regs->s0;
	if (!consume_entry(cookie, regs->epc))
		return;

	fp = unwind_user_frame(consume_entry, cookie, fp, regs->ra);
	while (fp && !(fp & 0x7))
		fp = unwind_user_frame(consume_entry, cookie, fp, 0);
}
