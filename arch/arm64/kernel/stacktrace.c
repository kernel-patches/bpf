// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/filter.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>
#include <linux/unwind_dwarf_cfi.h>

#include <asm/efi.h>
#include <asm/irq.h>
#include <asm/sections.h>
#include <asm/stack_pointer.h>
#include <asm/stacktrace.h>

#ifdef CONFIG_UNWINDER_DWARF_CFI
static const struct dwarf_cfi_arch arm64_cfi_arch = {
	.ws	= 8,
	.sp_reg	= 31,	/* sp */
	.fp_reg	= 29,	/* x29 */
	.ra_reg	= 30,	/* x30 (lr) */
};

#ifdef CONFIG_MODULES
/**
 * arm64_unwind_module_init() - Build Minimal DWARF CFI index for a module
 * @mod: Module being loaded.
 * @eh_frame: Pointer to the module's SHF_ALLOC .eh_frame section.
 * @eh_frame_size: Size in bytes of @eh_frame.
 *
 * Scans and sorts the module's FDEs and publishes the index to
 * @mod->arch.dwarf_cfi_index for RCU-protected lockless unwinding.
 */
void arm64_unwind_module_init(struct module *mod, void *eh_frame,
			      size_t eh_frame_size)
{
	struct mod_dwarf_cfi_index *idx;

	idx = dwarf_cfi_mod_alloc(eh_frame, eh_frame_size, &arm64_cfi_arch);
	if (idx)
		rcu_assign_pointer(mod->arch.dwarf_cfi_index, idx);
}

/**
 * arm64_unwind_module_cleanup() - Unpublish and RCU-free module DWARF CFI index
 * @mod: Module being unloaded or cleaned up after a failed load.
 */
void arm64_unwind_module_cleanup(struct module *mod)
{
	struct mod_dwarf_cfi_index *idx;

	idx = rcu_replace_pointer(mod->arch.dwarf_cfi_index, /*ptr=*/NULL,
				  /*c=*/true);
	dwarf_cfi_mod_free_rcu(idx);
}

/**
 * arm64_dwarf_cfi_module_find() - Look up Minimal DWARF CFI in loadable modules
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
arm64_dwarf_cfi_module_find(unsigned long pc, struct dwarf_cfi_row *row)
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
	ret = dwarf_cfi_mod_eval(idx, pc, &arm64_cfi_arch, row);
	rcu_read_unlock_sched_notrace();
	return ret;
}
#else
static __always_inline int
arm64_dwarf_cfi_module_find(unsigned long pc, struct dwarf_cfi_row *row)
{
	return -ENOENT;
}
#endif /* CONFIG_MODULES */

/**
 * arm64_dwarf_cfi_find() - Evaluate Minimal DWARF CFI for core or module @pc
 * @pc: Kernel instruction pointer to look up.
 * @row: Output evaluated Minimal DWARF CFI row.
 *
 * Return: 0 on success, -ENOENT if no FDE covers @pc, or a negative errno on
 * malformed CFI data.
 */
static __always_inline int
arm64_dwarf_cfi_find(unsigned long pc, struct dwarf_cfi_row *row)
{
	size_t hdr_size = __stop_eh_frame_hdr - __start_eh_frame_hdr;
	int err;

	err = dwarf_cfi_unwind_eh_frame_hdr(__start_eh_frame_hdr, hdr_size,
					    __start_eh_frame, __stop_eh_frame,
					    pc, &arm64_cfi_arch, row);
	if (!err)
		return 0;

	return arm64_dwarf_cfi_module_find(pc, row);
}
#endif /* CONFIG_UNWINDER_DWARF_CFI */

/**
 * enum kunwind_source - Origin of the current frame's PC during kernel unwind
 * @KUNWIND_SOURCE_UNKNOWN: Uninitialized or invalid unwind state.
 * @KUNWIND_SOURCE_FRAME: Unwound from a callee stack frame or return address.
 * @KUNWIND_SOURCE_CALLER: Initialized from the immediate caller of the walker.
 * @KUNWIND_SOURCE_TASK: Initialized from a blocked task's saved thread_struct.
 * @KUNWIND_SOURCE_REGS_PC: Exact PC from an exception/interrupt &struct pt_regs.
 */
enum kunwind_source {
	KUNWIND_SOURCE_UNKNOWN,
	KUNWIND_SOURCE_FRAME,
	KUNWIND_SOURCE_CALLER,
	KUNWIND_SOURCE_TASK,
	KUNWIND_SOURCE_REGS_PC,
};

union unwind_flags {
	unsigned long	all;
	struct {
		unsigned long	fgraph : 1,
				kretprobe : 1;
	};
};

/**
 * struct kunwind_state - ARM64 kernel stack unwind iteration state
 * @common: Common stack-bounds, PC, and FP unwind state.
 * @task: The task being unwound.
 * @sp: Current frame's stack pointer (equal to the callee's CFA after stepping).
 * @lr: Saved link register (x30) when @lr_valid is true.
 * @graph_idx: Shadow-stack cursor for ftrace_graph_ret_addr().
 * @kr_cur: Cursor into @task->kretprobe_instances for kretprobe_find_ret_addr().
 * @source: How @common.pc was obtained (&enum kunwind_source).
 * @flags: Return-address recovery annotations (fgraph / kretprobe) for printing.
 * @lr_valid: True if @lr holds a live return address for leaf/entry frames.
 * @unreliable: True if an unannotated fallback (LR guess or non-CFI frame
 *              record) was used, disqualifying reliable stacktraces.
 */
struct kunwind_state {
	struct unwind_state common;
	struct task_struct *task;
	unsigned long sp;
	unsigned long lr;
	int graph_idx;
#ifdef CONFIG_KRETPROBES
	struct llist_node *kr_cur;
#endif
	enum kunwind_source source;
	union unwind_flags flags;
	bool lr_valid;
	bool unreliable;
};

static __always_inline int kunwind_next(struct kunwind_state *state);

static __always_inline void
kunwind_init(struct kunwind_state *state,
	     struct task_struct *task)
{
	unwind_init_common(&state->common);
	state->task = task;
	state->sp = 0;
	state->lr = 0;
	state->lr_valid = false;
	state->unreliable = false;
	state->source = KUNWIND_SOURCE_UNKNOWN;
	state->flags.all = 0;
}

/*
 * Start an unwind from a pt_regs.
 *
 * The unwind will begin at the PC within the regs.
 *
 * The regs must be on a stack currently owned by the calling task.
 */
static __always_inline void
kunwind_init_from_regs(struct kunwind_state *state,
		       struct pt_regs *regs)
{
	kunwind_init(state, current);

	state->common.fp = regs->regs[29];
	state->common.pc = regs->pc;
	state->sp = regs->sp;
	state->lr = regs->regs[30];
	state->lr_valid = !!state->lr;
	state->source = KUNWIND_SOURCE_REGS_PC;
}

/*
 * Start an unwind from a caller.
 *
 * The unwind will begin at the caller of whichever function this is inlined
 * into.
 *
 * The function which invokes this must be noinline.
 */
static __always_inline void
kunwind_init_from_caller(struct kunwind_state *state)
{
	kunwind_init(state, current);

#ifdef CONFIG_UNWINDER_DWARF_CFI
	{
		unsigned long pc, fp;

		asm volatile("1: adr %0, 1b\n\t"
			     "mov %1, x29"
			     : "=r"(pc), "=r"(fp));
		state->common.pc = pc;
		state->common.fp = fp;
		state->sp = current_stack_pointer;
		state->lr = (unsigned long)__builtin_return_address(0);
		state->lr_valid = true;
		state->source = KUNWIND_SOURCE_REGS_PC;
		if (!kunwind_next(state))
			state->source = KUNWIND_SOURCE_CALLER;
		else
			state->source = KUNWIND_SOURCE_UNKNOWN;
	}
#else
	state->common.fp = (unsigned long)__builtin_frame_address(1);
	state->common.pc = (unsigned long)__builtin_return_address(0);
	state->source = KUNWIND_SOURCE_CALLER;
#endif
}

/*
 * Start an unwind from a blocked task.
 *
 * The unwind will begin at the blocked tasks saved PC (i.e. the caller of
 * cpu_switch_to()).
 *
 * The caller should ensure the task is blocked in cpu_switch_to() for the
 * duration of the unwind, or the unwind will be bogus. It is never valid to
 * call this for the current task.
 */
static __always_inline void
kunwind_init_from_task(struct kunwind_state *state,
		       struct task_struct *task)
{
	kunwind_init(state, task);

	state->common.fp = thread_saved_fp(task);
	state->common.pc = thread_saved_pc(task);
	state->sp = thread_saved_sp(task);
	state->source = KUNWIND_SOURCE_TASK;
}

/**
 * kunwind_recover_return_address() - Restore fgraph/kretprobe return addresses
 * @state: Current ARM64 kernel unwind state.
 *
 * Replaces return_to_handler and __kretprobe_trampoline return addresses with
 * the original caller PC from @state->task's shadow stacks in either hooking
 * order. Under CONFIG_UNWINDER_DWARF_CFI (-fomit-frame-pointer), entries are
 * keyed on the frame's entry SP (@state->sp, equal to the callee's CFA) rather
 * than x29.
 *
 * Return: 0 on success, or -EINVAL if a shadow return address cannot be found.
 */
static __always_inline int
kunwind_recover_return_address(struct kunwind_state *state)
{
	void *frame_key __maybe_unused = IS_ENABLED(CONFIG_UNWINDER_DWARF_CFI) ?
					 (void *)state->sp :
					 (void *)state->common.fp;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (state->task->ret_stack &&
	    state->common.pc == (unsigned long)return_to_handler) {
		unsigned long orig_pc;

		orig_pc = ftrace_graph_ret_addr(state->task, &state->graph_idx,
						state->common.pc, frame_key);
		if (state->common.pc == orig_pc) {
			WARN_ON_ONCE(state->task == current &&
				     !state->unreliable);
			return -EINVAL;
		}
		state->common.pc = orig_pc;
		state->flags.fgraph = 1;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

#ifdef CONFIG_KRETPROBES
	if (is_kretprobe_trampoline(state->common.pc)) {
		unsigned long orig_pc;

		orig_pc = kretprobe_find_ret_addr(state->task, frame_key,
						  &state->kr_cur);
		if (!orig_pc)
			return -EINVAL;
		state->common.pc = orig_pc;
		state->flags.kretprobe = 1;
	}
#endif /* CONFIG_KRETPROBES */

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (state->task->ret_stack &&
	    state->common.pc == (unsigned long)return_to_handler) {
		unsigned long orig_pc;

		orig_pc = ftrace_graph_ret_addr(state->task, &state->graph_idx,
						state->common.pc, frame_key);
		if (state->common.pc == orig_pc) {
			WARN_ON_ONCE(state->task == current &&
				     !state->unreliable);
			return -EINVAL;
		}
		state->common.pc = orig_pc;
		state->flags.fgraph = 1;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

	return 0;
}

static __always_inline
int kunwind_next_regs_pc(struct kunwind_state *state)
{
	struct stack_info *info;
	unsigned long fp = state->common.fp;
	struct pt_regs *regs;

	regs = container_of((u64 *)fp, struct pt_regs, stackframe.record.fp);

	info = unwind_find_stack(&state->common, (unsigned long)regs, sizeof(*regs));
	if (!info)
		return -EINVAL;

	unwind_consume_stack(&state->common, info, (unsigned long)regs,
			     sizeof(*regs));

	state->common.pc = regs->pc;
	state->common.fp = regs->regs[29];
	state->sp = regs->sp;
	state->lr = regs->regs[30];
	state->lr_valid = !!state->lr;
	state->source = KUNWIND_SOURCE_REGS_PC;
	return 0;
}

static __always_inline int
kunwind_next_frame_record_meta(struct kunwind_state *state)
{
	struct task_struct *tsk = state->task;
	unsigned long fp = state->common.fp;
	struct frame_record_meta *meta;
	struct stack_info *info;

	info = unwind_find_stack(&state->common, fp, sizeof(*meta));
	if (!info)
		return -EINVAL;

	meta = (struct frame_record_meta *)fp;
	switch (READ_ONCE(meta->type)) {
	case FRAME_META_TYPE_FINAL:
		if (meta == &task_pt_regs(tsk)->stackframe) {
			if (IS_ENABLED(CONFIG_UNWINDER_DWARF_CFI) &&
			    state->sp != (unsigned long)task_pt_regs(tsk))
				return -EINVAL;
			return -ENOENT;
		}
		WARN_ON_ONCE(tsk == current);
		return -EINVAL;
	case FRAME_META_TYPE_PT_REGS:
		if (IS_ENABLED(CONFIG_UNWINDER_DWARF_CFI) &&
		    state->sp != (unsigned long)container_of(meta, struct pt_regs,
							     stackframe))
			return -EINVAL;
		return kunwind_next_regs_pc(state);
	default:
		WARN_ON_ONCE(tsk == current);
		return -EINVAL;
	}
}

static __always_inline int
kunwind_next_frame_record(struct kunwind_state *state)
{
	unsigned long fp = state->common.fp;
	struct frame_record *record;
	struct stack_info *info;
	unsigned long new_fp, new_pc;

	if (fp & 0x7)
		return -EINVAL;

	info = unwind_find_stack(&state->common, fp, sizeof(*record));
	if (!info)
		return -EINVAL;

	record = (struct frame_record *)fp;
	new_fp = READ_ONCE(record->fp);
	new_pc = READ_ONCE(record->lr);

	if (!new_fp && !new_pc)
		return kunwind_next_frame_record_meta(state);

	unwind_consume_stack(&state->common, info, fp, sizeof(*record));

	state->common.fp = new_fp;
	state->common.pc = new_pc;
	state->source = KUNWIND_SOURCE_FRAME;

	return 0;
}

#ifdef CONFIG_UNWINDER_DWARF_CFI
/**
 * kunwind_next_cfi() - Step one ARM64 kernel frame using Minimal DWARF CFI
 * @state: Current ARM64 kernel unwind state.
 *
 * Evaluates the Minimal DWARF CFI table at @state->common.pc (or pc - 4 for
 * call return addresses), validates stack bounds and monotonic stack
 * consumption across task/IRQ/overflow/SDEI/EFI stacks, and handles ftrace
 * trampolines, SP-verified exception frame_record_meta boundaries, and
 * frame-pointer fallbacks for JITed BPF code.
 *
 * Return: 0 on success, -ENOENT at the final user/kthread boundary or an
 * explicit DW_CFA_undefined root frame, or -EINVAL on invalid unwind state.
 */
static __always_inline int kunwind_next_cfi(struct kunwind_state *state)
{
	unsigned long lookup_pc, cfa, ra_addr = 0, new_pc, new_fp = state->common.fp;
	struct stack_info *info, *ra_info = NULL;
	struct dwarf_cfi_row row;
	int err;

	lookup_pc = (state->source == KUNWIND_SOURCE_REGS_PC) ?
		    state->common.pc : state->common.pc - 4;

	err = arm64_dwarf_cfi_find(lookup_pc, &row);
	if (err) {
		unsigned long old_fp = state->common.fp;

#ifdef CONFIG_DYNAMIC_FTRACE_WITH_ARGS
		if (lookup_pc >= (unsigned long)ftrace_caller &&
		    lookup_pc < (unsigned long)ftrace_caller_end &&
		    !(state->sp & 0x7)) {
			struct __arch_ftrace_regs *fregs = (void *)state->sp;
			size_t fsize = sizeof(*fregs) + 32;

			info = unwind_find_stack(&state->common, state->sp, fsize);
			if (info && READ_ONCE(fregs->sp) == state->sp + fsize) {
				unwind_consume_stack(&state->common, info,
						     state->sp, fsize);
				state->common.pc = READ_ONCE(fregs->pc);
				if (old_fp == state->sp + sizeof(*fregs))
					state->common.fp = READ_ONCE(fregs->fp);
				state->lr = ptrauth_strip_kernel_insn_pac(READ_ONCE(fregs->lr));
				state->lr_valid = true;
				state->sp += fsize;
				state->source = KUNWIND_SOURCE_FRAME;
				return 0;
			}
		}
#endif
		if (!(old_fp & 0x7) &&
		    unwind_find_stack(&state->common, old_fp,
				      sizeof(struct frame_record_meta))) {
			struct frame_record_meta *m = (void *)old_fp;

			if (state->sp == (unsigned long)container_of(m,
								     struct pt_regs,
								     stackframe) &&
			    !READ_ONCE(m->record.fp) &&
			    !READ_ONCE(m->record.lr))
				return kunwind_next_frame_record_meta(state);
		}

		if (state->lr_valid && !is_bpf_text_address(lookup_pc)) {
			state->common.pc = state->lr;
			state->lr_valid = false;
			state->source = KUNWIND_SOURCE_FRAME;
			state->unreliable = true;
			return 0;
		}

		info = !(old_fp & 0x7) ?
		       unwind_find_stack(&state->common, old_fp,
					 sizeof(struct frame_record)) : NULL;
		if (!info ||
		    (stackinfo_on_stack(info, state->sp, /*size=*/0) &&
		     old_fp < state->sp)) {
			if (state->lr_valid) {
				state->common.pc = state->lr;
				state->lr_valid = false;
				state->source = KUNWIND_SOURCE_FRAME;
				state->unreliable = true;
				return 0;
			}
			return -EINVAL;
		}

		err = kunwind_next_frame_record(state);
		if (!err && state->source == KUNWIND_SOURCE_FRAME) {
			state->sp = old_fp + sizeof(struct frame_record);
			state->lr_valid = false;
			state->unreliable = true;
		} else if (err && state->lr_valid) {
			state->common.pc = state->lr;
			state->lr_valid = false;
			state->source = KUNWIND_SOURCE_FRAME;
			state->unreliable = true;
			return 0;
		}
		return err;
	}

	if (row.ra_rule == DWARF_CFI_RULE_UNDEFINED)
		return -ENOENT;

	switch (row.cfa_base) {
	case DWARF_CFI_BASE_SP:
		cfa = state->sp + row.cfa_off;
		break;
	case DWARF_CFI_BASE_FP:
		cfa = state->common.fp + row.cfa_off;
		break;
	case DWARF_CFI_BASE_FP_INDIRECT:
		info = unwind_find_stack(&state->common,
					 state->common.fp + row.cfa_off,
					 sizeof(long));
		if (!info)
			return -EINVAL;
		cfa = READ_ONCE(*(unsigned long *)(state->common.fp + row.cfa_off));
		break;
	default:
		return -EINVAL;
	}

	if (cfa & 0x7)
		return -EINVAL;

	if (row.ra_rule == DWARF_CFI_RULE_SAME) {
		if (!state->lr_valid) {
			/*
			 * Non-struct_ops BPF trampolines push a synthetic
			 * parent frame record above the inner traced-function
			 * frame record; consume it at the pre-prologue entry.
			 */
			if (state->unreliable &&
			    row.cfa_base == DWARF_CFI_BASE_SP &&
			    row.cfa_off == 0 &&
			    state->common.fp == state->sp) {
				unsigned long old_fp = state->common.fp;

				err = kunwind_next_frame_record(state);
				if (!err && state->source == KUNWIND_SOURCE_FRAME)
					state->sp = old_fp + sizeof(struct frame_record);
				return err;
			}
			return -EINVAL;
		}
		if (cfa < state->sp)
			return -EINVAL;
		new_pc = state->lr;
	} else if (row.ra_rule == DWARF_CFI_RULE_OFFSET) {
		ra_addr = cfa + row.ra_off;

		ra_info = unwind_find_stack(&state->common, ra_addr, sizeof(long));
		if (!ra_info || !stackinfo_on_stack(ra_info, cfa, /*size=*/0))
			return -EINVAL;
		new_pc = READ_ONCE(*(unsigned long *)ra_addr);
	} else {
		return -EINVAL;
	}

	if (row.fp_rule == DWARF_CFI_RULE_OFFSET) {
		unsigned long fp_addr = cfa + row.fp_off;

		info = unwind_find_stack(&state->common, fp_addr, sizeof(long));
		if (!info)
			return -EINVAL;
		new_fp = READ_ONCE(*(unsigned long *)fp_addr);
	} else if (row.fp_rule == DWARF_CFI_RULE_FP_OFFSET) {
		unsigned long fp_addr = state->common.fp + row.fp_off;

		info = unwind_find_stack(&state->common, fp_addr, sizeof(long));
		if (!info)
			return -EINVAL;
		new_fp = READ_ONCE(*(unsigned long *)fp_addr);
	}

	if (row.ra_rule == DWARF_CFI_RULE_OFFSET) {
		if (stackinfo_on_stack(ra_info, state->sp, /*size=*/0)) {
			if (cfa <= state->sp ||
			    !stackinfo_on_stack(ra_info, state->sp,
						cfa - state->sp))
				return -EINVAL;
			unwind_consume_stack(&state->common, ra_info, state->sp,
					     cfa - state->sp);
		} else {
			if (row.cfa_base == DWARF_CFI_BASE_SP || cfa <= ra_addr)
				return -EINVAL;
			unwind_consume_stack(&state->common, ra_info, ra_addr,
					     cfa - ra_addr);
		}
	} else if (cfa > state->sp) {
		info = unwind_find_stack(&state->common, state->sp,
					 cfa - state->sp);
		if (!info)
			return -EINVAL;
		unwind_consume_stack(&state->common, info, state->sp,
				     cfa - state->sp);
	}

	state->sp = cfa;
	state->common.fp = new_fp;
	state->common.pc = new_pc;
	state->lr_valid = false;
	state->source = KUNWIND_SOURCE_FRAME;
	return 0;
}
#endif /* CONFIG_UNWINDER_DWARF_CFI */

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static __always_inline int
kunwind_next(struct kunwind_state *state)
{
	int err;

	state->flags.all = 0;

	switch (state->source) {
	case KUNWIND_SOURCE_FRAME:
	case KUNWIND_SOURCE_CALLER:
	case KUNWIND_SOURCE_TASK:
	case KUNWIND_SOURCE_REGS_PC:
#ifdef CONFIG_UNWINDER_DWARF_CFI
		err = kunwind_next_cfi(state);
#else
		err = kunwind_next_frame_record(state);
#endif
		break;
	default:
		err = -EINVAL;
	}

	if (err)
		return err;

	state->common.pc = ptrauth_strip_kernel_insn_pac(state->common.pc);

	return kunwind_recover_return_address(state);
}

typedef bool (*kunwind_consume_fn)(const struct kunwind_state *state, void *cookie);

static __always_inline int
do_kunwind(struct kunwind_state *state, kunwind_consume_fn consume_state,
	   void *cookie)
{
	int ret;

	if (state->source == KUNWIND_SOURCE_UNKNOWN)
		return -EINVAL;

	ret = kunwind_recover_return_address(state);
	if (ret)
		return ret;

	while (1) {
		if (!consume_state(state, cookie))
			return -EINVAL;
		ret = kunwind_next(state);
		if (ret == -ENOENT)
			return 0;
		if (ret < 0)
			return ret;
	}
}

/*
 * Per-cpu stacks are only accessible when unwinding the current task in a
 * non-preemptible context.
 */
#define STACKINFO_CPU(name)					\
	({							\
		((task == current) && !preemptible())		\
			? stackinfo_get_##name()		\
			: stackinfo_get_unknown();		\
	})

/*
 * SDEI stacks are only accessible when unwinding the current task in an NMI
 * context.
 */
#define STACKINFO_SDEI(name)					\
	({							\
		((task == current) && in_nmi())			\
			? stackinfo_get_sdei_##name()		\
			: stackinfo_get_unknown();		\
	})

#define STACKINFO_EFI						\
	({							\
		((task == current) && current_in_efi())		\
			? stackinfo_get_efi()			\
			: stackinfo_get_unknown();		\
	})

static __always_inline int
kunwind_stack_walk(kunwind_consume_fn consume_state,
		   void *cookie, struct task_struct *task,
		   struct pt_regs *regs)
{
	struct stack_info stacks[] = {
		stackinfo_get_task(task),
		STACKINFO_CPU(irq),
		STACKINFO_CPU(overflow),
#if defined(CONFIG_ARM_SDE_INTERFACE)
		STACKINFO_SDEI(normal),
		STACKINFO_SDEI(critical),
#endif
#ifdef CONFIG_EFI
		STACKINFO_EFI,
#endif
	};
	struct kunwind_state state = {
		.common = {
			.stacks = stacks,
			.nr_stacks = ARRAY_SIZE(stacks),
		},
	};

	if (regs) {
		if (task != current)
			return -EINVAL;
		if (IS_ENABLED(CONFIG_UNWINDER_DWARF_CFI) &&
		    regs->stackframe.type == FRAME_META_TYPE_CALLER &&
		    !regs->regs[30]) {
			unsigned long target_pc =
				ptrauth_strip_kernel_insn_pac(regs->pc);

			kunwind_init_from_caller(&state);
			while (state.source != KUNWIND_SOURCE_UNKNOWN &&
			       (state.sp < regs->sp ||
				(state.sp == regs->sp &&
				 state.sp <= regs->regs[29] &&
				 state.common.pc != target_pc))) {
				if (kunwind_next(&state)) {
					state.source = KUNWIND_SOURCE_UNKNOWN;
					break;
				}
			}
		} else {
			kunwind_init_from_regs(&state, regs);
		}
	} else if (task == current) {
		kunwind_init_from_caller(&state);
	} else {
		kunwind_init_from_task(&state, task);
	}

	return do_kunwind(&state, consume_state, cookie);
}

struct kunwind_consume_entry_data {
	stack_trace_consume_fn consume_entry;
	void *cookie;
};

static __always_inline bool
arch_kunwind_consume_entry(const struct kunwind_state *state, void *cookie)
{
	struct kunwind_consume_entry_data *data = cookie;
	return data->consume_entry(data->cookie, state->common.pc);
}

noinline noinstr void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	struct kunwind_consume_entry_data data = {
		.consume_entry = consume_entry,
		.cookie = cookie,
	};

	kunwind_stack_walk(arch_kunwind_consume_entry, &data, task, regs);
}

static __always_inline bool
arch_reliable_kunwind_consume_entry(const struct kunwind_state *state, void *cookie)
{
	/*
	 * At an exception boundary we can reliably consume the saved PC. We do
	 * not know whether the LR was live when the exception was taken, and
	 * so we cannot perform the next unwind step reliably.
	 *
	 * All that matters is whether the *entire* unwind is reliable, so give
	 * up as soon as we hit an exception boundary.
	 */
	if (state->source == KUNWIND_SOURCE_REGS_PC || state->unreliable)
		return false;

	return arch_kunwind_consume_entry(state, cookie);
}

noinline noinstr int arch_stack_walk_reliable(stack_trace_consume_fn consume_entry,
					      void *cookie,
					      struct task_struct *task)
{
	struct kunwind_consume_entry_data data = {
		.consume_entry = consume_entry,
		.cookie = cookie,
	};

	return kunwind_stack_walk(arch_reliable_kunwind_consume_entry, &data,
				  task, NULL);
}

struct bpf_unwind_consume_entry_data {
	bool (*consume_entry)(void *cookie, u64 ip, u64 sp, u64 fp);
	void *cookie;
};

static bool
arch_bpf_unwind_consume_entry(const struct kunwind_state *state, void *cookie)
{
	struct bpf_unwind_consume_entry_data *data = cookie;

	return data->consume_entry(data->cookie, state->common.pc, 0,
				   state->common.fp);
}

noinline noinstr void arch_bpf_stack_walk(bool (*consume_entry)(void *cookie, u64 ip, u64 sp,
								u64 fp), void *cookie)
{
	struct bpf_unwind_consume_entry_data data = {
		.consume_entry = consume_entry,
		.cookie = cookie,
	};

	kunwind_stack_walk(arch_bpf_unwind_consume_entry, &data, current, NULL);
}

static const char *state_source_string(const struct kunwind_state *state)
{
	switch (state->source) {
	case KUNWIND_SOURCE_FRAME:	return NULL;
	case KUNWIND_SOURCE_CALLER:	return "C";
	case KUNWIND_SOURCE_TASK:	return "T";
	case KUNWIND_SOURCE_REGS_PC:	return "P";
	default:			return "U";
	}
}

static bool dump_backtrace_entry(const struct kunwind_state *state, void *arg)
{
	const char *source = state_source_string(state);
	union unwind_flags flags = state->flags;
	bool has_info = source || flags.all;
	char *loglvl = arg;

	printk("%s %pSb%s%s%s%s%s\n", loglvl,
		(void *)state->common.pc,
		has_info ? " (" : "",
		source ? source : "",
		flags.fgraph ? "F" : "",
		flags.kretprobe ? "K" : "",
		has_info ? ")" : "");

	return true;
}

noinline void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
			     const char *loglvl)
{
	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs && user_mode(regs))
		return;

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	printk("%sCall trace:\n", loglvl);
	kunwind_stack_walk(dump_backtrace_entry, (void *)loglvl, tsk, regs);

	put_task_stack(tsk);
}

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}

/*
 * The struct defined for userspace stack frame in AARCH64 mode.
 */
struct frame_tail {
	struct frame_tail	__user *fp;
	unsigned long		lr;
} __attribute__((packed));

/*
 * Get the return address for a single stackframe and return a pointer to the
 * next frame tail.
 */
static struct frame_tail __user *
unwind_user_frame(struct frame_tail __user *tail, void *cookie,
	       stack_trace_consume_fn consume_entry)
{
	struct frame_tail buftail;
	unsigned long err;
	unsigned long lr;

	/* Also check accessibility of one struct frame_tail beyond */
	if (!access_ok(tail, sizeof(buftail)))
		return NULL;

	pagefault_disable();
	err = __copy_from_user_inatomic(&buftail, tail, sizeof(buftail));
	pagefault_enable();

	if (err)
		return NULL;

	lr = ptrauth_strip_user_insn_pac(buftail.lr);

	if (!consume_entry(cookie, lr))
		return NULL;

	/*
	 * Frame pointers should strictly progress back up the stack
	 * (towards higher addresses).
	 */
	if (tail >= buftail.fp)
		return NULL;

	return buftail.fp;
}

#ifdef CONFIG_COMPAT
/*
 * The registers we're interested in are at the end of the variable
 * length saved register structure. The fp points at the end of this
 * structure so the address of this struct is:
 * (struct compat_frame_tail *)(xxx->fp)-1
 *
 * This code has been adapted from the ARM OProfile support.
 */
struct compat_frame_tail {
	compat_uptr_t	fp; /* a (struct compat_frame_tail *) in compat mode */
	u32		sp;
	u32		lr;
} __attribute__((packed));

static struct compat_frame_tail __user *
unwind_compat_user_frame(struct compat_frame_tail __user *tail, void *cookie,
				stack_trace_consume_fn consume_entry)
{
	struct compat_frame_tail buftail;
	unsigned long err;

	/* Also check accessibility of one struct frame_tail beyond */
	if (!access_ok(tail, sizeof(buftail)))
		return NULL;

	pagefault_disable();
	err = __copy_from_user_inatomic(&buftail, tail, sizeof(buftail));
	pagefault_enable();

	if (err)
		return NULL;

	if (!consume_entry(cookie, buftail.lr))
		return NULL;

	/*
	 * Frame pointers should strictly progress back up the stack
	 * (towards higher addresses).
	 */
	if (tail + 1 >= (struct compat_frame_tail __user *)
			compat_ptr(buftail.fp))
		return NULL;

	return (struct compat_frame_tail __user *)compat_ptr(buftail.fp) - 1;
}
#endif /* CONFIG_COMPAT */


void arch_stack_walk_user(stack_trace_consume_fn consume_entry, void *cookie,
					const struct pt_regs *regs)
{
	if (!consume_entry(cookie, regs->pc))
		return;

	if (!compat_user_mode(regs)) {
		/* AARCH64 mode */
		struct frame_tail __user *tail;

		tail = (struct frame_tail __user *)regs->regs[29];
		while (tail && !((unsigned long)tail & 0x7))
			tail = unwind_user_frame(tail, cookie, consume_entry);
	} else {
#ifdef CONFIG_COMPAT
		/* AARCH32 compat mode */
		struct compat_frame_tail __user *tail;

		tail = (struct compat_frame_tail __user *)regs->compat_fp - 1;
		while (tail && !((unsigned long)tail & 0x3))
			tail = unwind_compat_user_frame(tail, cookie, consume_entry);
#endif
	}
}
