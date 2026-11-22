// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal DWARF CFI kernel stack unwinder for x86-64.
 *
 * Unwinds kernel stacks using the link-time .eh_frame_hdr / .eh_frame tables
 * and the strictly bounded Minimal DWARF CFA subset (matching SFrame's state
 * model), with ENCODE_FRAME_POINTER handling entry/exception pt_regs frames.
 */

#define pr_fmt(fmt) "unwind_dwarf: " fmt

#include <linux/bpf.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/unwind_dwarf_cfi.h>
#include <asm/ptrace.h>
#include <asm/sections.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

static bool dwarf_cfi_ready __ro_after_init;

static const struct dwarf_cfi_arch x86_64_cfi_arch = {
	.ws	= 8,
	.sp_reg	= 7,	/* %rsp */
	.fp_reg	= 6,	/* %rbp */
	.ra_reg	= 16,	/* %rip */
};

/* Frame-pointer fallback row for BPF JIT frames */
static const struct dwarf_cfi_row bpf_fp_row = {
	.cfa_base	= DWARF_CFI_BASE_FP,
	.cfa_off	= 16,
	.fp_rule	= DWARF_CFI_RULE_OFFSET,
	.fp_off		= -16,
	.ra_rule	= DWARF_CFI_RULE_OFFSET,
	.ra_off		= -8,
};

/* Hardcoded row for IP == 0 (NULL function pointer call crash) */
static const struct dwarf_cfi_row null_call_row = {
	.cfa_base	= DWARF_CFI_BASE_SP,
	.cfa_off	= sizeof(long),
	.fp_rule	= DWARF_CFI_RULE_SAME,
	.ra_rule	= DWARF_CFI_RULE_OFFSET,
	.ra_off		= -(s32)sizeof(long),
};

#ifdef CONFIG_MODULES
/**
 * unwind_module_init() - Build Minimal DWARF CFI index for a loadable module
 * @mod: Module being loaded.
 * @orc_ip: Unused under CONFIG_UNWINDER_DWARF_CFI (shared prototype with ORC).
 * @orc_ip_size: Unused under CONFIG_UNWINDER_DWARF_CFI.
 * @eh_frame: Pointer to the module's SHF_ALLOC .eh_frame section.
 * @eh_frame_size: Size in bytes of @eh_frame.
 *
 * Scans and sorts the module's FDEs and publishes the resulting index to
 * @mod->arch.dwarf_cfi_index for RCU-protected lockless lookups.
 */
void unwind_module_init(struct module *mod, void *orc_ip, size_t orc_ip_size,
			void *eh_frame, size_t eh_frame_size)
{
	struct mod_dwarf_cfi_index *idx;

	idx = dwarf_cfi_mod_alloc(eh_frame, eh_frame_size, &x86_64_cfi_arch);
	if (idx)
		rcu_assign_pointer(mod->arch.dwarf_cfi_index, idx);
}

/**
 * unwind_module_cleanup() - Unpublish and RCU-free a module's DWARF CFI index
 * @mod: Module being unloaded or torn down on load failure.
 */
void unwind_module_cleanup(struct module *mod)
{
	struct mod_dwarf_cfi_index *idx;

	idx = rcu_replace_pointer(mod->arch.dwarf_cfi_index, /*ptr=*/NULL,
				  /*c=*/true);
	dwarf_cfi_mod_free_rcu(idx);
}

/**
 * dwarf_cfi_module_find() - Evaluate Minimal DWARF CFI for a module text IP
 * @ip: Kernel instruction pointer to look up (caller holds RCU read lock).
 * @row: Output evaluated Minimal DWARF CFI row.
 *
 * Return: 0 on success, -ENOENT if @ip is not in a module with an FDE, or a
 * negative errno on invalid FDE bytecode.
 */
static int dwarf_cfi_module_find(unsigned long ip, struct dwarf_cfi_row *row)
{
	struct mod_dwarf_cfi_index *idx;
	struct module *mod;

	mod = __module_address(ip);
	if (!mod)
		return -ENOENT;

	idx = rcu_dereference_raw(mod->arch.dwarf_cfi_index);
	return dwarf_cfi_mod_eval(idx, ip, &x86_64_cfi_arch, row);
}
#else
static int dwarf_cfi_module_find(unsigned long ip, struct dwarf_cfi_row *row)
{
	return -ENOENT;
}
#endif /* CONFIG_MODULES */

static int dwarf_cfi_find(unsigned long ip, struct dwarf_cfi_row *row);

#ifdef CONFIG_DYNAMIC_FTRACE
/**
 * dwarf_cfi_ftrace_find() - Map dynamic ftrace trampolines to template CFI
 * @ip: Instruction pointer potentially inside a dynamic ftrace ops trampoline.
 * @row: Output evaluated Minimal DWARF CFI row.
 *
 * Dynamic ftrace trampolines are copied from ftrace_caller or
 * ftrace_regs_caller templates at runtime and therefore have no static FDEs of
 * their own; translate @ip to the corresponding offset in the template stub.
 *
 * Return: 0 on success, or -ENOENT if @ip is not in a dynamic trampoline.
 */
static int dwarf_cfi_ftrace_find(unsigned long ip, struct dwarf_cfi_row *row)
{
	struct ftrace_ops *ops;
	unsigned long tramp_addr;

	ops = ftrace_ops_trampoline(ip);
	if (!ops)
		return -ENOENT;

	if (ops->flags & FTRACE_OPS_FL_SAVE_REGS)
		tramp_addr = (unsigned long)ftrace_regs_caller;
	else
		tramp_addr = (unsigned long)ftrace_caller;

	tramp_addr += ip - ops->trampoline;
	if (ip == tramp_addr)
		return -ENOENT;

	return dwarf_cfi_find(tramp_addr, row);
}
#else
static int dwarf_cfi_ftrace_find(unsigned long ip, struct dwarf_cfi_row *row)
{
	return -ENOENT;
}
#endif

/**
 * dwarf_cfi_find() - Locate and evaluate the Minimal DWARF CFI row for @ip
 * @ip: Kernel instruction pointer (caller holds RCU read lock).
 * @row: Output evaluated Minimal DWARF CFI row.
 *
 * Checks NULL-call faults (ip == 0), core vmlinux .eh_frame_hdr, loadable
 * modules, JITed BPF programs/trampolines with frame pointers, and dynamic
 * ftrace trampolines.
 *
 * Return: 0 on success, -ENOENT if no unwind entry covers @ip, or a negative
 * errno on malformed CFI data.
 */
static int dwarf_cfi_find(unsigned long ip, struct dwarf_cfi_row *row)
{
	size_t hdr_size = __stop_eh_frame_hdr - __start_eh_frame_hdr;
	int err;

	if (ip == 0) {
		*row = null_call_row;
		return 0;
	}

	err = dwarf_cfi_unwind_eh_frame_hdr(__start_eh_frame_hdr, hdr_size,
					    __start_eh_frame, __stop_eh_frame,
					    ip, &x86_64_cfi_arch, row);
	if (!err)
		return 0;

	err = dwarf_cfi_module_find(ip, row);
	if (!err)
		return 0;

#ifdef CONFIG_BPF_JIT
	if (bpf_has_frame_pointer(ip)) {
		*row = bpf_fp_row;
		return 0;
	}
#endif

	return dwarf_cfi_ftrace_find(ip, row);
}

/**
 * unwind_init() - Validate vmlinux .eh_frame_hdr and enable the CFI unwinder
 *
 * Verifies that the linker-generated .eh_frame_hdr version-1 table and
 * .eh_frame section are present before marking the unwinder ready during early
 * boot.
 */
void __init unwind_init(void)
{
	size_t hdr_size = __stop_eh_frame_hdr - __start_eh_frame_hdr;
	size_t eh_size = __stop_eh_frame - __start_eh_frame;

	if (hdr_size < 12 || !eh_size || __start_eh_frame_hdr[0] != 1) {
		pr_warn("Bad or missing .eh_frame_hdr table; disabling Minimal DWARF unwinder.\n");
		return;
	}

	dwarf_cfi_ready = true;
}

/**
 * unwind_get_return_address() - Return the current frame's kernel text IP
 * @state: Current x86 unwind state.
 *
 * Return: Kernel text instruction pointer for @state, or 0 if unwinding is
 * complete or @state->ip is outside kernel/module/BPF/ftrace text.
 */
unsigned long unwind_get_return_address(struct unwind_state *state)
{
	if (unwind_done(state))
		return 0;

	return __kernel_text_address(state->ip) ? state->ip : 0;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

/**
 * unwind_get_return_address_ptr() - Return stack slot address holding @state's IP
 * @state: Current x86 unwind state.
 *
 * Return: Pointer to the saved IP in @state->regs or at @state->sp - 8, or
 * NULL if unwinding is complete.
 */
unsigned long *unwind_get_return_address_ptr(struct unwind_state *state)
{
	if (unwind_done(state))
		return NULL;

	if (state->regs)
		return &state->regs->ip;

	if (state->sp)
		return (unsigned long *)state->sp - 1;

	return NULL;
}

static bool stack_access_ok(struct unwind_state *state, unsigned long _addr,
			    size_t len)
{
	struct stack_info *info = &state->stack_info;
	void *addr = (void *)_addr;

	if (on_stack(info, addr, len))
		return true;

	return !get_stack_info(addr, state->task, info, &state->stack_mask) &&
	       on_stack(info, addr, len);
}

static bool deref_stack_reg(struct unwind_state *state, unsigned long addr,
			    unsigned long *val)
{
	if (!stack_access_ok(state, addr, sizeof(long)))
		return false;

	*val = READ_ONCE_NOCHECK(*(unsigned long *)addr);
	return true;
}

static bool deref_stack_regs(struct unwind_state *state, unsigned long addr,
			     unsigned long *ip, unsigned long *sp,
			     unsigned long *bp)
{
	struct pt_regs *regs = (struct pt_regs *)addr;

	if (!stack_access_ok(state, addr, sizeof(struct pt_regs)))
		return false;

	*ip = READ_ONCE_NOCHECK(regs->ip);
	*sp = READ_ONCE_NOCHECK(regs->sp);
	*bp = READ_ONCE_NOCHECK(regs->bp);

	if (!user_mode(regs) &&
	    !on_stack(&state->stack_info, (void *)*sp, sizeof(long))) {
		struct stack_info next_info;

		if (!get_stack_info((unsigned long *)*sp, state->task,
				    &next_info, &state->stack_mask))
			state->stack_info = next_info;
	}
	return true;
}

static struct pt_regs *decode_frame_pointer(unsigned long bp)
{
	if (!(bp & 0x1))
		return NULL;

	return (struct pt_regs *)(bp & ~0x1UL);
}

/**
 * get_scratch_reg() - Read a transient DRAP CFA register from @state's pt_regs
 * @state: Current x86 unwind state.
 * @dwarf_reg: x86-64 DWARF register number used by DW_CFA_def_cfa_register.
 * @val: Output register value.
 *
 * Compilers realignment prologues/epilogues (DRAP) briefly define the CFA in a
 * caller-saved scratch register (%r10, %rcx, etc.) for 1-2 instructions. When
 * unwinding directly from an interrupt/exception with full pt_regs, recover
 * that register so asynchronous unwinding succeeds at every instruction.
 *
 * Return: true if @dwarf_reg was recovered from full pt_regs, false otherwise.
 */
static bool get_scratch_reg(struct unwind_state *state, u8 dwarf_reg,
			    unsigned long *val)
{
	struct pt_regs *regs = state->full_regs ? state->regs : state->prev_regs;

	if (!regs)
		return false;

	switch (dwarf_reg) {
	case 0: /* %rax */
		*val = READ_ONCE_NOCHECK(regs->ax);
		return true;
	case 1: /* %rdx */
		*val = READ_ONCE_NOCHECK(regs->dx);
		return true;
	case 2: /* %rcx */
		*val = READ_ONCE_NOCHECK(regs->cx);
		return true;
	case 5: /* %rdi */
		*val = READ_ONCE_NOCHECK(regs->di);
		return true;
	case 10: /* %r10 */
		*val = READ_ONCE_NOCHECK(regs->r10);
		return true;
	case 13: /* %r13 */
		*val = READ_ONCE_NOCHECK(regs->r13);
		return true;
	default:
		return false;
	}
}

static bool in_entry_text(unsigned long ip)
{
	char *addr = (char *)ip;

	return (addr >= __entry_text_start && addr < __entry_text_end) ||
	       (void *)ip == ret_from_fork_asm;
}

/**
 * dwarf_recover_ret_addr() - Recover ftrace_graph and rethook return addresses
 * @state: Current x86 unwind state.
 * @addr: Raw return address read from the stack or pt_regs.
 * @addr_p: Stack slot address where @addr was stored.
 *
 * Handles both single hooks and stacked hooks in either installation order
 * (fgraph->rethook via unwind_recover_ret_addr(), or rethook->fgraph via a
 * follow-up ftrace_graph_ret_addr() pass).
 *
 * Return: Original caller instruction pointer (or 0 if rethook lookup failed).
 */
static unsigned long dwarf_recover_ret_addr(struct unwind_state *state,
					    unsigned long addr,
					    unsigned long *addr_p)
{
	unsigned long ret;

	ret = unwind_recover_ret_addr(state, addr, addr_p);
	return ftrace_graph_ret_addr(state->task, &state->graph_idx,
				     ret, addr_p);
}

/**
 * unwind_next_frame() - Advance @state to the next outer x86-64 kernel frame
 * @state: Current x86 unwind state.
 *
 * Evaluates Minimal DWARF CFI for @state->ip, handles top-of-stack task
 * pt_regs, arch_rethook_trampoline entry, %rsp-verified ENCODE_FRAME_POINTER
 * entry/exception pt_regs transitions, and call_on_stack() IRQ stack pivots.
 *
 * Return: true if a valid outer frame was unwound, or false when the bottom of
 * the stack is reached or an error terminates the walk.
 */
bool unwind_next_frame(struct unwind_state *state)
{
	enum stack_type prev_type = state->stack_info.type;
	unsigned long prev_sp = state->sp;
	struct dwarf_cfi_row row;
	unsigned long lookup_ip, cfa, ip_p;
	struct pt_regs *regs;
	int err;

	if (unwind_done(state))
		return false;

	/* Keep module .eh_frame tables alive across lookup and evaluation */
	guard(rcu)();

	if (state->regs && user_mode(state->regs))
		goto the_end;

	/*
	 * Check if we have reached the top-of-task-stack pt_regs boundary
	 * (syscall entry, newly forked thread, kthread, or idle thread).
	 */
	regs = task_pt_regs(state->task);
	if ((void *)state->ip == ret_from_fork_asm ||
	    state->sp == (unsigned long)regs) {
		if (!user_mode(regs))
			goto the_end;

		if (!deref_stack_regs(state, (unsigned long)regs,
				      &state->ip, &state->sp, &state->bp))
			goto err;
		state->regs = regs;
		state->prev_regs = NULL;
		state->full_regs = true;
		state->signal = true;
		return true;
	}

	if (!state->ip && !state->signal)
		goto err;

	lookup_ip = state->signal ? state->ip : state->ip - 1;
	err = dwarf_cfi_find(lookup_ip, &row);
	if (err) {
		/*
		 * Handle an interrupt/unwind starting right at the entry of
		 * arch_rethook_trampoline() before pushq $arch_rethook_trampoline.
		 */
		if (state->signal && is_rethook_trampoline(state->ip)) {
			state->ip = dwarf_recover_ret_addr(state, state->ip,
					(unsigned long *)(state->sp - sizeof(long)));
			if (!state->ip || is_rethook_trampoline(state->ip))
				goto err;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
			if (state->ip == (unsigned long)return_to_handler)
				goto err;
#endif
			state->regs = NULL;
			state->prev_regs = NULL;
			state->full_regs = false;
			state->signal = true;
			return true;
		}

		/*
		 * Entry / interrupt / exception .S stubs without .eh_frame
		 * encode a pointer to struct pt_regs in %rbp via
		 * ENCODE_FRAME_POINTER (setting bit 0).  Verify that %rsp has
		 * actually reached that pt_regs frame (or the 8-byte return
		 * slot immediately below it in error_entry / paranoid_entry)
		 * so a stale outer encoded %rbp never skips intermediate frames.
		 */
		regs = decode_frame_pointer(state->bp);
		if (regs &&
		    (state->sp == (unsigned long)regs ||
		     (in_entry_text(state->ip) &&
		      state->sp == (unsigned long)regs - sizeof(long)))) {
			unsigned long orig_ip;

			if (!deref_stack_regs(state, (unsigned long)regs,
					      &orig_ip, &state->sp, &state->bp))
				goto err;
			state->ip = dwarf_recover_ret_addr(state, orig_ip,
					(unsigned long *)(state->sp - sizeof(long)));
			if (is_rethook_trampoline(orig_ip) &&
			    (!state->ip || is_rethook_trampoline(state->ip)))
				goto err;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
			if (is_rethook_trampoline(orig_ip) &&
			    state->ip == (unsigned long)return_to_handler)
				goto err;
#endif
			state->regs = regs;
			state->prev_regs = NULL;
			state->full_regs = true;
			state->signal = true;
			goto check_progress;
		}

		/*
		 * Unencoded entry assembly (pre-ENCODE_FRAME_POINTER or
		 * post-POP_REGS) or an unaligned/encoded %rbp cannot be
		 * unwound via a frame-pointer guess.
		 */
		if (in_entry_text(state->ip) || (state->bp & (sizeof(long) - 1)))
			goto err;

		/* Fallback to frame-pointer guess and mark unreliable */
		row = bpf_fp_row;
		state->error = true;
	}

	if (row.ra_rule == DWARF_CFI_RULE_UNDEFINED)
		goto the_end;

	if (row.ra_rule != DWARF_CFI_RULE_OFFSET)
		goto err;

	switch (row.cfa_base) {
	case DWARF_CFI_BASE_SP: {
		unsigned long sp_base = state->sp;

		/*
		 * call_on_stack() stores the pre-switch task-stack %rsp at the
		 * top slot of the per-CPU IRQ stack (info.end - 1) and pivots
		 * %rsp there before invoking the IRQ/softirq handler.
		 */
		if (state->stack_info.type == STACK_TYPE_IRQ &&
		    state->sp == (unsigned long)(state->stack_info.end - 1)) {
			if (!deref_stack_reg(state, state->sp, &sp_base))
				goto err;
		}
		cfa = sp_base + row.cfa_off;
		break;
	}
	case DWARF_CFI_BASE_FP:
		cfa = state->bp + row.cfa_off;
		break;
	case DWARF_CFI_BASE_FP_INDIRECT:
		if (!deref_stack_reg(state, state->bp + row.cfa_off, &cfa))
			goto err;
		break;
	case DWARF_CFI_BASE_REG:
		if (!get_scratch_reg(state, row.cfa_reg, &cfa))
			goto err;
		cfa += row.cfa_off;
		break;
	default:
		goto err;
	}

	ip_p = cfa + row.ra_off;
	if (!deref_stack_reg(state, ip_p, &state->ip))
		goto err;

	state->ip = dwarf_recover_ret_addr(state, state->ip,
					   (unsigned long *)ip_p);
	if (!state->ip || is_rethook_trampoline(state->ip))
		goto err;
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (state->ip == (unsigned long)return_to_handler)
		goto err;
#endif

	if (row.fp_rule == DWARF_CFI_RULE_OFFSET) {
		if (!deref_stack_reg(state, cfa + row.fp_off, &state->bp))
			goto err;
	} else if (row.fp_rule == DWARF_CFI_RULE_FP_OFFSET) {
		if (!deref_stack_reg(state, state->bp + row.fp_off, &state->bp))
			goto err;
	}

	state->sp = cfa;
	state->regs = NULL;
	state->prev_regs = NULL;
	state->full_regs = false;
	state->signal = row.signal;

check_progress:
	if (state->stack_info.type == prev_type &&
	    on_stack(&state->stack_info, (void *)state->sp, sizeof(long)) &&
	    state->sp <= prev_sp)
		goto err;

	return true;

err:
	state->error = true;
the_end:
	state->stack_info.type = STACK_TYPE_UNKNOWN;
	return false;
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

/**
 * __unwind_start() - Initialize an x86-64 Minimal DWARF CFI kernel stack walk
 * @state: Unwind state structure to initialize.
 * @task: Task whose kernel stack is being unwound.
 * @regs: Optional starting register state (e.g. from an interrupt/exception).
 * @first_frame: Stack pointer threshold to skip frames below the caller.
 */
void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *first_frame)
{
	memset(state, 0, sizeof(*state));
	state->task = task;

	if (!dwarf_cfi_ready)
		goto err;

	if (task_on_another_cpu(task))
		goto err;

	if (regs) {
		if (user_mode(regs))
			goto the_end;

		state->ip = regs->ip;
		state->sp = regs->sp;
		state->bp = regs->bp;
		state->regs = regs;
		state->full_regs = true;
		state->signal = true;
	} else if (task == current) {
		asm volatile("lea (%%rip), %0\n\t"
			     "mov %%rsp, %1\n\t"
			     "mov %%rbp, %2\n\t"
			     : "=r" (state->ip), "=r" (state->sp),
			       "=r" (state->bp));
		state->signal = true;
	} else {
		struct inactive_task_frame *frame = (void *)task->thread.sp;

		state->sp = task->thread.sp + sizeof(*frame);
		state->bp = READ_ONCE_NOCHECK(frame->bp);
		state->ip = READ_ONCE_NOCHECK(frame->ret_addr);
		state->signal = (void *)state->ip == ret_from_fork_asm;
	}

	if (get_stack_info((unsigned long *)state->sp, state->task,
			   &state->stack_info, &state->stack_mask)) {
		void *next_page = (void *)PAGE_ALIGN((unsigned long)state->sp);

		state->error = true;
		if (get_stack_info(next_page, state->task, &state->stack_info,
				   &state->stack_mask))
			return;
	}

	if (regs) {
		unwind_next_frame(state);
		return;
	}

	while (!unwind_done(state) &&
	       (!on_stack(&state->stack_info, first_frame, sizeof(long)) ||
		state->sp <= (unsigned long)first_frame))
		unwind_next_frame(state);

	return;

err:
	state->error = true;
the_end:
	state->stack_info.type = STACK_TYPE_UNKNOWN;
}
EXPORT_SYMBOL_GPL(__unwind_start);
