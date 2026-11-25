// SPDX-License-Identifier: GPL-2.0
/*
 * Generic interfaces for unwinding user space.
 */
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/unwind_user.h>
#include <linux/uaccess.h>

#define for_each_user_frame(state) \
	for (unwind_user_start(state); !(state)->done; unwind_user_next(state))

/**
 * get_user_word() - Read a native or compat-sized word from the user stack
 * @word: Output zero-extended word value.
 * @base: Base user virtual address.
 * @off: Signed byte offset from @base.
 * @ws: Word size in bytes (4 for compat 32-bit tasks, sizeof(long) otherwise).
 *
 * Return: 0 on success, or -EFAULT if the user memory access faults.
 */
static inline int
get_user_word(unsigned long *word, unsigned long base, int off, unsigned int ws)
{
	unsigned long __user *addr = (void __user *)base + off;

#ifdef CONFIG_COMPAT
	if (ws == sizeof(int)) {
		unsigned int data;
		int ret = get_user(data, (unsigned int __user *)addr);

		*word = data;
		return ret;
	}
#endif
	return get_user(*word, addr);
}

/**
 * unwind_user_next_common() - Apply an evaluated &struct unwind_user_frame rule
 * @state: Current user unwind state to advance to the caller frame.
 * @frame: Frame CFA, SP, RA, and FP recovery rule.
 * @signal: True if @frame unwinds a signal trampoline (allowing bounded stack
 *          switching across alternate signal stacks).
 *
 * Computes the caller's CFA, validates alignment and monotonic stack progress,
 * reads and strips PAC bits from the return address, optionally recovers the
 * saved frame pointer and stack pointer, and updates @state.
 *
 * Return: 0 on success, -ENOENT if the recovered return address is 0 (marking
 * @state->done), or -EINVAL on invalid alignment, stack regression, or fault.
 */
static int unwind_user_next_common(struct unwind_user_state *state,
				   const struct unwind_user_frame *frame,
				   bool signal)
{
	unsigned long old_sp = state->sp;
	unsigned long cfa, new_sp, fp, ra;

	if (signal && state->nr_signals >= UNWIND_USER_MAX_SIGNALS)
		return -EINVAL;

	/* Get the Canonical Frame Address (CFA) */
	if (frame->use_fp) {
		if (!signal && state->fp < state->sp)
			return -EINVAL;
		cfa = state->fp;
	} else {
		if (!state->sp_valid)
			return -EINVAL;
		cfa = state->sp;
	}
	cfa += frame->cfa_off;
	if (frame->cfa_indirect && get_user_word(&cfa, cfa, /*off=*/0, state->ws))
		return -EINVAL;

	/* Make sure that stack is not going in wrong direction */
	if (frame->ra_from_reg) {
		if (!state->ra_valid || (!signal && cfa < state->sp))
			return -EINVAL;
	} else if (!signal && cfa <= state->sp) {
		return -EINVAL;
	}

	/* Make sure that the address is word aligned */
	if (cfa & (state->ws - 1))
		return -EINVAL;

	/* Get the Return Address (RA) */
	if (frame->ra_from_reg) {
		ra = state->ra;
	} else if (get_user_word(&ra, frame->ra_from_sp ? old_sp : cfa,
				 frame->ra_off, state->ws)) {
		return -EINVAL;
	}
	ra = unwind_user_strip_pac(ra, frame->ra_signed);
	if (!ra) {
		state->done = true;
		return -ENOENT;
	}

	/* Get the Frame Pointer (FP) */
	if (frame->fp_from_fp) {
		if (get_user_word(&fp, state->fp, frame->fp_off, state->ws))
			return -EINVAL;
	} else if (frame->fp_from_sp) {
		if (get_user_word(&fp, old_sp, frame->fp_off, state->ws))
			return -EINVAL;
	} else if (frame->fp_off) {
		if (get_user_word(&fp, cfa, frame->fp_off, state->ws))
			return -EINVAL;
	}

	if (frame->sp_from_cfa) {
		if (get_user_word(&new_sp, cfa, frame->sp_off, state->ws))
			return -EINVAL;
		if (!signal && new_sp <= state->sp)
			return -EINVAL;
	} else {
		new_sp = cfa;
	}

	state->ip = ra;
	state->sp = new_sp;
	if (frame->fp_from_fp || frame->fp_from_sp || frame->fp_off)
		state->fp = fp;
	if (signal)
		state->nr_signals++;
	state->signal = signal;
	state->ra_valid = false;
	state->topmost = false;
	return 0;
}

/**
 * unwind_user_next_fp() - Step one user frame using architectural frame records
 * @state: Current user unwind state.
 *
 * Return: 0 on success, or a negative errno from unwind_user_next_common().
 */
static int unwind_user_next_fp(struct unwind_user_state *state)
{
	struct pt_regs *regs = task_pt_regs(current);
	int ret;

	if (state->topmost && unwind_user_at_function_start(regs)) {
		const struct unwind_user_frame fp_entry_frame = {
			ARCH_INIT_USER_FP_ENTRY_FRAME(state->ws)
		};

		ret = unwind_user_next_common(state, &fp_entry_frame,
					      /*signal=*/false);
		if (!ret)
			state->sp_valid = true;
		return ret;
	}

	const struct unwind_user_frame fp_frame = {
		ARCH_INIT_USER_FP_FRAME(state->ws)
	};

	ret = unwind_user_next_common(state, &fp_frame, /*signal=*/false);
	if (!ret)
		state->sp_valid = unwind_user_fp_sets_sp();
	return ret;
}

/**
 * unwind_user_next() - Advance @state to the next outer user-space stack frame
 * @state: Current user unwind state.
 *
 * Checks architectural signal-trampoline unwinding first, then attempts each
 * enabled method in @state->available_types in priority order (Minimal DWARF
 * CFI first, falling back per frame to frame pointers when an executable
 * mapping such as JIT code lacks .eh_frame_hdr).
 *
 * Return: 0 on success, or -EINVAL when no unwind method succeeds or the walk
 * has reached the bottom of the stack (setting @state->done).
 */
static int unwind_user_next(struct unwind_user_state *state)
{
	unsigned long iter_mask = state->available_types;
	unsigned int bit;

	if (state->done)
		return -EINVAL;

	if (state->nr_signals < UNWIND_USER_MAX_SIGNALS &&
	    unwind_user_sigreturn(state)) {
		state->sp_valid = true;
		state->nr_signals++;
		return 0;
	}

	for_each_set_bit(bit, &iter_mask, NR_UNWIND_USER_TYPE_BITS) {
		enum unwind_user_type type = BIT(bit);

		state->current_type = type;
		switch (type) {
		case UNWIND_USER_TYPE_CFI: {
			struct unwind_user_frame frame;
			bool signal = false;

			if (!unwind_user_next_cfi(state, &frame, &signal) &&
			    !unwind_user_next_common(state, &frame, signal)) {
				state->sp_valid = true;
				return 0;
			}
			if (state->done)
				break;
			continue;
		}
		case UNWIND_USER_TYPE_FP:
			if (!unwind_user_next_fp(state))
				return 0;
			continue;
		default:
			WARN_ONCE(1, "Undefined unwind bit %d", bit);
			break;
		}
		break;
	}

	/* No successful unwind method. */
	state->current_type = UNWIND_USER_TYPE_NONE;
	state->done = true;
	return -EINVAL;
}

/**
 * unwind_user_start() - Initialize user-space stack unwinding from current task
 * @state: Unwind state structure to initialize.
 *
 * Populates @state from task_pt_regs(current) if the current task is a user
 * task with valid user-mode registers.
 *
 * Return: 0 on success, or -EINVAL if current is a kernel thread, not in user
 * mode, or running in an unsupported execution mode (e.g. x86 VM86).
 */
static int unwind_user_start(struct unwind_user_state *state)
{
	struct pt_regs *regs = task_pt_regs(current);

	memset(state, 0, sizeof(*state));

	if ((current->flags & PF_KTHREAD) || !user_mode(regs)) {
		state->done = true;
		return -EINVAL;
	}

	if (IS_ENABLED(CONFIG_HAVE_UNWIND_USER_CFI))
		state->available_types |= UNWIND_USER_TYPE_CFI;
	if (IS_ENABLED(CONFIG_HAVE_UNWIND_USER_FP))
		state->available_types |= UNWIND_USER_TYPE_FP;

	state->ip = instruction_pointer(regs);
	state->sp = user_stack_pointer(regs);
	state->fp = unwind_user_frame_pointer(regs);
	state->ra_valid = unwind_user_link_register(regs, &state->ra);
	state->ws = unwind_user_word_size(regs);
	if (!state->ws) {
		state->done = true;
		return -EINVAL;
	}
	state->sp_valid = true;
	state->topmost = true;

	return 0;
}

/**
 * unwind_user() - Capture a user-space stack trace for the current task
 * @trace: Output stack trace descriptor with caller-allocated @trace->entries.
 * @max_entries: Maximum number of instruction pointers to store in @trace.
 *
 * Must be called in sleepable task context (e.g. syscall return / task_work
 * deferred unwinding) because user stack and ELF .eh_frame_hdr reads may fault.
 *
 * Return: 0 on success (including 0 entries for kernel threads), or -EINVAL if
 * @max_entries is 0.
 */
int unwind_user(struct unwind_stacktrace *trace, unsigned int max_entries)
{
	struct unwind_user_state state;

	trace->nr = 0;

	if (!max_entries)
		return -EINVAL;

	if (current->flags & PF_KTHREAD)
		return 0;

	for_each_user_frame(&state) {
		trace->entries[trace->nr++] = state.ip;
		if (trace->nr >= max_entries)
			break;
	}

	return 0;
}
