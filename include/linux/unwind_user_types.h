/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UNWIND_USER_TYPES_H
#define _LINUX_UNWIND_USER_TYPES_H

#include <linux/types.h>

/**
 * enum unwind_user_type_bits - Priority bit indices for user-space unwinders
 * @UNWIND_USER_TYPE_CFI_BIT: Bit index for Minimal DWARF CFI (.eh_frame_hdr).
 * @UNWIND_USER_TYPE_FP_BIT: Bit index for architectural frame-pointer chains.
 * @NR_UNWIND_USER_TYPE_BITS: Total number of user-space unwind method bits.
 *
 * Listed in priority order: lower bit indices are attempted first on each
 * frame when enabled in &unwind_user_state.available_types.
 */
enum unwind_user_type_bits {
	UNWIND_USER_TYPE_CFI_BIT =		0,
	UNWIND_USER_TYPE_FP_BIT =		1,

	NR_UNWIND_USER_TYPE_BITS,
};

/**
 * enum unwind_user_type - Bitmask values identifying a user-space unwind method
 * @UNWIND_USER_TYPE_NONE: No active unwind method (initial or terminal state).
 * @UNWIND_USER_TYPE_CFI: Unwind using Minimal DWARF CFI via PT_GNU_EH_FRAME.
 * @UNWIND_USER_TYPE_FP: Unwind using architectural frame-pointer records.
 */
enum unwind_user_type {
	UNWIND_USER_TYPE_NONE =			0,
	UNWIND_USER_TYPE_CFI =			BIT(UNWIND_USER_TYPE_CFI_BIT),
	UNWIND_USER_TYPE_FP =			BIT(UNWIND_USER_TYPE_FP_BIT),
};

/**
 * struct unwind_stacktrace - Captured user-space callchain buffer
 * @nr: Number of instruction pointers stored in @entries.
 * @entries: Caller-allocated array of user instruction pointers.
 */
struct unwind_stacktrace {
	unsigned int	nr;
	unsigned long	*entries;
};

/**
 * struct unwind_user_frame - Evaluated unwind rule for stepping one user frame
 * @cfa_off: Byte offset added to FP (when @use_fp is true) or SP to form CFA.
 * @sp_off: Byte offset from CFA to saved caller SP when @sp_from_cfa is true.
 * @ra_off: Byte offset from CFA (or SP when @ra_from_sp is true) to saved RA.
 * @fp_off: Byte offset from CFA, FP, or SP to saved caller FP (0 if unchanged,
 *          unless @fp_from_fp or @fp_from_sp is set).
 * @use_fp: True if the CFA base register is FP rather than SP.
 * @cfa_indirect: True if the computed CFA address must be dereferenced once in
 *                user memory (DRAP or signal trampoline frame).
 * @sp_from_cfa: True if saved SP is located at *(cfa + @sp_off) (e.g. vdso32
 *               sigreturn frame where CFA points at sigcontext).
 * @fp_from_fp: True if saved FP is located at *(state->fp + @fp_off).
 * @fp_from_sp: True if saved FP is located at *(old_sp + @fp_off).
 * @ra_from_sp: True if saved RA is located at *(old_sp + @ra_off).
 * @ra_from_reg: True if RA is still in @state->ra rather than on the stack.
 * @ra_signed: True if the recovered RA carries an AArch64 PAC signature.
 */
struct unwind_user_frame {
	s32 cfa_off;
	s32 sp_off;
	s32 ra_off;
	s32 fp_off;
	bool use_fp;
	bool cfa_indirect;
	bool sp_from_cfa;
	bool fp_from_fp;
	bool fp_from_sp;
	bool ra_from_sp;
	bool ra_from_reg;
	bool ra_signed;
};

/**
 * struct unwind_user_cfi_cache - Per-walk cache entry mapping a VMA to EH_FRAME
 * @vma_start: Start virtual address of the cached executable VMA.
 * @vma_end: End virtual address (exclusive) of the cached executable VMA.
 * @eh_hdr_uaddr: User virtual address of PT_GNU_EH_FRAME (0 for negative cache
 *                entries when an executable VMA has no PT_GNU_EH_FRAME).
 * @eh_hdr_size: Size in bytes of the PT_GNU_EH_FRAME segment.
 * @valid: True if this cache slot holds a populated entry.
 */
struct unwind_user_cfi_cache {
	unsigned long	vma_start;
	unsigned long	vma_end;
	unsigned long	eh_hdr_uaddr;
	size_t		eh_hdr_size;
	bool		valid;
};

#define UNWIND_USER_MAX_SIGNALS	4U

/**
 * struct unwind_user_state - Iteration state for a user-space stack walk
 * @ip: Current frame's user instruction pointer.
 * @sp: Current frame's user stack pointer.
 * @fp: Current frame's user frame pointer.
 * @ra: Link register value for leaf/topmost frames when @ra_valid is true.
 * @ws: User word size in bytes (4 for compat 32-bit tasks, 8 for 64-bit tasks).
 * @current_type: Unwind method used for the current step.
 * @available_types: Bitmask of &enum unwind_user_type methods available.
 * @cfi_cache_next: Round-robin replacement cursor into @cfi_cache.
 * @cfi_cache: Small per-walk cache of executable VMA PT_GNU_EH_FRAME lookups.
 * @nr_signals: Number of signal frames unwound so far during this walk.
 * @ra_valid: True if @ra holds a live link register value for this frame.
 * @sp_valid: True if @sp holds the exact stack pointer of the current frame;
 *            false after an architectural FP step that only establishes a lower
 *            bound on the caller's SP.
 * @signal: True if the current frame was entered from a signal trampoline, so
 *          @ip points directly at the interrupted instruction rather than
 *          immediately after a call instruction.
 * @topmost: True when unwinding the innermost interrupted user frame.
 * @done: True once the stack walk has reached the bottom or terminated.
 */
struct unwind_user_state {
	unsigned long				ip;
	unsigned long				sp;
	unsigned long				fp;
	unsigned long				ra;
	unsigned int				ws;
	enum unwind_user_type			current_type;
	unsigned int				available_types;
	unsigned int				cfi_cache_next;
	struct unwind_user_cfi_cache		cfi_cache[4];
	unsigned int				nr_signals;
	bool					ra_valid;
	bool					sp_valid;
	bool					signal;
	bool					topmost;
	bool					done;
};

#endif /* _LINUX_UNWIND_USER_TYPES_H */
