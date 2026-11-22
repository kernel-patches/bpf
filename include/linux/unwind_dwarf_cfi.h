/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UNWIND_DWARF_CFI_H
#define _LINUX_UNWIND_DWARF_CFI_H

#include <linux/types.h>

/*
 * Minimal DWARF Call Frame Information (CFI) unwinder subset.
 *
 * Evaluates a strictly bounded, non-Turing-complete subset of .eh_frame and
 * .eh_frame_hdr tables matching SFrame's stack-unwinding state model (plus
 * fixed-pattern DRAP stack-realignment and signal-frame expressions):
 *  - Advances PC monotonically through a single FDE (no backward jumps)
 *  - Tracks CFA = (SP | FP | scratch) + cfa_off or *(FP/SP + cfa_off)
 *  - Tracks stack save offsets for FP and RA (ignoring callee-saved GPR spills)
 *  - Rejects general DWARF expressions, register-to-register rules on SP/FP/RA,
 *    and DW_EH_PE_indirect pointer dereferences.
 */

/* Hard safety bounds enforced on CIE/FDE lengths, offsets, and state stack */
#define DWARF_CFI_MAX_CIE_LEN		128U
#define DWARF_CFI_MAX_FDE_LEN		4096U
#define DWARF_CFI_MAX_CIE_DELTA		(64U * 1024U * 1024U)
#define DWARF_CFI_MAX_FDE_COUNT		(4U * 1024U * 1024U)
#define DWARF_CFI_MAX_STATE_STACK	4U

/**
 * enum dwarf_cfi_base - Base register or addressing mode for computing the CFA
 * @DWARF_CFI_BASE_UNDEFINED: CFA rule has not been established yet.
 * @DWARF_CFI_BASE_SP: CFA = stack pointer + cfa_off.
 * @DWARF_CFI_BASE_FP: CFA = frame pointer + cfa_off.
 * @DWARF_CFI_BASE_FP_INDIRECT: DRAP stack realignment: CFA = *(FP + cfa_off).
 * @DWARF_CFI_BASE_SP_INDIRECT: Signal trampoline frame: CFA = *(SP + cfa_off).
 * @DWARF_CFI_BASE_REG: Transient prologue/epilogue scratch register:
 *                      CFA = reg(cfa_reg) + cfa_off.
 */
enum dwarf_cfi_base {
	DWARF_CFI_BASE_UNDEFINED = 0,
	DWARF_CFI_BASE_SP,
	DWARF_CFI_BASE_FP,
	DWARF_CFI_BASE_FP_INDIRECT,
	DWARF_CFI_BASE_SP_INDIRECT,
	DWARF_CFI_BASE_REG,
};

/**
 * enum dwarf_cfi_rule - Recovery rule for the caller's FP or return address
 * @DWARF_CFI_RULE_SAME: Register retains its value from the current frame
 *                       (e.g. leaf function link register or unmodified FP).
 * @DWARF_CFI_RULE_OFFSET: Saved on the stack at *(CFA + off).
 * @DWARF_CFI_RULE_FP_OFFSET: Saved relative to FP at *(FP + off) (DRAP frame).
 * @DWARF_CFI_RULE_SP_OFFSET: Saved relative to SP at *(SP + off) (sigframe).
 * @DWARF_CFI_RULE_UNDEFINED: Explicitly undefined (DW_CFA_undefined); marks
 *                            the bottom of a stack (e.g. _start or clone).
 */
enum dwarf_cfi_rule {
	DWARF_CFI_RULE_SAME = 0,
	DWARF_CFI_RULE_OFFSET,
	DWARF_CFI_RULE_FP_OFFSET,
	DWARF_CFI_RULE_SP_OFFSET,
	DWARF_CFI_RULE_UNDEFINED,
};

/**
 * struct dwarf_cfi_arch - Architecture DWARF register numbers and word size
 * @ws: Target address/word size in bytes (4 or 8).
 * @sp_reg: DWARF register number for the stack pointer.
 * @fp_reg: DWARF register number for the frame pointer.
 * @ra_reg: Default DWARF return-address column number.
 */
struct dwarf_cfi_arch {
	u8 ws;
	u8 sp_reg;
	u8 fp_reg;
	u8 ra_reg;
};

/**
 * struct dwarf_cfi_row - Evaluated Minimal DWARF unwind state at a target PC
 * @cfa_off: Byte offset added to the CFA base register before or as the CFA.
 * @fp_off: Byte offset used to load the saved FP when @fp_rule is an offset.
 * @ra_off: Byte offset used to load the saved RA when @ra_rule is an offset.
 * @cfa_base: CFA computation mode (&enum dwarf_cfi_base).
 * @cfa_reg: DWARF register number when @cfa_base is %DWARF_CFI_BASE_REG.
 * @fp_rule: Recovery rule for the frame pointer (&enum dwarf_cfi_rule).
 * @ra_rule: Recovery rule for the return address (&enum dwarf_cfi_rule).
 * @signal: True if the CIE carries the 'S' signal/interrupt frame augmentation,
 *          indicating that the saved PC points directly to the interrupted
 *          instruction rather than after a call instruction.
 * @ra_signed: True on AArch64 when DW_CFA_AARCH64_negate_ra_state indicates
 *             that the saved return address carries a PAC signature.
 */
struct dwarf_cfi_row {
	s32 cfa_off;
	s32 fp_off;
	s32 ra_off;
	u8 cfa_base;
	u8 cfa_reg;
	u8 fp_rule;
	u8 ra_rule;
	bool signal;
	bool ra_signed;
};

/**
 * struct eh_frame_hdr_entry - Binary-search index entry for an FDE
 * @start_off: Signed 32-bit offset from the table base (or entry field) to the
 *             FDE's initial PC location.
 * @fde_off: Signed 32-bit offset from the table base (or entry field) to the
 *           start of the FDE record in .eh_frame.
 */
struct eh_frame_hdr_entry {
	s32 start_off;
	s32 fde_off;
};

#ifdef CONFIG_UNWIND_DWARF_CFI

extern const u8 __start_eh_frame_hdr[];
extern const u8 __stop_eh_frame_hdr[];
extern const u8 __start_eh_frame[];
extern const u8 __stop_eh_frame[];

int dwarf_cfi_eval_fde_kmem(const u8 *fde, const u8 *eh_start,
			    const u8 *eh_end, unsigned long pc,
			    const struct dwarf_cfi_arch *arch,
			    struct dwarf_cfi_row *out_row);

int dwarf_cfi_unwind_eh_frame_hdr(const u8 *hdr, size_t hdr_size,
				  const u8 *eh_start, const u8 *eh_end,
				  unsigned long pc,
				  const struct dwarf_cfi_arch *arch,
				  struct dwarf_cfi_row *out_row);

int dwarf_cfi_scan_eh_frame_kmem(const u8 *eh_start, size_t eh_size,
				 const struct dwarf_cfi_arch *arch,
				 unsigned long base_addr,
				 struct eh_frame_hdr_entry *entries,
				 unsigned int max_entries,
				 unsigned int *out_count);

int dwarf_cfi_unwind_user_eh_frame_hdr(unsigned long hdr_uaddr,
				       size_t hdr_size, unsigned long pc,
				       const struct dwarf_cfi_arch *arch,
				       struct dwarf_cfi_row *out_row);

#if defined(CONFIG_UNWINDER_DWARF_CFI) && defined(CONFIG_MODULES)
/**
 * struct mod_dwarf_cfi_index - Sorted FDE lookup table for a loadable module
 * @num_fdes: Number of sorted FDE index entries in @entries.
 * @eh_frame: Pointer to the module's in-memory SHF_ALLOC .eh_frame section;
 *            also serves as the base address for @entries offsets.
 * @eh_frame_size: Size in bytes of the module's .eh_frame section.
 * @entries: Sorted binary-search table mapping PCs to module FDEs.
 */
struct mod_dwarf_cfi_index {
	unsigned int num_fdes;
	const u8 *eh_frame;
	size_t eh_frame_size;
	struct eh_frame_hdr_entry entries[] __counted_by(num_fdes);
};

struct mod_dwarf_cfi_index *dwarf_cfi_mod_alloc(const void *eh_frame,
						size_t eh_frame_size,
						const struct dwarf_cfi_arch *arch);
void dwarf_cfi_mod_free_rcu(struct mod_dwarf_cfi_index *idx);
int dwarf_cfi_mod_eval(const struct mod_dwarf_cfi_index *idx, unsigned long ip,
		       const struct dwarf_cfi_arch *arch,
		       struct dwarf_cfi_row *out_row);
#endif

#endif /* CONFIG_UNWIND_DWARF_CFI */

#endif /* _LINUX_UNWIND_DWARF_CFI_H */
