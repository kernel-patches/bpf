// SPDX-License-Identifier: GPL-2.0-only
/*
 * Minimal DWARF Call Frame Information (CFI) bytecode interpreter.
 *
 * Implements a strictly bounded subset of .eh_frame / .eh_frame_hdr matching
 * SFrame's expressiveness: PC advancement, SP/FP-based CFA offsets, and FP/RA
 * stack save offsets. Callee-saved GPR spills are decoded and ignored; DWARF
 * expressions and indirect pointer encodings are rejected.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/nospec.h>
#include <linux/overflow.h>
#if defined(CONFIG_UNWINDER_DWARF_CFI) && defined(CONFIG_MODULES)
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/sort.h>
#endif
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>
#include <linux/unwind_dwarf_cfi.h>

/* DWARF Call Frame Instruction opcodes */
#define DW_CFA_nop				0x00
#define DW_CFA_set_loc				0x01
#define DW_CFA_advance_loc1			0x02
#define DW_CFA_advance_loc2			0x03
#define DW_CFA_advance_loc4			0x04
#define DW_CFA_offset_extended			0x05
#define DW_CFA_restore_extended			0x06
#define DW_CFA_undefined			0x07
#define DW_CFA_same_value			0x08
#define DW_CFA_register				0x09
#define DW_CFA_remember_state			0x0a
#define DW_CFA_restore_state			0x0b
#define DW_CFA_def_cfa				0x0c
#define DW_CFA_def_cfa_register			0x0d
#define DW_CFA_def_cfa_offset			0x0e
#define DW_CFA_def_cfa_expression		0x0f
#define DW_CFA_expression			0x10
#define DW_CFA_offset_extended_sf		0x11
#define DW_CFA_def_cfa_sf			0x12
#define DW_CFA_def_cfa_offset_sf		0x13
#define DW_CFA_val_offset			0x14
#define DW_CFA_val_offset_sf			0x15
#define DW_CFA_val_expression			0x16
#define DW_CFA_AARCH64_negate_ra_state		0x2d
#define DW_CFA_GNU_args_size			0x2e
#define DW_CFA_GNU_negative_offset_extended	0x2f

/* Fixed DWARF expression opcodes for DRAP stack-realigned frames */
#define DW_OP_deref				0x06
#define DW_OP_breg0				0x70

/* Exception Header Pointer Encoding formats */
#define DW_EH_PE_omit		0xff
#define DW_EH_PE_FORM		0x0f
#define DW_EH_PE_absptr		0x00
#define DW_EH_PE_uleb128	0x01
#define DW_EH_PE_udata2		0x02
#define DW_EH_PE_udata4		0x03
#define DW_EH_PE_udata8		0x04
#define DW_EH_PE_sleb128	0x09
#define DW_EH_PE_sdata2		0x0a
#define DW_EH_PE_sdata4		0x0b
#define DW_EH_PE_sdata8		0x0c

#define DW_EH_PE_ADJUST		0x70
#define DW_EH_PE_abs		0x00
#define DW_EH_PE_pcrel		0x10
#define DW_EH_PE_datarel	0x30
#define DW_EH_PE_indirect	0x80

#define DWARF_CFI_WIN_SIZE	128U

/**
 * struct dwarf_cfi_cie - Parsed Common Information Entry (CIE) attributes
 * @code_align: Multiplier applied to DW_CFA_advance_loc* deltas.
 * @data_align: Signed multiplier applied to factored register/CFA offsets.
 * @ra_reg: DWARF register column holding the return address for this CIE.
 * @fde_enc: DW_EH_PE_* pointer encoding for FDE initial_location and range.
 * @has_z: True if the CIE augmentation string starts with 'z' (length-prefixed
 *         augmentation data present in both CIE and FDEs).
 * @signal: True if the CIE augmentation string includes 'S' (signal/interrupt
 *          frame where PC is not decremented before FDE lookup).
 */
struct dwarf_cfi_cie {
	u32 code_align;
	s32 data_align;
	u8 ra_reg;
	u8 fde_enc;
	bool has_z;
	bool signal;
};

/**
 * struct dwarf_cfi_stream - Bounded byte reader over kernel or user memory
 * @buf: Active byte buffer (direct kernel pointer or @scratch window).
 * @pos: Current byte offset within @buf.
 * @win_len: Number of valid bytes currently available in @buf.
 * @rem_after_win: Remaining bytes in user memory after the current window.
 * @next_uaddr: Next user virtual address to copy when refilling @scratch.
 * @cur_base_addr: Virtual address corresponding to @buf[0] (used for
 *                 DW_EH_PE_pcrel pointer decoding).
 * @scratch: Caller-supplied %DWARF_CFI_WIN_SIZE stack buffer for user streams.
 * @is_user: False for zero-copy kernel memory, true for windowed user memory.
 */
struct dwarf_cfi_stream {
	const u8 *buf;
	size_t pos;
	size_t win_len;
	size_t rem_after_win;
	unsigned long next_uaddr;
	unsigned long cur_base_addr;
	u8 *scratch;
	bool is_user;
};

static __always_inline void cfi_stream_init_kmem(struct dwarf_cfi_stream *s,
						 const u8 *ptr, size_t len)
{
	s->buf = ptr;
	s->pos = 0;
	s->win_len = len;
	s->rem_after_win = 0;
	s->next_uaddr = 0;
	s->cur_base_addr = (unsigned long)ptr;
	s->scratch = NULL;
	s->is_user = false;
}

static int cfi_stream_init_user(struct dwarf_cfi_stream *s, unsigned long uaddr,
				size_t len, u8 *scratch)
{
	size_t chunk = min_t(size_t, len, DWARF_CFI_WIN_SIZE);

	if (chunk && copy_from_user(scratch, (const void __user *)uaddr, chunk))
		return -EFAULT;

	s->buf = scratch;
	s->pos = 0;
	s->win_len = chunk;
	s->rem_after_win = len - chunk;
	s->next_uaddr = uaddr + chunk;
	s->cur_base_addr = uaddr;
	s->scratch = scratch;
	s->is_user = true;
	return 0;
}

static __always_inline bool cfi_stream_empty(const struct dwarf_cfi_stream *s)
{
	return s->pos >= s->win_len && (!s->is_user || s->rem_after_win == 0);
}

static __always_inline unsigned long
cfi_stream_addr(const struct dwarf_cfi_stream *s)
{
	return s->cur_base_addr + s->pos;
}

static noinline int cfi_stream_refill(struct dwarf_cfi_stream *s)
{
	size_t chunk;

	if (!s->is_user || !s->rem_after_win || !s->scratch)
		return -EINVAL;

	chunk = min_t(size_t, s->rem_after_win, DWARF_CFI_WIN_SIZE);
	if (copy_from_user(s->scratch, (const void __user *)s->next_uaddr, chunk))
		return -EFAULT;

	s->cur_base_addr = s->next_uaddr;
	s->next_uaddr += chunk;
	s->rem_after_win -= chunk;
	s->pos = 0;
	s->win_len = chunk;
	return 0;
}

static __always_inline int cfi_read_u8(struct dwarf_cfi_stream *s, u8 *val)
{
	size_t idx;

	if (unlikely(s->pos >= s->win_len)) {
		int err;

		if (!s->is_user)
			return -EINVAL;
		err = cfi_stream_refill(s);
		if (err)
			return err;
	}
	/*
	 * Prevent Spectre v1 OOB reads past the 128-byte user stack window if
	 * a preceding bounds check in cfi_skip_bytes() or here mispredicts.
	 */
	idx = s->is_user ? array_index_nospec(s->pos, DWARF_CFI_WIN_SIZE) :
			   s->pos;
	s->pos = idx + 1;
	*val = s->buf[idx];
	return 0;
}

static __always_inline int cfi_read_bytes(struct dwarf_cfi_stream *s,
					  void *dst, size_t n)
{
	u8 *out = dst;

	if (likely(n <= s->win_len && s->pos <= s->win_len - n)) {
		size_t idx = s->is_user ?
			array_index_nospec(s->pos, DWARF_CFI_WIN_SIZE - n + 1) :
			s->pos;

		memcpy(out, s->buf + idx, n);
		s->pos = idx + n;
		return 0;
	}

	if (!s->is_user)
		return -EINVAL;

	while (n--) {
		int err = cfi_read_u8(s, out++);

		if (err)
			return err;
	}
	return 0;
}

static int cfi_skip_bytes(struct dwarf_cfi_stream *s, size_t n)
{
	size_t avail = (s->win_len - s->pos) + s->rem_after_win;

	if (n > avail)
		return -EINVAL;

	while (n > 0) {
		size_t in_win = s->win_len - s->pos;

		if (n <= in_win) {
			barrier_nospec();
			s->pos += n;
			return 0;
		}
		if (!s->is_user)
			return -EINVAL;
		n -= in_win;
		s->pos = s->win_len;
		if (n > 0) {
			int err = cfi_stream_refill(s);

			if (err)
				return err;
		}
	}
	return 0;
}

static noinline int cfi_read_uleb128_u32_slow(struct dwarf_cfi_stream *s,
					      u32 val, u32 *out)
{
	unsigned int shift = 7;

	for (;;) {
		u8 b;
		int err = cfi_read_u8(s, &b);

		if (err)
			return err;

		if (shift == 28 && ((b & 0x7f) > 0x0f || (b & 0x80)))
			return -EOVERFLOW;

		val |= (u32)(b & 0x7f) << shift;
		if (!(b & 0x80)) {
			*out = val;
			return 0;
		}
		shift += 7;
	}
}

static __always_inline int cfi_read_uleb128_u32(struct dwarf_cfi_stream *s,
						u32 *out)
{
	u8 b;
	int err = cfi_read_u8(s, &b);

	if (unlikely(err))
		return err;
	if (likely(!(b & 0x80))) {
		*out = b;
		return 0;
	}
	return cfi_read_uleb128_u32_slow(s, b & 0x7f, out);
}

static noinline int cfi_read_sleb128_s32_slow(struct dwarf_cfi_stream *s,
					      u32 val, s32 *out)
{
	unsigned int shift = 7;

	for (;;) {
		u8 b;
		int err = cfi_read_u8(s, &b);

		if (err)
			return err;

		if (shift == 28) {
			u8 top = b & 0x78;

			if ((b & 0x80) || (top != 0x00 && top != 0x78))
				return -EOVERFLOW;
		}

		val |= (u32)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80)) {
			if (shift < 32 && (b & 0x40))
				val |= ~0U << shift;
			*out = (s32)val;
			return 0;
		}
	}
}

static __always_inline int cfi_read_sleb128_s32(struct dwarf_cfi_stream *s,
						s32 *out)
{
	u8 b;
	int err = cfi_read_u8(s, &b);

	if (unlikely(err))
		return err;
	if (likely(!(b & 0x80))) {
		*out = (b & 0x40) ? (s32)((u32)b | ~0x7fU) : (s32)b;
		return 0;
	}
	return cfi_read_sleb128_s32_slow(s, b & 0x7f, out);
}

static int cfi_encoded_ptr_size(u8 enc, u8 ws)
{
	if (enc == DW_EH_PE_omit)
		return 0;

	switch (enc & DW_EH_PE_FORM) {
	case DW_EH_PE_absptr:
		return ws;
	case DW_EH_PE_udata2:
	case DW_EH_PE_sdata2:
		return 2;
	case DW_EH_PE_udata4:
	case DW_EH_PE_sdata4:
		return 4;
	case DW_EH_PE_udata8:
	case DW_EH_PE_sdata8:
		return 8;
	default:
		return -EINVAL;
	}
}

/**
 * cfi_read_encoded_ptr() - Decode a DW_EH_PE_* pointer from a CFI stream
 * @s: Input byte stream.
 * @enc: DWARF Exception Header pointer encoding byte.
 * @ws: Target word size in bytes (4 or 8).
 * @datarel_base: Base address added when @enc uses DW_EH_PE_datarel.
 * @out: Decoded virtual address (0 when @enc is DW_EH_PE_omit).
 *
 * Decodes fixed-width and LEB128 pointer encodings with abs, pcrel, or datarel
 * adjustments without ever dereferencing memory: any DW_EH_PE_indirect flag is
 * strictly rejected with -EINVAL.
 *
 * Return: 0 on success, -EFAULT on user copy fault, -EOVERFLOW on LEB128
 * overflow, or -EINVAL on unsupported or indirect encodings.
 */
static int cfi_read_encoded_ptr(struct dwarf_cfi_stream *s, u8 enc, u8 ws,
				unsigned long datarel_base, unsigned long *out)
{
	unsigned long field_addr = cfi_stream_addr(s);
	s64 raw = 0;
	u8 buf[8];
	int err;

	if (enc == DW_EH_PE_omit) {
		*out = 0;
		return 0;
	}
	if (enc & DW_EH_PE_indirect)
		return -EINVAL;

	switch (enc & DW_EH_PE_FORM) {
	case DW_EH_PE_absptr:
		err = cfi_read_bytes(s, buf, ws);
		if (err)
			return err;
		raw = (ws == 8) ? (s64)get_unaligned_le64(buf) :
				  (s64)get_unaligned_le32(buf);
		break;
	case DW_EH_PE_udata2:
		err = cfi_read_bytes(s, buf, 2);
		if (err)
			return err;
		raw = get_unaligned_le16(buf);
		break;
	case DW_EH_PE_sdata2:
		err = cfi_read_bytes(s, buf, 2);
		if (err)
			return err;
		raw = (s16)get_unaligned_le16(buf);
		break;
	case DW_EH_PE_udata4:
		err = cfi_read_bytes(s, buf, 4);
		if (err)
			return err;
		raw = get_unaligned_le32(buf);
		break;
	case DW_EH_PE_sdata4:
		err = cfi_read_bytes(s, buf, 4);
		if (err)
			return err;
		raw = (s32)get_unaligned_le32(buf);
		break;
	case DW_EH_PE_udata8:
	case DW_EH_PE_sdata8:
		err = cfi_read_bytes(s, buf, 8);
		if (err)
			return err;
		raw = (s64)get_unaligned_le64(buf);
		break;
	case DW_EH_PE_uleb128: {
		u32 uval;

		err = cfi_read_uleb128_u32(s, &uval);
		if (err)
			return err;
		raw = uval;
		break;
	}
	case DW_EH_PE_sleb128: {
		s32 sval;

		err = cfi_read_sleb128_s32(s, &sval);
		if (err)
			return err;
		raw = sval;
		break;
	}
	default:
		return -EINVAL;
	}

	switch (enc & DW_EH_PE_ADJUST) {
	case DW_EH_PE_abs:
		*out = (unsigned long)raw;
		break;
	case DW_EH_PE_pcrel:
		*out = field_addr + (unsigned long)raw;
		break;
	case DW_EH_PE_datarel:
		*out = datarel_base + (unsigned long)raw;
		break;
	default:
		return -EINVAL;
	}

	if (ws == 4)
		*out = (u32)*out;

	return 0;
}

static __always_inline int cfi_factored_offset(s64 factor_operand,
					       s32 data_align, s32 *out)
{
	s64 prod;

	if (unlikely(check_mul_overflow(factor_operand, (s64)data_align, &prod)))
		return -EOVERFLOW;
	if (unlikely(prod < S32_MIN || prod > S32_MAX))
		return -EOVERFLOW;

	*out = (s32)prod;
	return 0;
}

static __always_inline bool cfi_cfa_is_reg_off(const struct dwarf_cfi_row *row)
{
	return row->cfa_base == DWARF_CFI_BASE_SP ||
	       row->cfa_base == DWARF_CFI_BASE_FP ||
	       row->cfa_base == DWARF_CFI_BASE_REG;
}

static int cfi_set_cfa_reg(u32 reg, const struct dwarf_cfi_arch *arch,
			   struct dwarf_cfi_row *row)
{
	if (reg > U8_MAX)
		return -EINVAL;
	if (reg == arch->sp_reg) {
		row->cfa_base = DWARF_CFI_BASE_SP;
		row->cfa_reg = (u8)reg;
		return 0;
	}
	if (reg == arch->fp_reg) {
		row->cfa_base = DWARF_CFI_BASE_FP;
		row->cfa_reg = (u8)reg;
		return 0;
	}
	/*
	 * Allow transient prologue/epilogue DRAP scratch registers so scanning
	 * reaches the body's FP/FP_INDIRECT state (or recovers from pt_regs).
	 */
	row->cfa_base = DWARF_CFI_BASE_REG;
	row->cfa_reg = (u8)reg;
	return 0;
}

/*
 * Match ONLY the fixed 3-part DRAP / sigreturn CFA indirect pattern:
 *   DW_OP_breg(fp_reg | sp_reg) <sleb128>, DW_OP_deref  =>  CFA = *(reg + off)
 * All other DWARF expressions are rejected.
 */
static int cfi_parse_indirect_cfa_expr(struct dwarf_cfi_stream *s, u32 expr_len,
				       const struct dwarf_cfi_arch *arch,
				       struct dwarf_cfi_row *row)
{
	struct dwarf_cfi_stream es;
	u8 expr_buf[8], op0, op_end;
	enum dwarf_cfi_base base;
	s32 off;
	int err;

	if (expr_len < 3 || expr_len > 7)
		return -EINVAL;
	/* Prevent Spectre v1.1 speculative stack overflow of expr_buf[8] */
	barrier_nospec();

	err = cfi_read_bytes(s, expr_buf, expr_len);
	if (err)
		return err;

	cfi_stream_init_kmem(&es, expr_buf, expr_len - 1);
	err = cfi_read_u8(&es, &op0);
	if (err)
		return err;

	if (arch->fp_reg <= 31 && op0 == (u8)(DW_OP_breg0 + arch->fp_reg))
		base = DWARF_CFI_BASE_FP_INDIRECT;
	else if (arch->sp_reg <= 31 && op0 == (u8)(DW_OP_breg0 + arch->sp_reg))
		base = DWARF_CFI_BASE_SP_INDIRECT;
	else
		return -EINVAL;

	err = cfi_read_sleb128_s32(&es, &off);
	if (err || !cfi_stream_empty(&es))
		return -EINVAL;

	op_end = expr_buf[expr_len - 1];
	if (op_end != DW_OP_deref)
		return -EINVAL;

	row->cfa_base = base;
	row->cfa_off = off;
	return 0;
}

/*
 * Match ONLY the fixed 2-part DRAP / sigreturn register save pattern:
 *   DW_OP_breg(fp_reg | sp_reg) <sleb128>   =>   saved reg at *(FP/SP + off)
 */
static int cfi_parse_reg_expr(struct dwarf_cfi_stream *s, u32 reg, u32 expr_len,
			      const struct dwarf_cfi_arch *arch, u8 ra_reg,
			      struct dwarf_cfi_row *row)
{
	struct dwarf_cfi_stream es;
	u8 expr_buf[8], op0;
	enum dwarf_cfi_rule rule;
	s32 off;
	int err;

	if (expr_len < 2 || expr_len > 6)
		return -EINVAL;
	/* Prevent Spectre v1.1 speculative stack overflow of expr_buf[8] */
	barrier_nospec();

	err = cfi_read_bytes(s, expr_buf, expr_len);
	if (err)
		return err;

	cfi_stream_init_kmem(&es, expr_buf, expr_len);
	err = cfi_read_u8(&es, &op0);
	if (err)
		return err;

	if (arch->fp_reg <= 31 && op0 == (u8)(DW_OP_breg0 + arch->fp_reg))
		rule = DWARF_CFI_RULE_FP_OFFSET;
	else if (arch->sp_reg <= 31 && op0 == (u8)(DW_OP_breg0 + arch->sp_reg))
		rule = DWARF_CFI_RULE_SP_OFFSET;
	else
		return -EINVAL;

	err = cfi_read_sleb128_s32(&es, &off);
	if (err || !cfi_stream_empty(&es))
		return -EINVAL;

	if (reg == arch->fp_reg) {
		row->fp_rule = rule;
		row->fp_off = off;
		return 0;
	}
	if (reg == ra_reg && rule == DWARF_CFI_RULE_SP_OFFSET) {
		row->ra_rule = rule;
		row->ra_off = off;
		return 0;
	}
	if (reg == arch->sp_reg && rule == DWARF_CFI_RULE_SP_OFFSET &&
	    row->cfa_base == DWARF_CFI_BASE_SP_INDIRECT && off == row->cfa_off)
		return 0;

	return -EINVAL;
}

static void cfi_apply_reg_rule(u32 reg, enum dwarf_cfi_rule rule, s32 off,
			       const struct dwarf_cfi_arch *arch, u8 ra_reg,
			       struct dwarf_cfi_row *row)
{
	if (reg == arch->fp_reg) {
		row->fp_rule = rule;
		row->fp_off = off;
	} else if (reg == ra_reg) {
		row->ra_rule = rule;
		row->ra_off = off;
	}
	/* All other general-purpose registers are intentionally ignored. */
}

static void cfi_restore_reg(u32 reg, const struct dwarf_cfi_arch *arch,
			    u8 ra_reg, const struct dwarf_cfi_row *cie_row,
			    struct dwarf_cfi_row *row)
{
	if (reg == arch->fp_reg) {
		row->fp_rule = cie_row->fp_rule;
		row->fp_off = cie_row->fp_off;
	} else if (reg == ra_reg) {
		row->ra_rule = cie_row->ra_rule;
		row->ra_off = cie_row->ra_off;
	}
}

static __always_inline int cfi_advance_pc(unsigned long *loc, u32 delta,
					  u32 code_align)
{
	unsigned long step;

	if (likely(code_align == 1)) {
		if (unlikely(check_add_overflow(*loc, (unsigned long)delta, loc)))
			return -EOVERFLOW;
		return 0;
	}

	if (check_mul_overflow((unsigned long)delta, (unsigned long)code_align, &step) ||
	    check_add_overflow(*loc, step, loc))
		return -EOVERFLOW;
	return 0;
}

/**
 * dwarf_cfi_exec_insns() - Execute Minimal DWARF CFA instructions up to a PC
 * @s: Stream positioned at the start of CIE or FDE CFA instructions.
 * @cie: Parsed CIE attributes providing alignment factors and @ra_reg.
 * @arch: Target architecture DWARF register numbers.
 * @cie_row: Initial CIE unwind row for DW_CFA_restore* (NULL while parsing CIE).
 * @row: In/out unwind row updated in place as instructions execute.
 * @check_pc: True when evaluating an FDE up to @target_pc; false for CIE init.
 * @start_pc: Initial PC of the FDE when @check_pc is true.
 * @target_pc: Target PC at which to stop FDE execution (inclusive).
 *
 * Interprets the strictly bounded Minimal DWARF CFA subset in a single forward
 * pass with a 4-entry state stack for shrink-wrapped functions. Backward PC
 * jumps (DW_CFA_set_loc), register-to-register rules on SP/FP/RA, and general
 * DWARF expressions are rejected.
 *
 * Return: 0 on success, -EFAULT on user stream fault, -EOVERFLOW on arithmetic
 * or LEB128 overflow, or -EINVAL on unsupported or malformed opcodes.
 */
static int dwarf_cfi_exec_insns(struct dwarf_cfi_stream *s,
				const struct dwarf_cfi_cie *cie,
				const struct dwarf_cfi_arch *arch,
				const struct dwarf_cfi_row *cie_row,
				struct dwarf_cfi_row *row,
				bool check_pc, unsigned long start_pc,
				unsigned long target_pc)
{
	struct dwarf_cfi_row state_stack[DWARF_CFI_MAX_STATE_STACK];
	unsigned int stack_depth = 0;
	unsigned long loc = start_pc;

	while (!cfi_stream_empty(s) && (!check_pc || loc <= target_pc)) {
		u8 op, hi, lo;
		u32 reg, uval;
		s32 sval, off;
		int err;

		err = cfi_read_u8(s, &op);
		if (err)
			return err;

		hi = op & 0xc0;
		lo = op & 0x3f;

		if (hi == 0x40) {
			/* DW_CFA_advance_loc */
			err = cfi_advance_pc(&loc, lo, cie->code_align);
			if (err)
				return err;
			continue;
		}
		if (hi == 0x80) {
			/* DW_CFA_offset */
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (lo == arch->fp_reg || lo == cie->ra_reg) {
				err = cfi_factored_offset(uval, cie->data_align, &off);
				if (err)
					return err;
				cfi_apply_reg_rule(lo, DWARF_CFI_RULE_OFFSET,
						   off, arch, cie->ra_reg, row);
			}
			continue;
		}
		if (hi == 0xc0) {
			/* DW_CFA_restore */
			if (cie_row)
				cfi_restore_reg(lo, arch, cie->ra_reg, cie_row, row);
			continue;
		}

		switch (op) {
		case DW_CFA_nop:
			break;

		case DW_CFA_advance_loc1: {
			u8 d8;

			err = cfi_read_u8(s, &d8);
			if (err)
				return err;
			err = cfi_advance_pc(&loc, d8, cie->code_align);
			if (err)
				return err;
			break;
		}

		case DW_CFA_advance_loc2: {
			u8 b2[2];

			err = cfi_read_bytes(s, b2, 2);
			if (err)
				return err;
			err = cfi_advance_pc(&loc, get_unaligned_le16(b2),
					     cie->code_align);
			if (err)
				return err;
			break;
		}

		case DW_CFA_advance_loc4: {
			u8 b4[4];

			err = cfi_read_bytes(s, b4, 4);
			if (err)
				return err;
			err = cfi_advance_pc(&loc, get_unaligned_le32(b4),
					     cie->code_align);
			if (err)
				return err;
			break;
		}

		case DW_CFA_def_cfa:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (uval > (u32)S32_MAX)
				return -EOVERFLOW;
			err = cfi_set_cfa_reg(reg, arch, row);
			if (err)
				return err;
			row->cfa_off = (s32)uval;
			break;

		case DW_CFA_def_cfa_sf:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_sleb128_s32(s, &sval);
			if (err)
				return err;
			err = cfi_factored_offset(sval, cie->data_align, &off);
			if (err)
				return err;
			err = cfi_set_cfa_reg(reg, arch, row);
			if (err)
				return err;
			row->cfa_off = off;
			break;

		case DW_CFA_def_cfa_register:
			if (!cfi_cfa_is_reg_off(row))
				return -EINVAL;
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_set_cfa_reg(reg, arch, row);
			if (err)
				return err;
			break;

		case DW_CFA_def_cfa_offset:
			if (!cfi_cfa_is_reg_off(row))
				return -EINVAL;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (uval > (u32)S32_MAX)
				return -EOVERFLOW;
			row->cfa_off = (s32)uval;
			break;

		case DW_CFA_def_cfa_offset_sf:
			if (!cfi_cfa_is_reg_off(row))
				return -EINVAL;
			err = cfi_read_sleb128_s32(s, &sval);
			if (err)
				return err;
			err = cfi_factored_offset(sval, cie->data_align, &off);
			if (err)
				return err;
			row->cfa_off = off;
			break;

		case DW_CFA_offset_extended:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (reg == arch->fp_reg || reg == cie->ra_reg) {
				err = cfi_factored_offset(uval, cie->data_align, &off);
				if (err)
					return err;
				cfi_apply_reg_rule(reg, DWARF_CFI_RULE_OFFSET,
						   off, arch, cie->ra_reg, row);
			}
			break;

		case DW_CFA_offset_extended_sf:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_sleb128_s32(s, &sval);
			if (err)
				return err;
			if (reg == arch->fp_reg || reg == cie->ra_reg) {
				err = cfi_factored_offset(sval, cie->data_align, &off);
				if (err)
					return err;
				cfi_apply_reg_rule(reg, DWARF_CFI_RULE_OFFSET,
						   off, arch, cie->ra_reg, row);
			}
			break;

		case DW_CFA_GNU_negative_offset_extended:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (reg == arch->fp_reg || reg == cie->ra_reg) {
				err = cfi_factored_offset(-(s64)uval,
							  cie->data_align, &off);
				if (err)
					return err;
				cfi_apply_reg_rule(reg, DWARF_CFI_RULE_OFFSET,
						   off, arch, cie->ra_reg, row);
			}
			break;

		case DW_CFA_restore_extended:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			if (cie_row)
				cfi_restore_reg(reg, arch, cie->ra_reg, cie_row, row);
			break;

		case DW_CFA_undefined:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			cfi_apply_reg_rule(reg, DWARF_CFI_RULE_UNDEFINED,
					   /*off=*/0, arch, cie->ra_reg, row);
			break;

		case DW_CFA_same_value:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			cfi_apply_reg_rule(reg, DWARF_CFI_RULE_SAME, /*off=*/0,
					   arch, cie->ra_reg, row);
			break;

		case DW_CFA_remember_state:
			if (stack_depth >= DWARF_CFI_MAX_STATE_STACK)
				return -EINVAL;
			stack_depth = array_index_nospec(stack_depth,
							 DWARF_CFI_MAX_STATE_STACK);
			state_stack[stack_depth++] = *row;
			break;

		case DW_CFA_restore_state: {
			unsigned int idx;

			if (!stack_depth)
				return -EINVAL;
			idx = array_index_nospec(stack_depth - 1,
						 DWARF_CFI_MAX_STATE_STACK);
			stack_depth = idx;
			*row = state_stack[idx];
			break;
		}

		case DW_CFA_GNU_args_size:
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			break;

		case DW_CFA_AARCH64_negate_ra_state:
			if (arch->ws != 8 || arch->ra_reg != 30)
				return -EINVAL;
			row->ra_signed = !row->ra_signed;
			break;

		case DW_CFA_register:
			/* Ignorable only if targeting an untracked GPR */
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				return -EINVAL;
			break;

		case DW_CFA_val_offset:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				return -EINVAL;
			break;

		case DW_CFA_val_offset_sf:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_sleb128_s32(s, &sval);
			if (err)
				return err;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				return -EINVAL;
			break;

		case DW_CFA_def_cfa_expression:
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			err = cfi_parse_indirect_cfa_expr(s, uval, arch, row);
			if (err)
				return err;
			break;

		case DW_CFA_expression:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (reg == arch->fp_reg || reg == arch->sp_reg ||
			    reg == cie->ra_reg) {
				err = cfi_parse_reg_expr(s, reg, uval, arch,
							 cie->ra_reg, row);
				if (err)
					return err;
				break;
			}
			err = cfi_skip_bytes(s, uval);
			if (err)
				return err;
			break;

		case DW_CFA_val_expression:
			err = cfi_read_uleb128_u32(s, &reg);
			if (err)
				return err;
			err = cfi_read_uleb128_u32(s, &uval);
			if (err)
				return err;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				return -EINVAL;
			err = cfi_skip_bytes(s, uval);
			if (err)
				return err;
			break;

		/*
		 * Strictly rejected: backward PC jumps and unknown opcodes.
		 */
		case DW_CFA_set_loc:
		default:
			return -EINVAL;
		}
	}

	return 0;
}

/**
 * dwarf_cfi_parse_cie() - Parse a CIE header and its initial CFA instructions
 * @s: Bounded stream covering the CIE body (after length and CIE ID fields).
 * @arch: Target architecture DWARF register numbers and word size.
 * @cie: Output parsed CIE attributes.
 * @cie_row: Output initial unwind row established by the CIE's instructions.
 *
 * Supports CIE versions 1, 3, and 4 and 'z' augmentation strings containing
 * 'R', 'L', 'P', 'S', and 'B' (skipping LSDA/personality encodings without
 * dereferencing pointers).
 *
 * Return: 0 on success, -EFAULT on user copy fault, -EOVERFLOW on LEB128
 * overflow, or -EINVAL on unsupported CIE headers or instructions.
 */
static int dwarf_cfi_parse_cie(struct dwarf_cfi_stream *s,
			       const struct dwarf_cfi_arch *arch,
			       struct dwarf_cfi_cie *cie,
			       struct dwarf_cfi_row *cie_row)
{
	char aug[8];
	unsigned int aug_idx = 0;
	u8 version;
	u32 ra_col;
	int err;

	memset(cie, 0, sizeof(*cie));
	cie->fde_enc = DW_EH_PE_absptr;

	err = cfi_read_u8(s, &version);
	if (err)
		return err;
	if (version != 1 && version != 3 && version != 4)
		return -EINVAL;

	/* Read NUL-terminated augmentation string (bounded to 7 chars) */
	for (;;) {
		u8 ch;

		err = cfi_read_u8(s, &ch);
		if (err)
			return err;
		if (ch == '\0') {
			aug[aug_idx] = '\0';
			break;
		}
		if (aug_idx >= sizeof(aug) - 1)
			return -EINVAL;
		aug_idx = array_index_nospec(aug_idx, sizeof(aug) - 1);
		aug[aug_idx++] = (char)ch;
	}

	if (version == 4) {
		u8 addr_sz, seg_sz;

		err = cfi_read_u8(s, &addr_sz);
		if (err)
			return err;
		err = cfi_read_u8(s, &seg_sz);
		if (err)
			return err;
		if (addr_sz != arch->ws || seg_sz != 0)
			return -EINVAL;
	}

	err = cfi_read_uleb128_u32(s, &cie->code_align);
	if (err)
		return err;
	err = cfi_read_sleb128_s32(s, &cie->data_align);
	if (err)
		return err;
	if (!cie->code_align || !cie->data_align)
		return -EINVAL;

	if (version == 1) {
		u8 ra8;

		err = cfi_read_u8(s, &ra8);
		if (err)
			return err;
		ra_col = ra8;
	} else {
		err = cfi_read_uleb128_u32(s, &ra_col);
		if (err)
			return err;
	}
	if (ra_col > U8_MAX)
		return -EINVAL;
	cie->ra_reg = (u8)ra_col;

	if (aug[0] == 'z') {
		u32 aug_len;
		unsigned long aug_end;
		unsigned int i;

		cie->has_z = true;
		err = cfi_read_uleb128_u32(s, &aug_len);
		if (err)
			return err;
		if (aug_len > DWARF_CFI_MAX_CIE_LEN)
			return -EINVAL;

		aug_end = cfi_stream_addr(s) + aug_len;
		for (i = 1; aug[i] != '\0'; i++) {
			u8 enc;
			int psize;

			if (cfi_stream_addr(s) > aug_end)
				return -EINVAL;

			switch (aug[i]) {
			case 'R':
				err = cfi_read_u8(s, &cie->fde_enc);
				if (err)
					return err;
				if (cie->fde_enc & DW_EH_PE_indirect)
					return -EINVAL;
				break;
			case 'L':
				/* LSDA encoding byte; never dereferenced */
				err = cfi_read_u8(s, &enc);
				if (err)
					return err;
				break;
			case 'P':
				/* Personality encoding + pointer; skipped without deref */
				err = cfi_read_u8(s, &enc);
				if (err)
					return err;
				psize = cfi_encoded_ptr_size(enc & ~DW_EH_PE_indirect,
							     arch->ws);
				if (psize < 0)
					return psize;
				err = cfi_skip_bytes(s, psize);
				if (err)
					return err;
				break;
			case 'S':
				cie->signal = true;
				break;
			case 'B':
				break;
			default:
				return -EINVAL;
			}
		}

		if (cfi_stream_addr(s) > aug_end)
			return -EINVAL;
		if (cfi_stream_addr(s) < aug_end) {
			err = cfi_skip_bytes(s, aug_end - cfi_stream_addr(s));
			if (err)
				return err;
		}
	} else if (aug[0] != '\0') {
		return -EINVAL;
	}

	memset(cie_row, 0, sizeof(*cie_row));
	cie_row->signal = cie->signal;

	return dwarf_cfi_exec_insns(s, cie, arch, /*cie_row=*/NULL, cie_row,
				    /*check_pc=*/false, /*start_pc=*/0,
				    /*target_pc=*/0);
}

/**
 * dwarf_cfi_eval_fde_streams() - Evaluate a CIE/FDE stream pair at @pc
 * @cie_s: Bounded stream over the CIE body.
 * @fde_s: Bounded stream over the FDE body.
 * @pc: Target instruction pointer to unwind.
 * @arch: Target architecture DWARF register descriptor.
 * @out_row: Output Minimal DWARF unwind row at @pc.
 *
 * Return: 0 on success, -ENOENT if @pc lies outside the FDE's address range,
 * -EFAULT on user copy fault, -EOVERFLOW on overflow, or -EINVAL on malformed
 * CIE/FDE contents.
 */
static int dwarf_cfi_eval_fde_streams(struct dwarf_cfi_stream *cie_s,
				      struct dwarf_cfi_stream *fde_s,
				      unsigned long pc,
				      const struct dwarf_cfi_arch *arch,
				      struct dwarf_cfi_row *out_row)
{
	struct dwarf_cfi_cie cie;
	struct dwarf_cfi_row cie_row, row;
	unsigned long init_loc, pc_range, end_loc;
	int err;

	err = dwarf_cfi_parse_cie(cie_s, arch, &cie, &cie_row);
	if (err)
		return err;

	if (likely(cie.fde_enc == (DW_EH_PE_pcrel | DW_EH_PE_sdata4) &&
		   fde_s->pos + 8 <= fde_s->win_len)) {
		unsigned long faddr = cfi_stream_addr(fde_s);
		s32 rel = (s32)get_unaligned_le32(fde_s->buf + fde_s->pos);
		u32 rng = get_unaligned_le32(fde_s->buf + fde_s->pos + 4);

		fde_s->pos += 8;
		init_loc = faddr + (long)rel;
		if (arch->ws == 4)
			init_loc = (u32)init_loc;
		pc_range = rng;
	} else {
		err = cfi_read_encoded_ptr(fde_s, cie.fde_enc, arch->ws,
					   /*datarel_base=*/0, &init_loc);
		if (err)
			return err;
		err = cfi_read_encoded_ptr(fde_s, cie.fde_enc & DW_EH_PE_FORM,
					   arch->ws, /*datarel_base=*/0,
					   &pc_range);
		if (err)
			return err;
	}

	if (!pc_range || check_add_overflow(init_loc, pc_range, &end_loc))
		return -EINVAL;
	if (pc < init_loc || pc >= end_loc)
		return -ENOENT;

	if (cie.has_z) {
		u32 aug_len;

		err = cfi_read_uleb128_u32(fde_s, &aug_len);
		if (err)
			return err;
		err = cfi_skip_bytes(fde_s, aug_len);
		if (err)
			return err;
	}

	row = cie_row;
	err = dwarf_cfi_exec_insns(fde_s, &cie, arch, &cie_row, &row,
				   /*check_pc=*/true, init_loc, pc);
	if (err)
		return err;

	*out_row = row;
	return 0;
}

/**
 * dwarf_cfi_eval_fde_kmem() - Evaluate an in-kernel FDE record at @pc
 * @fde: Pointer to the start of the FDE record within [@eh_start, @eh_end).
 * @eh_start: Start of the containing kernel/module .eh_frame section.
 * @eh_end: End (exclusive) of the containing kernel/module .eh_frame section.
 * @pc: Target kernel instruction pointer.
 * @arch: Target architecture DWARF register descriptor.
 * @out_row: Output Minimal DWARF unwind row at @pc.
 *
 * Validates CIE/FDE bounds within [@eh_start, @eh_end) and executes the FDE
 * directly in kernel memory with zero allocations, making it safe in atomic,
 * NMI, and noinstr contexts.
 *
 * Return: 0 on success, -ENOENT if @pc is outside the FDE's PC range, or
 * -EINVAL / -EOVERFLOW if the FDE or CIE is malformed or out of bounds.
 */
int dwarf_cfi_eval_fde_kmem(const u8 *fde, const u8 *eh_start,
			    const u8 *eh_end, unsigned long pc,
			    const struct dwarf_cfi_arch *arch,
			    struct dwarf_cfi_row *out_row)
{
	struct dwarf_cfi_stream cie_s, fde_s;
	u32 fde_len, cie_delta, cie_len, cie_id;
	const u8 *cie;

	if (eh_end < eh_start || fde < eh_start || fde >= eh_end ||
	    (size_t)(eh_end - fde) < 8)
		return -EINVAL;

	fde_len = get_unaligned_le32(fde);
	cie_delta = get_unaligned_le32(fde + 4);
	if (fde_len <= 4 || fde_len > DWARF_CFI_MAX_FDE_LEN || cie_delta < 4)
		return -EINVAL;
	if ((size_t)(eh_end - fde) - 4 < (size_t)fde_len)
		return -EINVAL;
	if ((size_t)((fde + 4) - eh_start) < cie_delta)
		return -EINVAL;

	cie = (fde + 4) - cie_delta;
	if (cie < eh_start || cie >= eh_end || (size_t)(eh_end - cie) < 8)
		return -EINVAL;

	cie_len = get_unaligned_le32(cie);
	cie_id = get_unaligned_le32(cie + 4);
	if (cie_id != 0 || cie_len <= 4 || cie_len > DWARF_CFI_MAX_CIE_LEN)
		return -EINVAL;
	if ((size_t)(eh_end - cie) - 4 < (size_t)cie_len)
		return -EINVAL;

	cfi_stream_init_kmem(&cie_s, cie + 8, cie_len - 4);
	cfi_stream_init_kmem(&fde_s, fde + 8, fde_len - 4);

	return dwarf_cfi_eval_fde_streams(&cie_s, &fde_s, pc, arch, out_row);
}

static inline unsigned long eh_hdr_entry_addr(unsigned long hdr_base,
					      unsigned long entry_addr,
					      s32 off, u8 table_enc, u8 ws)
{
	unsigned long addr;

	if ((table_enc & DW_EH_PE_ADJUST) == DW_EH_PE_pcrel)
		addr = entry_addr + (long)off;
	else
		addr = hdr_base + (long)off;

	return (ws == 4) ? (u32)addr : addr;
}

/**
 * dwarf_cfi_unwind_eh_frame_hdr() - Look up and evaluate kernel CFI via hdr
 * @hdr: Pointer to the kernel's .eh_frame_hdr section.
 * @hdr_size: Size in bytes of @hdr.
 * @eh_start: Start of the kernel's .eh_frame section.
 * @eh_end: End (exclusive) of the kernel's .eh_frame section.
 * @pc: Target kernel instruction pointer.
 * @arch: Target architecture DWARF register descriptor.
 * @out_row: Output Minimal DWARF unwind row at @pc.
 *
 * Performs an O(log N) binary search over the sorted version-1 .eh_frame_hdr
 * lookup table and evaluates the matching FDE in [@eh_start, @eh_end). Safe in
 * NMI and noinstr contexts.
 *
 * Return: 0 on success, -ENOENT if @pc is not covered by any FDE in @hdr, or
 * -EINVAL / -EOVERFLOW on invalid header or FDE encodings.
 */
int dwarf_cfi_unwind_eh_frame_hdr(const u8 *hdr, size_t hdr_size,
				  const u8 *eh_start, const u8 *eh_end,
				  unsigned long pc,
				  const struct dwarf_cfi_arch *arch,
				  struct dwarf_cfi_row *out_row)
{
	unsigned long hdr_base = (unsigned long)hdr;
	unsigned long fde_cnt_ul, fde_addr;
	const size_t ent_sz = sizeof(struct eh_frame_hdr_entry);
	const u8 *table;
	u32 lo, hi;
	u8 table_enc;

	if (!hdr || hdr_size < 12 || hdr[0] != 1)
		return -EINVAL;

	table_enc = hdr[3];
	if (table_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4) &&
	    table_enc != (DW_EH_PE_pcrel | DW_EH_PE_sdata4))
		return -EINVAL;

	if (likely(hdr[1] == (DW_EH_PE_pcrel | DW_EH_PE_sdata4) &&
		   hdr[2] == DW_EH_PE_udata4)) {
		fde_cnt_ul = get_unaligned_le32(hdr + 8);
		if (!fde_cnt_ul || fde_cnt_ul > DWARF_CFI_MAX_FDE_COUNT)
			return -EINVAL;
		if (hdr_size - 12 < fde_cnt_ul * ent_sz)
			return -EINVAL;
		table = hdr + 12;
	} else {
		struct dwarf_cfi_stream hs;
		unsigned long eh_ptr;
		int err;

		cfi_stream_init_kmem(&hs, hdr + 4, hdr_size - 4);
		err = cfi_read_encoded_ptr(&hs, hdr[1], arch->ws, hdr_base,
					   &eh_ptr);
		if (err)
			return err;
		err = cfi_read_encoded_ptr(&hs, hdr[2], arch->ws, hdr_base,
					   &fde_cnt_ul);
		if (err)
			return err;

		if (!fde_cnt_ul || fde_cnt_ul > DWARF_CFI_MAX_FDE_COUNT)
			return -EINVAL;
		if ((hs.win_len - hs.pos) < fde_cnt_ul * ent_sz)
			return -EINVAL;

		table = hs.buf + hs.pos;
	}

	lo = 0;
	hi = (u32)fde_cnt_ul;
	if (likely(table_enc == (DW_EH_PE_datarel | DW_EH_PE_sdata4))) {
		while (lo < hi) {
			u32 mid = lo + (hi - lo) / 2;
			const u8 *ent = table + (size_t)mid * ent_sz;
			s32 off = (s32)get_unaligned_le32(ent);

			if (hdr_base + (long)off <= pc)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (!lo)
			return -ENOENT;
		fde_addr = hdr_base +
			   (long)(s32)get_unaligned_le32(table + (size_t)(lo - 1) * ent_sz + 4);
	} else {
		while (lo < hi) {
			u32 mid = lo + (hi - lo) / 2;
			const u8 *ent = table + (size_t)mid * ent_sz;
			unsigned long e_pc = (unsigned long)ent +
					     (long)(s32)get_unaligned_le32(ent);

			if (e_pc <= pc)
				lo = mid + 1;
			else
				hi = mid;
		}
		if (!lo)
			return -ENOENT;
		{
			const u8 *fent = table + (size_t)(lo - 1) * ent_sz + 4;

			fde_addr = (unsigned long)fent +
				   (long)(s32)get_unaligned_le32(fent);
		}
	}

	return dwarf_cfi_eval_fde_kmem((const u8 *)fde_addr, eh_start, eh_end,
				       pc, arch, out_row);
}

static bool cfi_s32_rel_offset(unsigned long target, unsigned long base,
			       s32 *out)
{
	unsigned long diff;

	if (target >= base) {
		diff = target - base;
		if (diff > (unsigned long)S32_MAX)
			return false;
		*out = (s32)diff;
		return true;
	}

	diff = base - target;
	if (diff > (unsigned long)S32_MAX + 1UL)
		return false;
	*out = (diff == (unsigned long)S32_MAX + 1UL) ? S32_MIN : -(s32)diff;
	return true;
}

/**
 * dwarf_cfi_scan_eh_frame_kmem() - Scan a kernel .eh_frame to index its FDEs
 * @eh_start: Start of the in-memory .eh_frame section.
 * @eh_size: Size in bytes of the .eh_frame section.
 * @arch: Target architecture DWARF register descriptor.
 * @base_addr: Reference base address from which @entries offsets are computed.
 * @entries: Optional output array of &struct eh_frame_hdr_entry (NULL to only
 *           count FDEs).
 * @max_entries: Capacity of @entries when @entries is non-NULL.
 * @out_count: Output number of valid FDEs discovered in [@eh_start, +@eh_size).
 *
 * Used at module load time (and in tests) to construct a binary-search FDE
 * lookup table when the linker has not emitted a separate .eh_frame_hdr.
 *
 * Return: 0 on success, -ENOSPC if @entries is non-NULL and smaller than the
 * FDE count, -EOVERFLOW if an offset exceeds s32 range from @base_addr, or
 * -EINVAL on malformed CIE/FDE records.
 */
int dwarf_cfi_scan_eh_frame_kmem(const u8 *eh_start, size_t eh_size,
				 const struct dwarf_cfi_arch *arch,
				 unsigned long base_addr,
				 struct eh_frame_hdr_entry *entries,
				 unsigned int max_entries,
				 unsigned int *out_count)
{
	const u8 *p = eh_start;
	const u8 *eh_end = eh_start + eh_size;
	unsigned int count = 0;

	if (!arch || arch->ws != sizeof(unsigned long))
		return -EINVAL;

	while (p < eh_end && (size_t)(eh_end - p) >= 4) {
		u32 len = get_unaligned_le32(p);
		u32 cie_delta;
		const u8 *entry_end;

		if (len == 0)
			break;
		if (len <= 4 || len == U32_MAX ||
		    (size_t)(eh_end - p) - 4 < (size_t)len)
			return -EINVAL;

		entry_end = p + 4 + len;
		cie_delta = get_unaligned_le32(p + 4);

		if (cie_delta != 0) {
			/* FDE: resolve CIE to decode initial_loc */
			const u8 *cie;
			u32 cie_len;
			struct dwarf_cfi_stream cie_s, fde_s;
			struct dwarf_cfi_cie parsed_cie;
			struct dwarf_cfi_row dummy_row;
			unsigned long init_loc;
			s32 rel_pc, rel_fde;
			int err;

			if (cie_delta < 4 ||
			    (size_t)((p + 4) - eh_start) < cie_delta)
				return -EINVAL;
			cie = (p + 4) - cie_delta;
			if (cie < eh_start || cie >= eh_end ||
			    (size_t)(eh_end - cie) < 8)
				return -EINVAL;
			cie_len = get_unaligned_le32(cie);
			if (cie_len <= 4 || cie_len > DWARF_CFI_MAX_CIE_LEN ||
			    (size_t)(eh_end - cie) - 4 < (size_t)cie_len ||
			    get_unaligned_le32(cie + 4) != 0)
				return -EINVAL;

			cfi_stream_init_kmem(&cie_s, cie + 8, cie_len - 4);
			err = dwarf_cfi_parse_cie(&cie_s, arch, &parsed_cie, &dummy_row);
			if (err)
				return err;

			cfi_stream_init_kmem(&fde_s, p + 8, len - 4);
			err = cfi_read_encoded_ptr(&fde_s, parsed_cie.fde_enc,
						   arch->ws, /*datarel_base=*/0,
						   &init_loc);
			if (err)
				return err;

			if (!cfi_s32_rel_offset(init_loc, base_addr, &rel_pc) ||
			    !cfi_s32_rel_offset((unsigned long)p, base_addr,
						&rel_fde))
				return -EOVERFLOW;

			if (entries) {
				if (count >= max_entries)
					return -ENOSPC;
				entries[count].start_off = rel_pc;
				entries[count].fde_off = rel_fde;
			}
			count++;
		}

		p = entry_end;
	}

	*out_count = count;
	return 0;
}

/**
 * dwarf_cfi_unwind_user_eh_frame_hdr() - Evaluate user-space CFI from user hdr
 * @hdr_uaddr: User virtual address of the binary's PT_GNU_EH_FRAME segment.
 * @hdr_size: Size in bytes of the PT_GNU_EH_FRAME segment.
 * @pc: Target user instruction pointer.
 * @arch: User architecture DWARF register descriptor (native or compat).
 * @out_row: Output Minimal DWARF unwind row at @pc.
 *
 * Binary-searches the user .eh_frame_hdr table via copy_from_user() and
 * streams the matching FDE and its CIE through bounded 128-byte stack windows.
 * Must be called in sleepable task context (calls might_fault()).
 *
 * Return: 0 on success, -ENOENT if @pc is not covered by @hdr_uaddr, -EFAULT
 * on unmapped user memory, or -EINVAL / -EOVERFLOW on invalid encodings.
 */
int dwarf_cfi_unwind_user_eh_frame_hdr(unsigned long hdr_uaddr,
				       size_t hdr_size, unsigned long pc,
				       const struct dwarf_cfi_arch *arch,
				       struct dwarf_cfi_row *out_row)
{
	struct dwarf_cfi_stream hs, cie_s, fde_s;
	unsigned long eh_ptr, fde_cnt_ul, table_uaddr, fde_uaddr, cie_uaddr;
	const size_t ent_sz = sizeof(struct eh_frame_hdr_entry);
	u8 cie_win[DWARF_CFI_WIN_SIZE], fde_win[DWARF_CFI_WIN_SIZE];
	u8 hdr_prefix[28];
	u8 fde_hdr[8], cie_hdr[8];
	u32 fde_len, cie_delta, cie_len, cie_id;
	u32 lo, hi;
	bool have_match = false;
	size_t prefix_len;
	u8 table_enc;
	int err;

	might_fault();

	if (!hdr_uaddr || hdr_size < 12)
		return -EINVAL;

	prefix_len = min_t(size_t, hdr_size, sizeof(hdr_prefix));
	if (copy_from_user(hdr_prefix, (const void __user *)hdr_uaddr, prefix_len))
		return -EFAULT;

	if (hdr_prefix[0] != 1)
		return -EINVAL;

	table_enc = hdr_prefix[3];
	if (table_enc != (DW_EH_PE_datarel | DW_EH_PE_sdata4) &&
	    table_enc != (DW_EH_PE_pcrel | DW_EH_PE_sdata4))
		return -EINVAL;

	cfi_stream_init_kmem(&hs, hdr_prefix + 4, prefix_len - 4);
	hs.cur_base_addr = hdr_uaddr + 4;

	err = cfi_read_encoded_ptr(&hs, hdr_prefix[1], arch->ws, hdr_uaddr, &eh_ptr);
	if (err)
		return err;
	err = cfi_read_encoded_ptr(&hs, hdr_prefix[2], arch->ws, hdr_uaddr, &fde_cnt_ul);
	if (err)
		return err;

	if (!fde_cnt_ul || fde_cnt_ul > DWARF_CFI_MAX_FDE_COUNT)
		return -EINVAL;

	table_uaddr = cfi_stream_addr(&hs);
	if (hdr_size - (table_uaddr - hdr_uaddr) < fde_cnt_ul * ent_sz)
		return -EINVAL;

	lo = 0;
	hi = (u32)fde_cnt_ul;
	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;
		unsigned long ent_uaddr = table_uaddr + (size_t)mid * ent_sz;
		struct eh_frame_hdr_entry ent;
		unsigned long e_pc;

		if (copy_from_user(&ent, (const void __user *)ent_uaddr, sizeof(ent)))
			return -EFAULT;

		e_pc = eh_hdr_entry_addr(hdr_uaddr, ent_uaddr,
					 le32_to_cpu((__force __le32)ent.start_off),
					 table_enc, arch->ws);
		if (e_pc <= pc) {
			unsigned long foff_uaddr =
				ent_uaddr + offsetof(struct eh_frame_hdr_entry, fde_off);

			fde_uaddr = eh_hdr_entry_addr(hdr_uaddr, foff_uaddr,
						      le32_to_cpu((__force __le32)ent.fde_off),
						      table_enc, arch->ws);
			have_match = true;
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}

	if (!have_match)
		return -ENOENT;

	if (copy_from_user(fde_hdr, (const void __user *)fde_uaddr, sizeof(fde_hdr)))
		return -EFAULT;

	fde_len = get_unaligned_le32(fde_hdr);
	cie_delta = get_unaligned_le32(fde_hdr + 4);
	if (fde_len <= 4 || fde_len > DWARF_CFI_MAX_FDE_LEN ||
	    cie_delta < 4 || cie_delta > DWARF_CFI_MAX_CIE_DELTA)
		return -EINVAL;
	if (fde_uaddr + 4 < cie_delta)
		return -EINVAL;

	cie_uaddr = (fde_uaddr + 4) - cie_delta;
	if (copy_from_user(cie_hdr, (const void __user *)cie_uaddr, sizeof(cie_hdr)))
		return -EFAULT;

	cie_len = get_unaligned_le32(cie_hdr);
	cie_id = get_unaligned_le32(cie_hdr + 4);
	if (cie_id != 0 || cie_len <= 4 || cie_len > DWARF_CFI_MAX_CIE_LEN)
		return -EINVAL;

	err = cfi_stream_init_user(&cie_s, cie_uaddr + 8, cie_len - 4, cie_win);
	if (err)
		return err;
	err = cfi_stream_init_user(&fde_s, fde_uaddr + 8, fde_len - 4, fde_win);
	if (err)
		return err;

	return dwarf_cfi_eval_fde_streams(&cie_s, &fde_s, pc, arch, out_row);
}

#if defined(CONFIG_UNWINDER_DWARF_CFI) && defined(CONFIG_MODULES)
static int cmp_eh_hdr_entry(const void *a, const void *b)
{
	const struct eh_frame_hdr_entry *ea = a;
	const struct eh_frame_hdr_entry *eb = b;

	return (ea->start_off > eb->start_off) - (ea->start_off < eb->start_off);
}

/**
 * dwarf_cfi_mod_alloc() - Allocate and sort a module .eh_frame lookup index
 * @eh_frame: Pointer to the module's SHF_ALLOC .eh_frame section.
 * @eh_frame_size: Size in bytes of @eh_frame.
 * @arch: Target architecture DWARF register descriptor.
 *
 * Performs a two-pass scan over @eh_frame to count and populate relative FDE
 * index entries and sorts them by initial PC offset for binary search.
 *
 * Return: Newly allocated &struct mod_dwarf_cfi_index on success, or NULL if
 * @eh_frame is empty, malformed, or memory allocation fails.
 */
struct mod_dwarf_cfi_index *dwarf_cfi_mod_alloc(const void *eh_frame,
						size_t eh_frame_size,
						const struct dwarf_cfi_arch *arch)
{
	struct mod_dwarf_cfi_index *idx;
	unsigned int num_fdes = 0;
	unsigned long base;

	if (!eh_frame || !eh_frame_size)
		return NULL;

	base = (unsigned long)eh_frame;
	if (dwarf_cfi_scan_eh_frame_kmem(eh_frame, eh_frame_size, arch, base,
					 /*entries=*/NULL, /*max_entries=*/0,
					 &num_fdes) || !num_fdes)
		return NULL;

	idx = kmalloc(struct_size(idx, entries, num_fdes), GFP_KERNEL);
	if (!idx)
		return NULL;

	idx->num_fdes = num_fdes;
	idx->eh_frame = eh_frame;
	idx->eh_frame_size = eh_frame_size;

	if (dwarf_cfi_scan_eh_frame_kmem(eh_frame, eh_frame_size, arch, base,
					 idx->entries, num_fdes, &num_fdes)) {
		kfree(idx);
		return NULL;
	}
	idx->num_fdes = num_fdes;

	sort(idx->entries, idx->num_fdes, sizeof(idx->entries[0]),
	     cmp_eh_hdr_entry, /*swap_func=*/NULL);
	return idx;
}

/**
 * dwarf_cfi_mod_free_rcu() - Free a module CFI index after an RCU grace period
 * @idx: Module CFI index previously unpublished from mod->arch (may be NULL).
 */
void dwarf_cfi_mod_free_rcu(struct mod_dwarf_cfi_index *idx)
{
	if (idx)
		kfree_rcu_mightsleep(idx);
}

/**
 * dwarf_cfi_mod_eval() - Look up and evaluate a module FDE at @ip
 * @idx: RCU-protected module CFI index (may be NULL).
 * @ip: Target module instruction pointer.
 * @arch: Target architecture DWARF register descriptor.
 * @out_row: Output Minimal DWARF unwind row at @ip.
 *
 * Caller must hold an RCU or RCU-sched read lock keeping both @idx and the
 * module's core/init .eh_frame memory alive across the evaluation.
 *
 * Return: 0 on success, -ENOENT if @idx is NULL or no FDE covers @ip, or
 * -EINVAL / -EOVERFLOW on invalid FDE bytecode.
 */
int dwarf_cfi_mod_eval(const struct mod_dwarf_cfi_index *idx, unsigned long ip,
		       const struct dwarf_cfi_arch *arch,
		       struct dwarf_cfi_row *out_row)
{
	unsigned long base;
	u32 lo, hi, found = 0;
	bool have_match = false;
	const u8 *fde;

	if (!idx || !idx->num_fdes)
		return -ENOENT;

	base = (unsigned long)idx->eh_frame;
	lo = 0;
	hi = idx->num_fdes;
	while (lo < hi) {
		u32 mid = lo + (hi - lo) / 2;
		unsigned long e_pc = base + (long)idx->entries[mid].start_off;

		if (e_pc <= ip) {
			found = mid;
			have_match = true;
			lo = mid + 1;
		} else {
			hi = mid;
		}
	}

	if (!have_match)
		return -ENOENT;

	fde = (const u8 *)(base + (long)idx->entries[found].fde_off);
	return dwarf_cfi_eval_fde_kmem(fde, idx->eh_frame,
				       idx->eh_frame + idx->eh_frame_size,
				       ip, arch, out_row);
}
#endif /* CONFIG_UNWINDER_DWARF_CFI && CONFIG_MODULES */
