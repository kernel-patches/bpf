// SPDX-License-Identifier: GPL-2.0-only OR MIT
/*
 * min_eh_frame.c - Build-time .eh_frame minifier for Minimal DWARF CFI.
 *
 * Rewrites ET_REL (.o) .eh_frame and .rela.eh_frame sections in place so only
 * Minimal DWARF CFA bytecodes remain:
 *  - Strips general-purpose register spills/restores (keeping only SP, FP, RA)
 *  - Strips DW_CFA_GNU_args_size and redundant remember_state/restore_state
 *  - Coalesces adjacent DW_CFA_advance_loc* instructions and drops trailing
 *    PC-advance instructions after the last state transition
 *  - Drops FDEs (and their relocations) that use unsupported DWARF expressions
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

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

#ifndef EM_RISCV
#define EM_RISCV				243
#endif

#ifndef SHT_X86_64_UNWIND
#define SHT_X86_64_UNWIND			0x70000001U
#endif

#define DW_OP_deref				0x06
#define DW_OP_breg0				0x70

#define DW_EH_PE_omit				0xff
#define DW_EH_PE_FORM				0x0f
#define DW_EH_PE_absptr				0x00
#define DW_EH_PE_udata2				0x02
#define DW_EH_PE_udata4				0x03
#define DW_EH_PE_udata8				0x04
#define DW_EH_PE_sdata2				0x0a
#define DW_EH_PE_sdata4				0x0b
#define DW_EH_PE_sdata8				0x0c
#define DW_EH_PE_indirect			0x80

/* Target architecture DWARF register numbers for SP, FP, and RA. */
struct arch_cfg {
	uint8_t addr_size;
	uint8_t sp_reg;
	uint8_t fp_reg;
	uint8_t ra_reg;
};

/* Abstract Minimal DWARF unwind row tracked while filtering CFA opcodes. */
struct min_row {
	int32_t cfa_off;
	int32_t sp_off;
	int32_t fp_off;
	int32_t ra_off;
	uint8_t cfa_kind; /* 0=undef, 1=reg, 2=fp_indirect, 3=sp_indirect */
	uint8_t cfa_reg;
	uint8_t sp_rule;  /* 0=same, 1=cfa_off, 3=undef */
	uint8_t fp_rule;  /* 0=same, 1=cfa_off, 2=fp_off, 3=undef, 4=sp_off */
	uint8_t ra_rule;  /* 0=same, 1=cfa_off, 3=undef, 4=sp_off */
	bool ra_signed;
};

/* Parsed CIE metadata and its rewritten offset in the minified .eh_frame. */
struct cie_info {
	size_t old_off;
	size_t new_off;
	uint32_t code_align;
	int32_t data_align;
	uint8_t ra_reg;
	uint8_t fde_enc;
	bool has_z;
	bool is_signal;
	struct min_row init_row;
};

/*
 * Buffered output event emitted by minify_insns(). Adjacent non-relocated
 * PC-advance events are coalesced before serialization, whereas relocated
 * DW_CFA_advance_loc* instructions (e.g. RISC-V R_RISCV_ADD/SUB pairs) are
 * preserved verbatim with their original byte offsets recorded for relocation
 * remapping.
 */
struct out_event {
	bool is_adv;
	bool has_reloc;
	uint32_t adv;
	size_t orig_off;
	size_t new_off;
	uint8_t bytes[16];
	size_t len;
};

/* Mapping from an input relocated CFA instruction span to its new offset. */
struct reloc_map {
	size_t orig_off;
	size_t len;
	size_t new_off;
};

/* Wrapper preserving original .rela.eh_frame order across r_offset sorting. */
struct indexed_rela {
	Elf64_Rela rela;
	size_t orig_idx;
};

/* Monotonic mapping anchor from an input .eh_frame span to output .eh_frame. */
struct eh_anchor {
	size_t old_off;
	size_t len;
	size_t new_off;
};

/* Sorted list of .eh_frame anchors for updating section-local symbols/relocs. */
struct anchor_list {
	struct eh_anchor *data;
	size_t len;
	size_t cap;
};

/* Growable output byte buffer. */
struct byte_buf {
	uint8_t *data;
	size_t len;
	size_t cap;
};

static void buf_append(struct byte_buf *b, const void *src, size_t n)
{
	if (!n)
		return;
	if (b->len + n > b->cap) {
		size_t ncap = b->cap ? b->cap * 2 : 4096;

		while (ncap < b->len + n)
			ncap *= 2;
		b->data = realloc(b->data, ncap);
		if (!b->data) {
			perror("realloc");
			exit(1);
		}
		b->cap = ncap;
	}
	memcpy(b->data + b->len, src, n);
	b->len += n;
}

static void buf_append_u8(struct byte_buf *b, uint8_t v)
{
	buf_append(b, &v, 1);
}

static uint16_t get_le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t get_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t get_le64(const void *vp)
{
	const uint8_t *p = vp;

	return (uint64_t)get_le32(p) | ((uint64_t)get_le32(p + 4) << 32);
}

static void put_le16(void *vp, uint16_t v)
{
	uint8_t *p = vp;

	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put_le32(void *vp, uint32_t v)
{
	uint8_t *p = vp;

	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void put_le64(void *vp, uint64_t v)
{
	uint8_t *p = vp;

	put_le32(p, (uint32_t)v);
	put_le32(p + 4, (uint32_t)(v >> 32));
}

static uint16_t r16(const uint16_t *p)
{
	return get_le16((const uint8_t *)p);
}

static uint32_t r32(const uint32_t *p)
{
	return get_le32((const uint8_t *)p);
}

static uint64_t r64(const uint64_t *p)
{
	return get_le64(p);
}

static void w64(uint64_t *p, uint64_t v)
{
	put_le64(p, v);
}

static int read_uleb128(const uint8_t *buf, size_t *pos, size_t end, uint32_t *out)
{
	uint32_t val = 0;
	unsigned int shift = 0;

	while (*pos < end) {
		uint8_t b = buf[(*pos)++];

		if (shift == 28 && ((b & 0x7f) > 0x0f || (b & 0x80)))
			return -1;
		val |= (uint32_t)(b & 0x7f) << shift;
		if (!(b & 0x80)) {
			*out = val;
			return 0;
		}
		shift += 7;
	}
	return -1;
}

static int read_sleb128(const uint8_t *buf, size_t *pos, size_t end, int32_t *out)
{
	uint32_t val = 0;
	unsigned int shift = 0;

	while (*pos < end) {
		uint8_t b = buf[(*pos)++];

		if (shift == 28) {
			uint8_t top = b & 0x78;

			if ((b & 0x80) || (top != 0x00 && top != 0x78))
				return -1;
		}
		val |= (uint32_t)(b & 0x7f) << shift;
		shift += 7;
		if (!(b & 0x80)) {
			if (shift < 32 && (b & 0x40))
				val |= ~0U << shift;
			*out = (int32_t)val;
			return 0;
		}
	}
	return -1;
}

static size_t encode_uleb128(uint32_t val, uint8_t *out)
{
	size_t n = 0;

	do {
		uint8_t b = val & 0x7f;

		val >>= 7;
		if (val)
			b |= 0x80;
		out[n++] = b;
	} while (val);
	return n;
}

static size_t encode_sleb128(int32_t val, uint8_t *out)
{
	size_t n = 0;
	bool more = true;

	while (more) {
		uint8_t b = val & 0x7f;

		val >>= 7;
		if ((val == 0 && !(b & 0x40)) || (val == -1 && (b & 0x40)))
			more = false;
		else
			b |= 0x80;
		out[n++] = b;
	}
	return n;
}

static int ptr_enc_size(uint8_t enc, uint8_t addr_size)
{
	if (enc == DW_EH_PE_omit)
		return 0;
	switch (enc & DW_EH_PE_FORM) {
	case DW_EH_PE_absptr:
		return addr_size;
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
		return -1;
	}
}

static bool rows_equal(const struct min_row *a, const struct min_row *b)
{
	if (a->cfa_kind != b->cfa_kind || a->cfa_off != b->cfa_off ||
	    a->sp_rule != b->sp_rule || a->fp_rule != b->fp_rule ||
	    a->ra_rule != b->ra_rule || a->ra_signed != b->ra_signed)
		return false;
	if (a->cfa_kind == 1 && a->cfa_reg != b->cfa_reg)
		return false;
	if (a->sp_rule == 1 && a->sp_off != b->sp_off)
		return false;
	if ((a->fp_rule == 1 || a->fp_rule == 2 || a->fp_rule == 4) &&
	    a->fp_off != b->fp_off)
		return false;
	if ((a->ra_rule == 1 || a->ra_rule == 4) &&
	    a->ra_off != b->ra_off)
		return false;
	return true;
}

static int mul_s32(int64_t a, int64_t b, int32_t *out)
{
	int64_t prod = a * b;

	if (prod < INT32_MIN || prod > INT32_MAX)
		return -1;
	*out = (int32_t)prod;
	return 0;
}

static int add_adv_u32(uint32_t *acc, uint32_t delta)
{
	if (UINT32_MAX - *acc < delta)
		return -1;
	*acc += delta;
	return 0;
}

static bool has_reloc_in_range(const Elf64_Rela *relas, size_t nrelas,
			       size_t lo, size_t hi)
{
	for (size_t i = 0; i < nrelas; i++) {
		if (relas[i].r_offset >= lo && relas[i].r_offset < hi)
			return true;
	}
	return false;
}

static void flush_adv_bytes(struct byte_buf *out_bytes, uint32_t *acc)
{
	uint8_t abuf[5];
	uint32_t v = *acc;

	if (!v)
		return;
	if (v <= 0x3f) {
		abuf[0] = 0x40 | (uint8_t)v;
		buf_append(out_bytes, abuf, 1);
	} else if (v <= 0xff) {
		abuf[0] = DW_CFA_advance_loc1;
		abuf[1] = (uint8_t)v;
		buf_append(out_bytes, abuf, 2);
	} else if (v <= 0xffff) {
		abuf[0] = DW_CFA_advance_loc2;
		put_le16(abuf + 1, (uint16_t)v);
		buf_append(out_bytes, abuf, 3);
	} else {
		abuf[0] = DW_CFA_advance_loc4;
		put_le32(abuf + 1, v);
		buf_append(out_bytes, abuf, 5);
	}
	*acc = 0;
}

/*
 * Filter a CIE or FDE instruction stream down to Minimal DWARF CFA opcodes:
 *  - Drop untracked GPR spills/restores, DW_CFA_nop, and DW_CFA_GNU_args_size
 *  - Elide redundant state transitions and empty remember_state/restore_state
 *  - Coalesce non-relocated DW_CFA_advance_loc* ops into minimal encodings and
 *    drop trailing PC advances after the final state change
 *  - Return -1 if an FDE uses opcodes or DWARF expressions outside the Minimal
 *    DWARF subset so the caller can drop that FDE cleanly.
 */
static int minify_insns(const uint8_t *insns, size_t end, size_t insns_eh_off,
			const Elf64_Rela *insn_relas, size_t n_insn_relas,
			const struct cie_info *cie, const struct arch_cfg *arch,
			bool is_cie, struct min_row *io_row,
			struct byte_buf *out_bytes,
			struct reloc_map **out_rmaps, size_t *out_nrmaps)
{
	size_t cap = end + 16;
	struct out_event *evs = calloc(cap, sizeof(*evs));
	size_t nev = 0;
	uint32_t pending_adv = 0;
	struct min_row row = *io_row;
	struct min_row cie_base = *io_row;
	struct {
		struct min_row saved;
		size_t ev_idx;
	} stack[4];
	unsigned int sp = 0;
	size_t pos = 0;
	int ret = -1;

	if (!evs)
		return -1;

#define EMIT_OP(raw_ptr, raw_len) do {					\
	size_t _raw_len = (raw_len);					\
									\
	if (pending_adv > 0 && !is_cie) {				\
		evs[nev].is_adv = true;					\
		evs[nev].adv = pending_adv;				\
		nev++;							\
		pending_adv = 0;					\
	}								\
	evs[nev].is_adv = false;					\
	evs[nev].len = _raw_len;					\
	memcpy(evs[nev].bytes, (raw_ptr), _raw_len);			\
	nev++;								\
} while (0)

#define EMIT_REL_ADV(op_pos, op_len) do {				\
	size_t _op_pos = (op_pos);					\
	size_t _op_len = (op_len);					\
									\
	if (pending_adv > 0 && !is_cie) {				\
		evs[nev].is_adv = true;					\
		evs[nev].adv = pending_adv;				\
		nev++;							\
		pending_adv = 0;					\
	}								\
	evs[nev].is_adv = true;						\
	evs[nev].has_reloc = true;					\
	evs[nev].orig_off = insns_eh_off + _op_pos;			\
	evs[nev].len = _op_len;						\
	memcpy(evs[nev].bytes, insns + _op_pos, _op_len);		\
	nev++;								\
} while (0)

	while (pos < end) {
		size_t op_start = pos;
		uint8_t op = insns[pos++];
		uint8_t hi = op & 0xc0;
		uint8_t lo = op & 0x3f;
		uint8_t tmp[16];
		size_t tn;
		uint32_t reg, uval;
		int32_t sval;

		if (nev + 2 >= cap) {
			struct out_event *nevs;

			cap *= 2;
			nevs = realloc(evs, cap * sizeof(*evs));
			if (!nevs)
				goto out;
			evs = nevs;
		}

		if (hi == 0x40) {
			if (!is_cie && n_insn_relas &&
			    has_reloc_in_range(insn_relas, n_insn_relas,
					       insns_eh_off + op_start,
					       insns_eh_off + pos)) {
				EMIT_REL_ADV(op_start, 1);
				continue;
			}
			if (add_adv_u32(&pending_adv, lo))
				goto out;
			continue;
		}
		if (hi == 0x80) {
			if (read_uleb128(insns, &pos, end, &uval))
				goto out;
			if (lo == arch->fp_reg || lo == cie->ra_reg ||
			    lo == arch->sp_reg) {
				int32_t off;

				if (mul_s32(uval, cie->data_align, &off))
					goto out;

				if (lo == arch->fp_reg &&
				    (row.fp_rule != 1 || row.fp_off != off)) {
					row.fp_rule = 1;
					row.fp_off = off;
					tmp[0] = 0x80 | lo;
					tn = 1 + encode_uleb128(uval, tmp + 1);
					EMIT_OP(tmp, tn);
				} else if (lo == cie->ra_reg &&
					   (row.ra_rule != 1 || row.ra_off != off)) {
					row.ra_rule = 1;
					row.ra_off = off;
					tmp[0] = 0x80 | lo;
					tn = 1 + encode_uleb128(uval, tmp + 1);
					EMIT_OP(tmp, tn);
				} else if (lo == arch->sp_reg &&
					   (row.sp_rule != 1 || row.sp_off != off)) {
					row.sp_rule = 1;
					row.sp_off = off;
					tmp[0] = 0x80 | lo;
					tn = 1 + encode_uleb128(uval, tmp + 1);
					EMIT_OP(tmp, tn);
				}
			}
			continue;
		}
		if (hi == 0xc0) {
			if (lo == arch->fp_reg &&
			    (row.fp_rule != cie_base.fp_rule ||
			     ((cie_base.fp_rule == 1 || cie_base.fp_rule == 2 ||
			       cie_base.fp_rule == 4) &&
			      row.fp_off != cie_base.fp_off))) {
				row.fp_rule = cie_base.fp_rule;
				row.fp_off = cie_base.fp_off;
				tmp[0] = 0xc0 | lo;
				EMIT_OP(tmp, 1);
			} else if (lo == cie->ra_reg &&
				   (row.ra_rule != cie_base.ra_rule ||
				    ((cie_base.ra_rule == 1 ||
				      cie_base.ra_rule == 4) &&
				     row.ra_off != cie_base.ra_off))) {
				row.ra_rule = cie_base.ra_rule;
				row.ra_off = cie_base.ra_off;
				tmp[0] = 0xc0 | lo;
				EMIT_OP(tmp, 1);
			} else if (lo == arch->sp_reg &&
				   (row.sp_rule != cie_base.sp_rule ||
				    (cie_base.sp_rule == 1 &&
				     row.sp_off != cie_base.sp_off))) {
				row.sp_rule = cie_base.sp_rule;
				row.sp_off = cie_base.sp_off;
				tmp[0] = 0xc0 | lo;
				EMIT_OP(tmp, 1);
			}
			continue;
		}

		switch (op) {
		case DW_CFA_nop:
			break;
		case DW_CFA_advance_loc1:
			if (pos + 1 > end)
				goto out;
			pos += 1;
			if (!is_cie && n_insn_relas &&
			    has_reloc_in_range(insn_relas, n_insn_relas,
					       insns_eh_off + op_start,
					       insns_eh_off + pos)) {
				EMIT_REL_ADV(op_start, 2);
				break;
			}
			if (add_adv_u32(&pending_adv, insns[op_start + 1]))
				goto out;
			break;
		case DW_CFA_advance_loc2:
			if (pos + 2 > end)
				goto out;
			pos += 2;
			if (!is_cie && n_insn_relas &&
			    has_reloc_in_range(insn_relas, n_insn_relas,
					       insns_eh_off + op_start,
					       insns_eh_off + pos)) {
				EMIT_REL_ADV(op_start, 3);
				break;
			}
			if (add_adv_u32(&pending_adv, get_le16(insns + op_start + 1)))
				goto out;
			break;
		case DW_CFA_advance_loc4:
			if (pos + 4 > end)
				goto out;
			pos += 4;
			if (!is_cie && n_insn_relas &&
			    has_reloc_in_range(insn_relas, n_insn_relas,
					       insns_eh_off + op_start,
					       insns_eh_off + pos)) {
				EMIT_REL_ADV(op_start, 5);
				break;
			}
			if (add_adv_u32(&pending_adv, get_le32(insns + op_start + 1)))
				goto out;
			break;
		case DW_CFA_def_cfa:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_uleb128(insns, &pos, end, &uval) ||
			    reg > 255 || uval > INT32_MAX)
				goto out;
			if (row.cfa_kind != 1 || row.cfa_reg != reg ||
			    row.cfa_off != (int32_t)uval) {
				row.cfa_kind = 1;
				row.cfa_reg = (uint8_t)reg;
				row.cfa_off = (int32_t)uval;
				tmp[0] = DW_CFA_def_cfa;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				tn += encode_uleb128(uval, tmp + tn);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_def_cfa_sf:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_sleb128(insns, &pos, end, &sval) || reg > 255 ||
			    mul_s32(sval, cie->data_align, &row.cfa_off))
				goto out;
			row.cfa_kind = 1;
			row.cfa_reg = (uint8_t)reg;
			tmp[0] = DW_CFA_def_cfa_sf;
			tn = 1 + encode_uleb128(reg, tmp + 1);
			tn += encode_sleb128(sval, tmp + tn);
			EMIT_OP(tmp, tn);
			break;
		case DW_CFA_def_cfa_register:
			if (row.cfa_kind != 1 ||
			    read_uleb128(insns, &pos, end, &reg) || reg > 255)
				goto out;
			if (row.cfa_reg != reg) {
				row.cfa_reg = (uint8_t)reg;
				tmp[0] = DW_CFA_def_cfa_register;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_def_cfa_offset:
			if (row.cfa_kind != 1 ||
			    read_uleb128(insns, &pos, end, &uval) ||
			    uval > INT32_MAX)
				goto out;
			if (row.cfa_off != (int32_t)uval) {
				row.cfa_off = (int32_t)uval;
				tmp[0] = DW_CFA_def_cfa_offset;
				tn = 1 + encode_uleb128(uval, tmp + 1);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_def_cfa_offset_sf:
			if (row.cfa_kind != 1 ||
			    read_sleb128(insns, &pos, end, &sval) ||
			    mul_s32(sval, cie->data_align, &row.cfa_off))
				goto out;
			tmp[0] = DW_CFA_def_cfa_offset_sf;
			tn = 1 + encode_sleb128(sval, tmp + 1);
			EMIT_OP(tmp, tn);
			break;
		case DW_CFA_offset_extended:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_uleb128(insns, &pos, end, &uval))
				goto out;
			if (reg == arch->fp_reg || reg == cie->ra_reg ||
			    reg == arch->sp_reg) {
				int32_t off;

				if (mul_s32(uval, cie->data_align, &off))
					goto out;

				if (reg == arch->fp_reg) {
					row.fp_rule = 1;
					row.fp_off = off;
				} else if (reg == cie->ra_reg) {
					row.ra_rule = 1;
					row.ra_off = off;
				} else {
					row.sp_rule = 1;
					row.sp_off = off;
				}
				tmp[0] = DW_CFA_offset_extended;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				tn += encode_uleb128(uval, tmp + tn);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_offset_extended_sf:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_sleb128(insns, &pos, end, &sval))
				goto out;
			if (reg == arch->fp_reg || reg == cie->ra_reg ||
			    reg == arch->sp_reg) {
				int32_t off;

				if (mul_s32(sval, cie->data_align, &off))
					goto out;

				if (reg == arch->fp_reg) {
					row.fp_rule = 1;
					row.fp_off = off;
				} else if (reg == cie->ra_reg) {
					row.ra_rule = 1;
					row.ra_off = off;
				} else {
					row.sp_rule = 1;
					row.sp_off = off;
				}
				tmp[0] = DW_CFA_offset_extended_sf;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				tn += encode_sleb128(sval, tmp + tn);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_GNU_negative_offset_extended:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_uleb128(insns, &pos, end, &uval))
				goto out;
			if (reg == arch->fp_reg || reg == cie->ra_reg ||
			    reg == arch->sp_reg) {
				int32_t off;

				if (mul_s32(-(int64_t)uval, cie->data_align, &off))
					goto out;

				if (reg == arch->fp_reg) {
					row.fp_rule = 1;
					row.fp_off = off;
				} else if (reg == cie->ra_reg) {
					row.ra_rule = 1;
					row.ra_off = off;
				} else {
					row.sp_rule = 1;
					row.sp_off = off;
				}
				tmp[0] = DW_CFA_GNU_negative_offset_extended;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				tn += encode_uleb128(uval, tmp + tn);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_restore_extended:
			if (read_uleb128(insns, &pos, end, &reg))
				goto out;
			if (reg == arch->fp_reg) {
				row.fp_rule = cie_base.fp_rule;
				row.fp_off = cie_base.fp_off;
				tmp[0] = DW_CFA_restore_extended;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				EMIT_OP(tmp, tn);
			} else if (reg == cie->ra_reg) {
				row.ra_rule = cie_base.ra_rule;
				row.ra_off = cie_base.ra_off;
				tmp[0] = DW_CFA_restore_extended;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				EMIT_OP(tmp, tn);
			} else if (reg == arch->sp_reg) {
				row.sp_rule = cie_base.sp_rule;
				row.sp_off = cie_base.sp_off;
				tmp[0] = DW_CFA_restore_extended;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_undefined:
			if (read_uleb128(insns, &pos, end, &reg))
				goto out;
			if (reg == arch->fp_reg || reg == cie->ra_reg ||
			    reg == arch->sp_reg) {
				if (reg == arch->fp_reg) {
					row.fp_rule = 3;
					row.fp_off = 0;
				} else if (reg == cie->ra_reg) {
					row.ra_rule = 3;
					row.ra_off = 0;
				} else {
					row.sp_rule = 3;
					row.sp_off = 0;
				}
				tmp[0] = DW_CFA_undefined;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_same_value:
			if (read_uleb128(insns, &pos, end, &reg))
				goto out;
			if (reg == arch->fp_reg || reg == cie->ra_reg ||
			    reg == arch->sp_reg) {
				if (reg == arch->fp_reg) {
					row.fp_rule = 0;
					row.fp_off = 0;
				} else if (reg == cie->ra_reg) {
					row.ra_rule = 0;
					row.ra_off = 0;
				} else {
					row.sp_rule = 0;
					row.sp_off = 0;
				}
				tmp[0] = DW_CFA_same_value;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				EMIT_OP(tmp, tn);
			}
			break;
		case DW_CFA_remember_state:
			if (sp >= 4)
				goto out;
			tmp[0] = DW_CFA_remember_state;
			EMIT_OP(tmp, 1);
			stack[sp].saved = row;
			stack[sp].ev_idx = nev - 1;
			sp++;
			break;
		case DW_CFA_restore_state:
			if (!sp)
				goto out;
			sp--;
			if (!rows_equal(&stack[sp].saved, &row)) {
				row = stack[sp].saved;
				tmp[0] = DW_CFA_restore_state;
				EMIT_OP(tmp, 1);
			} else {
				/*
				 * Elide dead remember_state..restore_state if
				 * no minimal ops occurred inside.
				 */
				size_t ridx = stack[sp].ev_idx;
				bool only_adv = true;
				uint32_t extra = 0;

				for (size_t k = ridx + 1; k < nev; k++) {
					if (!evs[k].is_adv || evs[k].has_reloc) {
						only_adv = false;
						break;
					}
					if (add_adv_u32(&extra, evs[k].adv))
						goto out;
				}
				if (only_adv) {
					if (add_adv_u32(&pending_adv, extra))
						goto out;
					nev = ridx;
				} else {
					tmp[0] = DW_CFA_restore_state;
					EMIT_OP(tmp, 1);
				}
			}
			break;
		case DW_CFA_AARCH64_negate_ra_state:
			if (arch->ra_reg != 30)
				goto out;
			row.ra_signed = !row.ra_signed;
			tmp[0] = DW_CFA_AARCH64_negate_ra_state;
			EMIT_OP(tmp, 1);
			break;
		case DW_CFA_GNU_args_size:
			if (read_uleb128(insns, &pos, end, &uval))
				goto out;
			break;
		case DW_CFA_register:
		case DW_CFA_val_offset:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_uleb128(insns, &pos, end, &uval))
				goto out;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				goto out;
			break;
		case DW_CFA_val_offset_sf:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_sleb128(insns, &pos, end, &sval))
				goto out;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				goto out;
			break;
		case DW_CFA_def_cfa_expression: {
			size_t epos = 1;

			if (read_uleb128(insns, &pos, end, &uval) ||
			    uval > end - pos || uval < 3 || uval > 7)
				goto out;
			if ((insns[pos] != (uint8_t)(DW_OP_breg0 + arch->fp_reg) &&
			     insns[pos] != (uint8_t)(DW_OP_breg0 + arch->sp_reg)) ||
			    insns[pos + uval - 1] != DW_OP_deref ||
			    read_sleb128(insns + pos, &epos, uval - 1, &sval) ||
			    epos != uval - 1)
				goto out;
			row.cfa_kind = (insns[pos] == (uint8_t)(DW_OP_breg0 + arch->fp_reg)) ?
				       2 : 3;
			row.cfa_reg = 0;
			row.cfa_off = sval;
			tmp[0] = DW_CFA_def_cfa_expression;
			tn = 1 + encode_uleb128(uval, tmp + 1);
			memcpy(tmp + tn, insns + pos, uval);
			tn += uval;
			pos += uval;
			EMIT_OP(tmp, tn);
			break;
		}
		case DW_CFA_expression: {
			size_t epos = 1;

			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_uleb128(insns, &pos, end, &uval) ||
			    uval > end - pos)
				goto out;
			if (reg == arch->fp_reg || reg == cie->ra_reg) {
				uint8_t fp_op = DW_OP_breg0 + arch->fp_reg;
				uint8_t sp_op = DW_OP_breg0 + arch->sp_reg;
				uint8_t b0 = insns[pos];

				if (uval < 2 || uval > 6 ||
				    (b0 != fp_op && b0 != sp_op) ||
				    (reg == cie->ra_reg && b0 != sp_op) ||
				    read_sleb128(insns + pos, &epos, uval, &sval) ||
				    epos != uval)
					goto out;
				if (reg == arch->fp_reg) {
					row.fp_rule = (b0 == fp_op) ? 2 : 4;
					row.fp_off = sval;
				} else {
					row.ra_rule = 4;
					row.ra_off = sval;
				}
				tmp[0] = DW_CFA_expression;
				tn = 1 + encode_uleb128(reg, tmp + 1);
				tn += encode_uleb128(uval, tmp + tn);
				memcpy(tmp + tn, insns + pos, uval);
				tn += uval;
				pos += uval;
				EMIT_OP(tmp, tn);
			} else if (reg == arch->sp_reg) {
				if (uval < 2 || uval > 6 || row.cfa_kind != 3 ||
				    insns[pos] != (uint8_t)(DW_OP_breg0 + arch->sp_reg) ||
				    read_sleb128(insns + pos, &epos, uval, &sval) ||
				    epos != uval || sval != row.cfa_off)
					goto out;
				pos += uval;
			} else {
				pos += uval;
			}
			break;
		}
		case DW_CFA_val_expression:
			if (read_uleb128(insns, &pos, end, &reg) ||
			    read_uleb128(insns, &pos, end, &uval) ||
			    pos + uval > end)
				goto out;
			if (reg == arch->sp_reg || reg == arch->fp_reg ||
			    reg == cie->ra_reg)
				goto out;
			pos += uval;
			break;
		default:
			goto out;
		}
	}

	/* Drop trailing advance_loc instructions */
	while (nev > 0 && evs[nev - 1].is_adv)
		nev--;

	{
		uint32_t acc = 0;
		size_t nrm = 0;

		for (size_t i = 0; i < nev; i++) {
			if (evs[i].is_adv && !evs[i].has_reloc) {
				if (add_adv_u32(&acc, evs[i].adv))
					goto out;
			} else {
				flush_adv_bytes(out_bytes, &acc);
				evs[i].new_off = out_bytes->len;
				if (evs[i].has_reloc)
					nrm++;
				buf_append(out_bytes, evs[i].bytes, evs[i].len);
			}
		}

		if (nrm && out_rmaps && out_nrmaps) {
			struct reloc_map *rm = calloc(nrm, sizeof(*rm));
			size_t idx = 0;

			if (!rm)
				goto out;
			for (size_t i = 0; i < nev; i++) {
				if (!evs[i].has_reloc)
					continue;
				rm[idx].orig_off = evs[i].orig_off;
				rm[idx].len = evs[i].len;
				rm[idx].new_off = evs[i].new_off;
				idx++;
			}
			*out_rmaps = rm;
			*out_nrmaps = nrm;
		}
	}

	*io_row = row;
	ret = 0;
out:
#undef EMIT_REL_ADV
#undef EMIT_OP
	free(evs);
	return ret;
}

static int anchor_add(struct anchor_list *al, size_t old_off, size_t len,
		      size_t new_off)
{
	if (al->len == al->cap) {
		size_t ncap = al->cap ? al->cap * 2 : 128;
		struct eh_anchor *nd = realloc(al->data, ncap * sizeof(*nd));

		if (!nd)
			return -1;
		al->data = nd;
		al->cap = ncap;
	}
	al->data[al->len++] = (struct eh_anchor){ old_off, len, new_off };
	return 0;
}

static int anchor_find_exact(const struct anchor_list *al, size_t old_off,
			     size_t *out_new_off)
{
	size_t lo = 0, hi = al->len;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (al->data[mid].old_off <= old_off)
			lo = mid + 1;
		else
			hi = mid;
	}
	if (!lo)
		return -1;
	lo--;
	if (old_off == al->data[lo].old_off ||
	    old_off - al->data[lo].old_off < al->data[lo].len) {
		*out_new_off = al->data[lo].new_off +
			       (old_off - al->data[lo].old_off);
		return 0;
	}
	return -1;
}

static size_t anchor_clamp_map(const struct anchor_list *al, size_t old_off,
			       size_t max_new)
{
	size_t mapped = 0;

	if (anchor_find_exact(al, old_off, &mapped) == 0)
		return mapped <= max_new ? mapped : max_new;

	for (size_t i = al->len; i-- > 0;) {
		if (al->data[i].old_off <= old_off) {
			size_t end_new = al->data[i].new_off + al->data[i].len;

			return end_new <= max_new ? end_new : max_new;
		}
	}
	return 0;
}

static bool sym_is_in_eh_frame(const Elf64_Sym *sym, size_t sym_i,
			       uint32_t eh_idx, const uint32_t *shndx_tab,
			       size_t nshndx)
{
	uint16_t shndx = r16(&sym->st_shndx);

	if (shndx == SHN_XINDEX)
		return shndx_tab && sym_i < nshndx &&
		       r32(&shndx_tab[sym_i]) == eh_idx;
	if (shndx >= SHN_LORESERVE)
		return false;
	return shndx == eh_idx;
}

static int cmp_rela_off(const void *a, const void *b)
{
	const struct indexed_rela *ra = a;
	const struct indexed_rela *rb = b;

	if (ra->rela.r_offset != rb->rela.r_offset)
		return (ra->rela.r_offset > rb->rela.r_offset) -
		       (ra->rela.r_offset < rb->rela.r_offset);
	return (ra->orig_idx > rb->orig_idx) - (ra->orig_idx < rb->orig_idx);
}

static size_t lower_bound_rela(const Elf64_Rela *relas, size_t nrelas, size_t off)
{
	size_t lo = 0, hi = nrelas;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (relas[mid].r_offset < off)
			lo = mid + 1;
		else
			hi = mid;
	}
	return lo;
}

static int remap_fde_relocs(const Elf64_Rela *loc_relas, size_t n_loc_relas,
			    size_t max_out_relas, size_t loc_off,
			    size_t new_fde_off,
			    const Elf64_Rela *insn_relas, size_t n_insn_relas,
			    const struct reloc_map *rmaps, size_t nrmaps,
			    size_t new_insns_base,
			    Elf64_Rela *out_relas, size_t *out_nrelas)
{
	for (size_t r = 0; r < n_loc_relas; r++) {
		if (*out_nrelas >= max_out_relas)
			return -1;
		out_relas[*out_nrelas] = loc_relas[r];
		out_relas[(*out_nrelas)++].r_offset =
			new_fde_off + 8 + (loc_relas[r].r_offset - loc_off);
	}

	for (size_t m = 0; m < nrmaps; m++) {
		size_t lo = rmaps[m].orig_off;
		size_t hi = lo + rmaps[m].len;

		for (size_t r = 0; r < n_insn_relas; r++) {
			if (insn_relas[r].r_offset < lo ||
			    insn_relas[r].r_offset >= hi)
				continue;
			if (*out_nrelas >= max_out_relas)
				return -1;
			out_relas[*out_nrelas] = insn_relas[r];
			out_relas[(*out_nrelas)++].r_offset =
				new_insns_base + rmaps[m].new_off +
				(insn_relas[r].r_offset - lo);
		}
	}
	return 0;
}

static int parse_cie_record(const uint8_t *eh_in, size_t p, size_t rec_end,
			    const struct arch_cfg *arch, struct cie_info *cie,
			    size_t *out_insns_off)
{
	uint8_t ver;
	const char *aug;
	size_t aug_len_str;
	uint32_t ra_col;

	if (p >= rec_end)
		return -1;
	ver = eh_in[p++];
	aug = (const char *)(eh_in + p);
	aug_len_str = strnlen(aug, rec_end - p);
	if (p + aug_len_str >= rec_end)
		return -1;
	p += aug_len_str + 1;
	if (ver == 4) {
		if (p + 2 > rec_end)
			return -1;
		p += 2;
	}
	if (read_uleb128(eh_in, &p, rec_end, &cie->code_align) ||
	    read_sleb128(eh_in, &p, rec_end, &cie->data_align))
		return -1;
	if (ver == 1) {
		if (p >= rec_end)
			return -1;
		ra_col = eh_in[p++];
	} else if (read_uleb128(eh_in, &p, rec_end, &ra_col)) {
		return -1;
	}
	cie->ra_reg = (uint8_t)ra_col;
	cie->fde_enc = DW_EH_PE_absptr;

	if (aug[0] == 'z') {
		uint32_t alen;
		size_t aend;

		cie->has_z = true;
		if (read_uleb128(eh_in, &p, rec_end, &alen) ||
		    alen > rec_end - p)
			return -1;
		aend = p + alen;
		for (size_t k = 1; aug[k]; k++) {
			uint8_t penc;
			int psz;

			if (aug[k] == 'R') {
				if (p >= aend)
					return -1;
				cie->fde_enc = eh_in[p++];
				if (cie->fde_enc & DW_EH_PE_indirect)
					return -1;
			} else if (aug[k] == 'L') {
				if (p >= aend)
					return -1;
				p++;
			} else if (aug[k] == 'P') {
				if (p >= aend)
					return -1;
				penc = eh_in[p++];
				psz = ptr_enc_size(penc & ~DW_EH_PE_indirect,
						   arch->addr_size);
				if (psz < 0 || (size_t)psz > aend - p)
					return -1;
				p += (size_t)psz;
			} else if (aug[k] == 'S') {
				cie->is_signal = true;
			} else if (aug[k] != 'B') {
				return -1;
			}
		}
		p = aend;
	} else if (aug[0] != '\0') {
		return -1;
	}

	*out_insns_off = p;
	return 0;
}

/*
 * Rewrite a 64-bit little-endian ET_REL object's .eh_frame and .rela.eh_frame
 * sections in place. Objects with unexpected formats or external relocations
 * into .eh_frame are left untouched (returning 0) so the build never breaks on
 * unusual hand-crafted assembly objects.
 */
static int process_elf64(uint8_t *map, size_t file_size)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
	Elf64_Shdr *shdrs;
	uint64_t shoff, shstr_off, shstr_size, eh_shoff, eh_align;
	uint16_t e_machine;
	uint32_t shnum, shstrndx;
	const char *shstrtab;
	Elf64_Shdr *eh_shdr = NULL, *rela_shdr = NULL, *sym_shdr = NULL;
	uint32_t eh_idx = 0, sym_idx = 0;
	Elf64_Sym *syms = NULL;
	size_t nsyms = 0, nshndx = 0;
	const uint32_t *shndx_tab = NULL;
	struct arch_cfg arch;
	const uint8_t *eh_in;
	size_t eh_in_len;
	Elf64_Rela *sorted_relas = NULL;
	size_t nrelas = 0, out_nrelas = 0;
	Elf64_Rela *out_relas = NULL;
	struct cie_info *cies = NULL;
	size_t ncies = 0, cies_cap = 0;
	struct anchor_list anchors = {};
	struct byte_buf out_eh = {};
	size_t last_len_pos = 0;
	bool have_last_rec = false;
	size_t pos = 0;

	if (r16(&ehdr->e_type) != ET_REL)
		return 0;

	e_machine = r16(&ehdr->e_machine);
	if (e_machine == EM_X86_64)
		arch = (struct arch_cfg){ 8, 7, 6, 16 };
	else if (e_machine == EM_AARCH64)
		arch = (struct arch_cfg){ 8, 31, 29, 30 };
	else if (e_machine == EM_RISCV)
		arch = (struct arch_cfg){ 8, 2, 8, 1 };
	else
		return 0;

	shoff = r64(&ehdr->e_shoff);
	if (!shoff || (shoff & 7) || shoff > file_size ||
	    file_size - shoff < sizeof(Elf64_Shdr))
		return 0;
	if (r16(&ehdr->e_shentsize) != sizeof(Elf64_Shdr))
		return -1;

	shdrs = (Elf64_Shdr *)(map + shoff);
	shnum = r16(&ehdr->e_shnum) ? r16(&ehdr->e_shnum) :
				      (uint32_t)r64(&shdrs[0].sh_size);
	if (!shnum ||
	    (size_t)shnum > (file_size - shoff) / sizeof(Elf64_Shdr))
		return -1;
	shstrndx = (r16(&ehdr->e_shstrndx) != SHN_XINDEX) ?
		   r16(&ehdr->e_shstrndx) : r32(&shdrs[0].sh_link);

	if (!shstrndx || shstrndx >= shnum)
		return -1;
	shstr_off = r64(&shdrs[shstrndx].sh_offset);
	shstr_size = r64(&shdrs[shstrndx].sh_size);
	if (shstr_off > file_size || shstr_size == 0 ||
	    shstr_size > file_size - shstr_off)
		return -1;
	shstrtab = (const char *)(map + shstr_off);

	for (uint32_t i = 1; i < shnum; i++) {
		uint32_t sh_type = r32(&shdrs[i].sh_type);
		uint32_t nm_off = r32(&shdrs[i].sh_name);

		if ((sh_type == SHT_PROGBITS ||
		     sh_type == SHT_X86_64_UNWIND) &&
		    nm_off < shstr_size &&
		    shstr_size - nm_off >= sizeof(".eh_frame") &&
		    memcmp(shstrtab + nm_off, ".eh_frame",
			   sizeof(".eh_frame")) == 0) {
			eh_shdr = &shdrs[i];
			eh_idx = i;
			break;
		}
	}

	if (!eh_shdr || r64(&eh_shdr->sh_size) == 0)
		return 0;
	eh_shoff = r64(&eh_shdr->sh_offset);
	eh_in_len = (size_t)r64(&eh_shdr->sh_size);
	eh_align = r64(&eh_shdr->sh_addralign);
	if (eh_shoff > file_size || eh_in_len > file_size - eh_shoff ||
	    eh_align > 16 || (eh_align & (eh_align - 1)) != 0)
		return -1;

	for (uint32_t i = 1; i < shnum; i++) {
		if (r32(&shdrs[i].sh_type) == SHT_RELA &&
		    r32(&shdrs[i].sh_info) == eh_idx) {
			rela_shdr = &shdrs[i];
			break;
		}
	}

	if (rela_shdr && r32(&rela_shdr->sh_link) > 0 &&
	    r32(&rela_shdr->sh_link) < shnum &&
	    r32(&shdrs[r32(&rela_shdr->sh_link)].sh_type) == SHT_SYMTAB) {
		sym_idx = r32(&rela_shdr->sh_link);
		sym_shdr = &shdrs[sym_idx];
	} else {
		for (uint32_t i = 1; i < shnum; i++) {
			if (r32(&shdrs[i].sh_type) == SHT_SYMTAB) {
				sym_idx = i;
				sym_shdr = &shdrs[i];
				break;
			}
		}
	}

	if (sym_shdr && r64(&sym_shdr->sh_size) > 0) {
		uint64_t sym_off = r64(&sym_shdr->sh_offset);
		uint64_t sym_sz = r64(&sym_shdr->sh_size);

		if ((sym_off & 7) || sym_off > file_size ||
		    sym_sz > file_size - sym_off ||
		    r64(&sym_shdr->sh_entsize) != sizeof(Elf64_Sym) ||
		    (sym_sz % sizeof(Elf64_Sym)) != 0)
			return -1;
		syms = (Elf64_Sym *)(map + sym_off);
		nsyms = (size_t)(sym_sz / sizeof(Elf64_Sym));

		for (uint32_t i = 1; i < shnum; i++) {
			if (r32(&shdrs[i].sh_type) == SHT_SYMTAB_SHNDX &&
			    r32(&shdrs[i].sh_link) == sym_idx) {
				uint64_t xoff = r64(&shdrs[i].sh_offset);
				uint64_t xsz = r64(&shdrs[i].sh_size);

				if ((xoff & 3) || xoff > file_size ||
				    xsz > file_size - xoff ||
				    r64(&shdrs[i].sh_entsize) != sizeof(uint32_t) ||
				    xsz != nsyms * sizeof(uint32_t))
					return -1;
				shndx_tab = (const uint32_t *)(map + xoff);
				nshndx = nsyms;
				break;
			}
		}

		/*
		 * Bail out cleanly if any other relocation section references
		 * symbols inside .eh_frame.
		 */
		for (uint32_t i = 1; i < shnum; i++) {
			const Elf64_Rela *other;
			size_t nother;
			uint64_t o_off, o_sz;

			if (&shdrs[i] == rela_shdr ||
			    r32(&shdrs[i].sh_type) != SHT_RELA ||
			    r32(&shdrs[i].sh_link) != sym_idx ||
			    r64(&shdrs[i].sh_size) == 0)
				continue;
			o_off = r64(&shdrs[i].sh_offset);
			o_sz = r64(&shdrs[i].sh_size);
			if ((o_off & 7) || o_off > file_size ||
			    o_sz > file_size - o_off ||
			    r64(&shdrs[i].sh_entsize) != sizeof(Elf64_Rela) ||
			    (o_sz % sizeof(Elf64_Rela)) != 0)
				return -1;
			other = (const Elf64_Rela *)(map + o_off);
			nother = (size_t)(o_sz / sizeof(Elf64_Rela));
			for (size_t r = 0; r < nother; r++) {
				uint32_t si = ELF64_R_SYM(r64(&other[r].r_info));

				if (si < nsyms &&
				    sym_is_in_eh_frame(&syms[si], si, eh_idx,
						       shndx_tab, nshndx))
					return 0;
			}
		}
	}

	eh_in = map + eh_shoff;
	if (rela_shdr && r64(&rela_shdr->sh_size) > 0) {
		struct indexed_rela *idx_relas;
		const Elf64_Rela *raw_relas;
		uint64_t r_off = r64(&rela_shdr->sh_offset);
		uint64_t r_sz = r64(&rela_shdr->sh_size);

		if ((r_off & 7) || r_off > file_size ||
		    r_sz > file_size - r_off ||
		    r64(&rela_shdr->sh_entsize) != sizeof(Elf64_Rela) ||
		    (r_sz % sizeof(Elf64_Rela)) != 0)
			return -1;
		nrelas = (size_t)(r_sz / sizeof(Elf64_Rela));
		idx_relas = malloc(nrelas * sizeof(*idx_relas));
		sorted_relas = malloc(nrelas * sizeof(Elf64_Rela));
		out_relas = calloc(nrelas, sizeof(Elf64_Rela));
		if (!idx_relas || !sorted_relas || !out_relas) {
			free(idx_relas);
			free(sorted_relas);
			free(out_relas);
			return -1;
		}
		raw_relas = (const Elf64_Rela *)(map + r_off);
		for (size_t i = 0; i < nrelas; i++) {
			idx_relas[i].rela.r_offset = r64(&raw_relas[i].r_offset);
			idx_relas[i].rela.r_info = r64(&raw_relas[i].r_info);
			idx_relas[i].rela.r_addend =
				(int64_t)r64((const uint64_t *)&raw_relas[i].r_addend);
			idx_relas[i].orig_idx = i;
		}
		qsort(idx_relas, nrelas, sizeof(*idx_relas), cmp_rela_off);
		for (size_t i = 0; i < nrelas; i++)
			sorted_relas[i] = idx_relas[i].rela;
		free(idx_relas);
	}

	if (anchor_add(&anchors, /*old_off=*/0, /*len=*/0, /*new_off=*/0))
		goto bail;

	while (pos + 4 <= eh_in_len) {
		uint32_t len = get_le32(eh_in + pos);
		size_t rec_start = pos;
		size_t rec_end, p;
		uint32_t cie_id;

		if (len == 0)
			break;
		if (len <= 4 || len == 0xffffffffU ||
		    len > eh_in_len - pos - 4) {
			free(anchors.data);
			free(cies);
			free(sorted_relas);
			free(out_eh.data);
			free(out_relas);
			return -1;
		}
		rec_end = pos + 4 + len;
		cie_id = get_le32(eh_in + pos + 4);
		p = pos + 8;

		if (cie_id == 0) {
			struct cie_info cie = {};
			struct byte_buf min_cie_insns = {};
			struct byte_buf cie_rec = {};
			const char *out_aug;
			uint8_t tmp[16];
			size_t tn;

			if (parse_cie_record(eh_in, p, rec_end, &arch, &cie, &p))
				goto bail;
			if (ncies >= cies_cap) {
				size_t ncap = cies_cap ? cies_cap * 2 : 64;
				struct cie_info *ncies_arr;

				ncies_arr = realloc(cies, ncap * sizeof(*cies));
				if (!ncies_arr)
					goto bail;
				cies = ncies_arr;
				cies_cap = ncap;
			}

			cie.old_off = rec_start;
			cie.new_off = out_eh.len;
			if (minify_insns(eh_in + p, rec_end - p, p,
					 /*insn_relas=*/NULL,
					 /*n_insn_relas=*/0, &cie, &arch,
					 /*is_cie=*/true, &cie.init_row,
					 &min_cie_insns, /*out_rmaps=*/NULL,
					 /*out_nrmaps=*/NULL)) {
				free(min_cie_insns.data);
				goto bail;
			}

			/* Emit normalized compact CIE (version 1, "zR" or "zRS") */
			out_aug = cie.is_signal ? "zRS" : "zR";
			if (cie.fde_enc == DW_EH_PE_absptr && !cie.has_z)
				out_aug = "";

			put_le32(tmp, 0);
			put_le32(tmp + 4, 0);
			buf_append(&cie_rec, tmp, 8);
			buf_append_u8(&cie_rec, 1);
			buf_append(&cie_rec, out_aug, strlen(out_aug) + 1);
			tn = encode_uleb128(cie.code_align, tmp);
			buf_append(&cie_rec, tmp, tn);
			tn = encode_sleb128(cie.data_align, tmp);
			buf_append(&cie_rec, tmp, tn);
			buf_append_u8(&cie_rec, cie.ra_reg);
			if (out_aug[0] == 'z') {
				buf_append_u8(&cie_rec, 1);
				buf_append_u8(&cie_rec, cie.fde_enc);
			}
			buf_append(&cie_rec, min_cie_insns.data, min_cie_insns.len);
			while (cie_rec.len & 3)
				buf_append_u8(&cie_rec, DW_CFA_nop);
			put_le32(cie_rec.data, (uint32_t)(cie_rec.len - 4));

			last_len_pos = out_eh.len;
			have_last_rec = true;
			if (anchor_add(&anchors, rec_start, /*len=*/8,
				       cie.new_off)) {
				free(min_cie_insns.data);
				free(cie_rec.data);
				goto bail;
			}
			buf_append(&out_eh, cie_rec.data, cie_rec.len);

			cies[ncies++] = cie;
			free(min_cie_insns.data);
			free(cie_rec.data);
		} else {
			size_t old_cie_off;
			const struct cie_info *cie = NULL;
			int ptr_sz;
			size_t loc_off, fde_insns_off;
			struct min_row fde_row;
			struct byte_buf min_fde_insns = {};
			struct byte_buf fde_rec = {};
			size_t new_fde_off;
			uint8_t hdr8[8];
			struct reloc_map *rmaps = NULL;
			size_t nrmaps = 0;
			const Elf64_Rela *loc_relas = NULL, *insn_relas = NULL;
			size_t n_loc_relas = 0, n_insn_relas = 0;

			if (cie_id > rec_start + 4)
				goto bail;
			old_cie_off = (rec_start + 4) - cie_id;
			for (size_t k = ncies; k-- > 0;) {
				if (cies[k].old_off == old_cie_off) {
					cie = &cies[k];
					break;
				}
			}
			if (!cie)
				goto bail;

			ptr_sz = ptr_enc_size(cie->fde_enc, arch.addr_size);
			if (ptr_sz <= 0 || p + 2 * (size_t)ptr_sz > rec_end)
				goto bail;
			loc_off = p;
			p += 2 * (size_t)ptr_sz;

			if (cie->has_z) {
				uint32_t alen;

				if (read_uleb128(eh_in, &p, rec_end, &alen) ||
				    p + alen > rec_end)
					goto bail;
				p += alen;
			}
			fde_insns_off = p;
			fde_row = cie->init_row;

			if (nrelas) {
				size_t l_lo = lower_bound_rela(sorted_relas,
							       nrelas, loc_off);
				size_t l_hi = lower_bound_rela(sorted_relas,
							       nrelas,
							       loc_off + 2 * (size_t)ptr_sz);
				size_t i_lo = lower_bound_rela(sorted_relas,
							       nrelas,
							       fde_insns_off);
				size_t i_hi = lower_bound_rela(sorted_relas,
							       nrelas, rec_end);

				loc_relas = sorted_relas + l_lo;
				n_loc_relas = l_hi - l_lo;
				insn_relas = sorted_relas + i_lo;
				n_insn_relas = i_hi - i_lo;
			}

			if (minify_insns(eh_in + fde_insns_off,
					 rec_end - fde_insns_off,
					 fde_insns_off, insn_relas,
					 n_insn_relas, cie, &arch,
					 /*is_cie=*/false, &fde_row,
					 &min_fde_insns, &rmaps,
					 &nrmaps) == 0) {
				size_t new_insns_base;

				new_fde_off = out_eh.len;
				put_le32(hdr8, 0);
				put_le32(hdr8 + 4,
					 (uint32_t)((new_fde_off + 4) - cie->new_off));
				buf_append(&fde_rec, hdr8, 8);
				buf_append(&fde_rec, eh_in + loc_off,
					   2 * (size_t)ptr_sz);
				if (cie->has_z || cie->is_signal ||
				    cie->fde_enc != DW_EH_PE_absptr)
					buf_append_u8(&fde_rec, 0);
				new_insns_base = new_fde_off + fde_rec.len;
				buf_append(&fde_rec, min_fde_insns.data,
					   min_fde_insns.len);
				while (fde_rec.len & 3)
					buf_append_u8(&fde_rec, DW_CFA_nop);
				put_le32(fde_rec.data,
					 (uint32_t)(fde_rec.len - 4));

				if (remap_fde_relocs(loc_relas, n_loc_relas,
						     nrelas, loc_off,
						     new_fde_off, insn_relas,
						     n_insn_relas, rmaps,
						     nrmaps, new_insns_base,
						     out_relas, &out_nrelas)) {
					free(rmaps);
					free(min_fde_insns.data);
					free(fde_rec.data);
					goto bail;
				}

				if (anchor_add(&anchors, rec_start,
					       8 + 2 * (size_t)ptr_sz,
					       new_fde_off) ||
				    anchor_add(&anchors, fde_insns_off,
					       /*len=*/0, new_insns_base)) {
					free(rmaps);
					free(min_fde_insns.data);
					free(fde_rec.data);
					goto bail;
				}
				for (size_t m = 0; m < nrmaps; m++) {
					if (anchor_add(&anchors,
						       rmaps[m].orig_off,
						       rmaps[m].len,
						       new_insns_base + rmaps[m].new_off)) {
						free(rmaps);
						free(min_fde_insns.data);
						free(fde_rec.data);
						goto bail;
					}
				}

				last_len_pos = out_eh.len;
				have_last_rec = true;
				buf_append(&out_eh, fde_rec.data, fde_rec.len);
			}
			free(rmaps);
			/* Unsupported FDEs are cleanly dropped along with their relocs */
			free(min_fde_insns.data);
			free(fde_rec.data);
		}

		pos = rec_end;
	}

	/* Pad final record with DW_CFA_nop to section alignment (8 bytes) */
	if (have_last_rec && eh_align > 4) {
		size_t align = (size_t)eh_align;

		while (out_eh.len & (align - 1))
			buf_append_u8(&out_eh, DW_CFA_nop);
		put_le32(out_eh.data + last_len_pos,
			 (uint32_t)(out_eh.len - last_len_pos - 4));
	}

	if (anchor_add(&anchors, pos, /*len=*/0, out_eh.len) ||
	    anchor_add(&anchors, eh_in_len, /*len=*/0, out_eh.len))
		goto bail;

	/*
	 * Update any .rela.eh_frame relocations whose target symbol resides in
	 * .eh_frame (e.g. R_RISCV_SUB32 subtracting FDE initial_location).
	 */
	for (size_t r = 0; r < out_nrelas; r++) {
		uint32_t si = ELF64_R_SYM(out_relas[r].r_info);
		uint64_t sym_val;
		int64_t old_target;
		size_t new_target, new_sym_val;

		if (!si)
			continue;
		if (!syms || si >= nsyms)
			goto bail;
		if (!sym_is_in_eh_frame(&syms[si], si, eh_idx, shndx_tab, nshndx))
			continue;

		sym_val = r64(&syms[si].st_value);
		old_target = (int64_t)sym_val + out_relas[r].r_addend;
		if (old_target <= 0 || (uint64_t)old_target > eh_in_len ||
		    anchor_find_exact(&anchors, (size_t)old_target, &new_target))
			goto bail;

		if (ELF64_ST_TYPE(syms[si].st_info) == STT_SECTION) {
			out_relas[r].r_addend = (int64_t)new_target -
						(int64_t)sym_val;
		} else {
			if (sym_val > eh_in_len ||
			    anchor_find_exact(&anchors, (size_t)sym_val,
					      &new_sym_val))
				goto bail;
			out_relas[r].r_addend = (int64_t)new_target -
						(int64_t)new_sym_val;
		}
	}

	if (have_last_rec && out_eh.data && out_eh.len <= eh_in_len) {
		if (syms) {
			for (size_t s = 1; s < nsyms; s++) {
				uint64_t sv;

				if (!sym_is_in_eh_frame(&syms[s], s, eh_idx,
							shndx_tab, nshndx) ||
				    ELF64_ST_TYPE(syms[s].st_info) == STT_SECTION)
					continue;
				sv = r64(&syms[s].st_value);
				w64(&syms[s].st_value,
				    anchor_clamp_map(&anchors, (size_t)sv,
						     out_eh.len));
			}
		}
		memcpy(map + eh_shoff, out_eh.data, out_eh.len);
		w64(&eh_shdr->sh_size, out_eh.len);
		if (rela_shdr && out_relas) {
			Elf64_Rela *dst =
				(Elf64_Rela *)(map + r64(&rela_shdr->sh_offset));

			for (size_t r = 0; r < out_nrelas; r++) {
				w64(&dst[r].r_offset, out_relas[r].r_offset);
				w64(&dst[r].r_info, out_relas[r].r_info);
				w64((uint64_t *)&dst[r].r_addend,
				    (uint64_t)out_relas[r].r_addend);
			}
			w64(&rela_shdr->sh_size,
			    out_nrelas * sizeof(Elf64_Rela));
		}
	}

	free(anchors.data);
	free(cies);
	free(sorted_relas);
	free(out_eh.data);
	free(out_relas);
	return 0;

bail:
	/* Leave unusual/hand-crafted .eh_frame untouched rather than failing build */
	free(anchors.data);
	free(cies);
	free(sorted_relas);
	free(out_eh.data);
	free(out_relas);
	return 0;
}

int main(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		const char *path = argv[i];
		struct stat st;
		uint8_t *map;
		int fd, rc = 0;

		fd = open(path, O_RDWR);
		if (fd < 0) {
			perror(path);
			return 1;
		}
		if (fstat(fd, &st) < 0) {
			perror("fstat");
			close(fd);
			return 1;
		}
		if ((size_t)st.st_size < sizeof(Elf64_Ehdr)) {
			close(fd);
			continue;
		}
		map = mmap(/*addr=*/NULL, (size_t)st.st_size,
			   PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			   /*offset=*/0);
		if (map == MAP_FAILED) {
			perror("mmap");
			close(fd);
			return 1;
		}
		if (memcmp(map, ELFMAG, SELFMAG) == 0 &&
		    map[EI_DATA] == ELFDATA2LSB &&
		    map[EI_CLASS] == ELFCLASS64)
			rc = process_elf64(map, (size_t)st.st_size);

		munmap(map, (size_t)st.st_size);
		close(fd);
		if (rc)
			return 1;
	}
	return 0;
}
