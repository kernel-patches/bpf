// SPDX-License-Identifier: GPL-2.0
/*
 * Alpha architecture jump label (static key) support
 *
 * Implements runtime patching of static key sites by replacing
 * a NOP instruction with an unconditional branch and vice versa.
 *
 * Copyright (C) 2026 Magnus Lindholm <linmag7@gmail.com>
 */

#include <linux/cacheflush.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>

/*
 * Alpha instruction encoding helpers.
 *
 * Branch format:
 *   [31:26] opcode
 *   [25:21] Ra
 *   [20:0 ] disp (signed, in instructions; hardware multiplies by 4)
 *
 * Unconditional branch:
 *   BR opcode is 0x30.  We use Ra=r31 so no link register is written.
 *
 * Updated PC semantics:
 *   Target = (pc + 4) + (disp << 2)
 * so disp = (target - (pc + 4)) >> 2.
 */
#define ALPHA_OP_BR	0x30
#define ALPHA_RA_R31	31
#define ALPHA_BR_DISP_MASK	((1u << 21) - 1)

#define ALPHA_INSN_NOP	0x47FF041Fu /* BIS r31,r31,r31 */

static inline bool alpha_br_insn(unsigned long pc, unsigned long target,
				 u32 *insn)
{
	long off_bytes = (long)target - (long)(pc + 4);
	long disp = off_bytes >> 2;

	/*
	 * 21-bit signed displacement: range is [-2^20, 2^20-1] instructions.
	 * If this trips, the site/target are too far apart for a BR.
	 */
	if (WARN_ON_ONCE(disp < -(1L << 20) || disp > ((1L << 20) - 1)))
		return false;

	*insn = (ALPHA_OP_BR << 26) |
		(ALPHA_RA_R31 << 21) |
		((u32)disp & ALPHA_BR_DISP_MASK);
	return true;
}

static inline void alpha_patch_text(u32 *site, u32 insn)
{
	WRITE_ONCE(*site, insn);
	/*
	 * Alpha needs an I-cache sync after patching executable text.
	 */
	flush_icache_range((unsigned long)site, (unsigned long)site + sizeof(*site));
}

void arch_jump_label_transform(struct jump_entry *entry,
			       enum jump_label_type type)
{
	u32 *site = (u32 *)jump_entry_code(entry);
	u32 insn;

	if (type == JUMP_LABEL_JMP) {
		if (!alpha_br_insn((unsigned long)site, jump_entry_target(entry),
				   &insn))
			return;
	} else {
		insn = ALPHA_INSN_NOP;
	}

	alpha_patch_text(site, insn);
}
