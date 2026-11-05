// SPDX-License-Identifier: GPL-2.0+

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/bug.h>
#include <asm/sections.h>

#include "decode-insn.h"
#include "simulate-insn.h"

/*
 * Can insn sit between the lr and the sc of a constrained LR/SC sequence?
 * The ISA allows base integer instructions there, except loads, stores,
 * JALR, FENCE, SYSTEM, backward jumps and taken backward branches, plus
 * their compressed forms. Backward branches are treated as not allowed:
 * the retry branch follows the sc, so one inside the body is not a
 * constrained sequence.
 */
static bool __kprobes riscv_insn_is_lrsc_body(u32 insn)
{
	u32 funct3;

	if (GET_INSN_LENGTH(insn) == 2) {
		switch (insn & RVC_INSN_OPCODE_MASK) {
		case RVC_OPCODE_C0:
			/* c.addi4spn; the rest of the quadrant is loads and stores */
			return (insn & RVC_INSN_FUNCT3_MASK) == 0;
		case RVC_OPCODE_C1:
			/* Arithmetic, c.j, c.jal and branches, bit 12 is the offset sign */
			if (riscv_insn_is_c_j(insn) || riscv_insn_is_c_jal(insn) ||
			    riscv_insn_is_c_beqz(insn) || riscv_insn_is_c_bnez(insn))
				return !(insn & BIT(12));
			return true;
		case RVC_OPCODE_C2:
			funct3 = (insn & RVC_INSN_FUNCT3_MASK) >> RVC_INSN_FUNCT3_OPOFF;
			if (funct3 == 0)	/* c.slli */
				return true;
			if (funct3 == 4)	/* c.mv, c.add, but not c.jr, c.jalr, c.ebreak */
				return !riscv_insn_is_c_jr(insn) &&
				       !riscv_insn_is_c_jalr(insn) &&
				       !riscv_insn_is_c_ebreak(insn);
			return false;	/* stack loads and stores */
		}
		return false;
	}

	switch (insn & RV_INSN_OPCODE_MASK) {
	case RVG_OPCODE_OP_IMM:
	case RVG_OPCODE_OP_IMM_32:
	case RVG_OPCODE_LUI:
	case RVG_OPCODE_AUIPC:
		return true;
	case RVG_OPCODE_OP:
	case RVG_OPCODE_OP_32:
		/* funct7 0 or 0x20 is base I; anything else is M, B or another extension */
		return !((insn & RV_INSN_FUNCT7_MASK) & ~(0x20U << RV_INSN_FUNCT7_OPOFF));
	case RVG_OPCODE_BRANCH:
	case RVG_OPCODE_JAL:
		/* forward only, bit 31 is the offset sign */
		return !(insn & BIT(31));
	}
	return false;
}

/*
 * Does the instruction at the start of buf lie inside a constrained LR/SC
 * sequence? Such a sequence holds at most RISCV_LRSC_MAX_BODY instructions
 * between the lr and the sc, all from the set above. Walk forward from the
 * probed instruction: reaching an sc through permitted instructions only
 * means the probe sits in the body; anything else, including an lr that
 * opens a new sequence, means it does not. The walk stops at the end of
 * buf, so a short buffer only makes the answer more permissive.
 */
bool __kprobes riscv_probe_in_lrsc_body(const u16 *buf, size_t len)
{
	size_t off = 0;
	u32 insn;
	int n;

	for (n = 0; n <= RISCV_LRSC_MAX_BODY; n++) {
		if (off + 2 > len)
			return false;
		insn = buf[off / 2];
		if (GET_INSN_LENGTH(insn) == 4) {
			if (off + 4 > len)
				return false;
			insn |= (u32)buf[off / 2 + 1] << 16;
		}
		if (riscv_insn_is_sc(insn))
			return true;
		if (!riscv_insn_is_lrsc_body(insn))
			return false;
		off += GET_INSN_LENGTH(insn);
	}
	return false;
}

/* Return:
 *   INSN_REJECTED     If instruction is one not allowed to kprobe,
 *   INSN_GOOD_NO_SLOT If instruction is supported but doesn't use its slot.
 */
enum probe_insn __kprobes
riscv_probe_decode_insn(probe_opcode_t *addr, struct arch_probe_insn *api)
{
	probe_opcode_t insn = *addr;

	/*
	 * Reject instructions list:
	 */
	RISCV_INSN_REJECTED(system,		insn);
	RISCV_INSN_REJECTED(fence,		insn);
	/*
	 * The breakpoint trap drops the reservation, so a probe on either
	 * end of an LR/SC sequence makes the SC fail on every retry.
	 */
	RISCV_INSN_REJECTED(lr,			insn);
	RISCV_INSN_REJECTED(sc,			insn);

	/*
	 * Simulate instructions list:
	 * TODO: the REJECTED ones below need to be implemented
	 */
#ifdef CONFIG_RISCV_ISA_C
	RISCV_INSN_REJECTED(c_ebreak,		insn);

	RISCV_INSN_SET_SIMULATE(c_j,		insn);
	RISCV_INSN_SET_SIMULATE(c_jr,		insn);
	RISCV_INSN_SET_SIMULATE(c_jalr,		insn);
	RISCV_INSN_SET_SIMULATE(c_jal,		insn);
	RISCV_INSN_SET_SIMULATE(c_beqz,		insn);
	RISCV_INSN_SET_SIMULATE(c_bnez,		insn);
#endif

	RISCV_INSN_SET_SIMULATE(jal,		insn);
	RISCV_INSN_SET_SIMULATE(jalr,		insn);
	RISCV_INSN_SET_SIMULATE(auipc,		insn);
	RISCV_INSN_SET_SIMULATE(branch,		insn);

	return INSN_GOOD;
}
