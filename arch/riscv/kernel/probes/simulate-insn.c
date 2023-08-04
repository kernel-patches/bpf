// SPDX-License-Identifier: GPL-2.0+

#include <asm/insn.h>
#include <asm/reg.h>
#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>

#include "decode-insn.h"
#include "simulate-insn.h"

bool __kprobes simulate_jal(u32 opcode, unsigned long addr, struct pt_regs *regs)
{
	/*
	 *     31    30       21    20     19        12 11 7 6      0
	 * imm [20] | imm[10:1] | imm[11] | imm[19:12] | rd | opcode
	 *     1         10          1           8       5    JAL/J
	 */
	bool ret;
	s32 imm;
	u32 index = riscv_insn_extract_rd(opcode);

	ret = rv_insn_reg_set_val((unsigned long *)regs, index, addr + 4);
	if (!ret)
		return ret;

	imm = riscv_insn_extract_jtype_imm(opcode);

	instruction_pointer_set(regs, addr + imm);

	return ret;
}

bool __kprobes simulate_jalr(u32 opcode, unsigned long addr, struct pt_regs *regs)
{
	/*
	 * 31          20 19 15 14 12 11 7 6      0
	 *  offset[11:0] | rs1 | 010 | rd | opcode
	 *      12         5      3    5    JALR/JR
	 */
	bool ret;
	unsigned long base_addr;
	s32 imm = riscv_insn_extract_itype_imm(opcode);
	u32 rd_index = riscv_insn_extract_rd(opcode);
	u32 rs1_index = riscv_insn_extract_rs1(opcode);

	ret = rv_insn_reg_get_val((unsigned long *)regs, rs1_index, &base_addr);
	if (!ret)
		return ret;

	ret = rv_insn_reg_set_val((unsigned long *)regs, rd_index, addr + 4);
	if (!ret)
		return ret;

	instruction_pointer_set(regs, (base_addr + imm) & ~1);

	return ret;
}

bool __kprobes simulate_auipc(u32 opcode, unsigned long addr, struct pt_regs *regs)
{
	/*
	 * auipc instruction:
	 *  31        12 11 7 6      0
	 * | imm[31:12] | rd | opcode |
	 *        20       5     7
	 */

	u32 rd_idx = riscv_insn_extract_rd(opcode);
	unsigned long rd_val = addr + riscv_insn_extract_utype_imm(opcode);

	if (!rv_insn_reg_set_val((unsigned long *)regs, rd_idx, rd_val))
		return false;

	instruction_pointer_set(regs, addr + 4);
	return true;
}

bool __kprobes simulate_branch(u32 opcode, unsigned long addr, struct pt_regs *regs)
{
	/*
	 * branch instructions:
	 *      31    30       25 24 20 19 15 14    12 11       8    7      6      0
	 * | imm[12] | imm[10:5] | rs2 | rs1 | funct3 | imm[4:1] | imm[11] | opcode |
	 *     1           6        5     5      3         4         1         7
	 *     imm[12|10:5]        rs2   rs1    000       imm[4:1|11]       1100011  BEQ
	 *     imm[12|10:5]        rs2   rs1    001       imm[4:1|11]       1100011  BNE
	 *     imm[12|10:5]        rs2   rs1    100       imm[4:1|11]       1100011  BLT
	 *     imm[12|10:5]        rs2   rs1    101       imm[4:1|11]       1100011  BGE
	 *     imm[12|10:5]        rs2   rs1    110       imm[4:1|11]       1100011  BLTU
	 *     imm[12|10:5]        rs2   rs1    111       imm[4:1|11]       1100011  BGEU
	 */

	s32 offset;
	s32 offset_tmp;
	unsigned long rs1_val;
	unsigned long rs2_val;

	if (!rv_insn_reg_get_val((unsigned long *)regs, riscv_insn_extract_rs1(opcode), &rs1_val) ||
	    !rv_insn_reg_get_val((unsigned long *)regs, riscv_insn_extract_rs2(opcode), &rs2_val))
		return false;

	offset_tmp = riscv_insn_extract_btype_imm(opcode);
	switch (riscv_insn_extract_funct3(opcode)) {
	case RVG_FUNCT3_BEQ:
		offset = (rs1_val == rs2_val) ? offset_tmp : 4;
		break;
	case RVG_FUNCT3_BNE:
		offset = (rs1_val != rs2_val) ? offset_tmp : 4;
		break;
	case RVG_FUNCT3_BLT:
		offset = ((long)rs1_val < (long)rs2_val) ? offset_tmp : 4;
		break;
	case RVG_FUNCT3_BGE:
		offset = ((long)rs1_val >= (long)rs2_val) ? offset_tmp : 4;
		break;
	case RVG_FUNCT3_BLTU:
		offset = (rs1_val < rs2_val) ? offset_tmp : 4;
		break;
	case RVG_FUNCT3_BGEU:
		offset = (rs1_val >= rs2_val) ? offset_tmp : 4;
		break;
	default:
		return false;
	}

	instruction_pointer_set(regs, addr + offset);

	return true;
}
