/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Definitions of RISC-V registers
 *
 * Copyright (c) 2023 Rivos Inc
 *
 */

#ifndef _ASM_RISCV_REG_H
#define _ASM_RISCV_REG_H

#include <linux/types.h>
#include <linux/bitops.h>

enum {
	RV_REG_ZERO =	0,	/* The constant value 0 */
	RV_REG_RA =	1,	/* Return address */
	RV_REG_SP =	2,	/* Stack pointer */
	RV_REG_GP =	3,	/* Global pointer */
	RV_REG_TP =	4,	/* Thread pointer */
	RV_REG_T0 =	5,	/* Temporaries */
	RV_REG_T1 =	6,
	RV_REG_T2 =	7,
	RV_REG_FP =	8,	/* Saved register/frame pointer */
	RV_REG_S1 =	9,	/* Saved register */
	RV_REG_A0 =	10,	/* Function argument/return values */
	RV_REG_A1 =	11,	/* Function arguments */
	RV_REG_A2 =	12,
	RV_REG_A3 =	13,
	RV_REG_A4 =	14,
	RV_REG_A5 =	15,
	RV_REG_A6 =	16,
	RV_REG_A7 =	17,
	RV_REG_S2 =	18,	/* Saved registers */
	RV_REG_S3 =	19,
	RV_REG_S4 =	20,
	RV_REG_S5 =	21,
	RV_REG_S6 =	22,
	RV_REG_S7 =	23,
	RV_REG_S8 =	24,
	RV_REG_S9 =	25,
	RV_REG_S10 =	26,
	RV_REG_S11 =	27,
	RV_REG_T3 =	28,	/* Temporaries */
	RV_REG_T4 =	29,
	RV_REG_T5 =	30,
	RV_REG_T6 =	31,
};

static inline bool is_creg(u8 reg)
{
	return (1 << reg) & (BIT(RV_REG_FP) |
			     BIT(RV_REG_S1) |
			     BIT(RV_REG_A0) |
			     BIT(RV_REG_A1) |
			     BIT(RV_REG_A2) |
			     BIT(RV_REG_A3) |
			     BIT(RV_REG_A4) |
			     BIT(RV_REG_A5));
}

static inline bool rv_insn_reg_get_val(unsigned long *regs, u32 index,
				       unsigned long *ptr)
{
	if (index == 0)
		*ptr = 0;
	else if (index <= 31)
		*ptr = *((unsigned long *)regs + index);
	else
		return false;

	return true;
}

static inline bool rv_insn_reg_set_val(unsigned long *regs, u32 index,
				       unsigned long val)
{
	if (index == 0)
		return false;
	else if (index <= 31)
		*((unsigned long *)regs + index) = val;
	else
		return false;

	return true;
}

#endif /* _ASM_RISCV_REG_H */
