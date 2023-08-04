/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 SiFive
 */

#ifndef _ASM_RISCV_INSN_H
#define _ASM_RISCV_INSN_H

#include <linux/bits.h>
#include <asm/reg.h>

#define RV_INSN_FUNCT5_IN_OPOFF	2
#define RV_INSN_AQ_IN_OPOFF	1
#define RV_INSN_RL_IN_OPOFF	0

#define RV_INSN_OPCODE_OPOFF	0
#define RV_INSN_FUNCT3_OPOFF	12
#define RV_INSN_FUNCT5_OPOFF	27
#define RV_INSN_FUNCT7_OPOFF	25
#define RV_INSN_FUNCT12_OPOFF	20
#define RV_INSN_RD_OPOFF	7
#define RV_INSN_RS1_OPOFF	15
#define RV_INSN_RS2_OPOFF	20
#define RV_INSN_OPCODE_MASK	GENMASK(6, 0)
#define RV_INSN_FUNCT3_MASK	GENMASK(2, 0)
#define RV_INSN_FUNCT5_MASK	GENMASK(4, 0)
#define RV_INSN_FUNCT7_MASK	GENMASK(6, 0)
#define RV_INSN_FUNCT12_MASK	GENMASK(11, 0)
#define RV_INSN_RD_MASK		GENMASK(4, 0)
#define RV_INSN_RS1_MASK	GENMASK(4, 0)
#define RV_INSN_RS2_MASK	GENMASK(4, 0)

/* The bit field of immediate value in I-type instruction */
#define RV_I_IMM_SIGN_OPOFF	31
#define RV_I_IMM_11_0_OPOFF	20
#define RV_I_IMM_SIGN_OFF	12
#define RV_I_IMM_11_0_OFF	0
#define RV_I_IMM_11_0_MASK	GENMASK(11, 0)

/* The bit field of immediate value in S-type instruction */
#define RV_S_IMM_11_5_OPOFF	25
#define RV_S_IMM_4_0_OPOFF	7
#define RV_S_IMM_11_5_OFF	5
#define RV_S_IMM_4_0_OFF	0
#define RV_S_IMM_11_5_MASK	GENMASK(6, 0)
#define RV_S_IMM_4_0_MASK	GENMASK(4, 0)

/* The bit field of immediate value in B-type instruction */
#define RV_B_IMM_SIGN_OPOFF	31
#define RV_B_IMM_4_1_OPOFF	8
#define RV_B_IMM_10_5_OPOFF	25
#define RV_B_IMM_11_OPOFF	7
#define RV_B_IMM_SIGN_OFF	12
#define RV_B_IMM_4_1_OFF	1
#define RV_B_IMM_10_5_OFF	5
#define RV_B_IMM_11_OFF		11
#define RV_B_IMM_SIGN_MASK	GENMASK(0, 0)
#define RV_B_IMM_4_1_MASK	GENMASK(3, 0)
#define RV_B_IMM_10_5_MASK	GENMASK(5, 0)
#define RV_B_IMM_11_MASK	GENMASK(0, 0)

/* The bit field of immediate value in S-type instruction */
#define RV_S_IMM_31_12_OPOFF	12
#define RV_S_IMM_31_12_OFF	12
#define RV_S_IMM_31_12_MASK	GENMASK(19, 0)

/* The bit field of immediate value in J-type instruction */
#define RV_J_IMM_SIGN_OPOFF	31
#define RV_J_IMM_10_1_OPOFF	21
#define RV_J_IMM_11_OPOFF	20
#define RV_J_IMM_19_12_OPOFF	12
#define RV_J_IMM_SIGN_OFF	20
#define RV_J_IMM_10_1_OFF	1
#define RV_J_IMM_11_OFF		11
#define RV_J_IMM_19_12_OFF	12
#define RV_J_IMM_10_1_MASK	GENMASK(9, 0)
#define RV_J_IMM_11_MASK	GENMASK(0, 0)
#define RV_J_IMM_19_12_MASK	GENMASK(7, 0)

/*
 * U-type IMMs contain the upper 20bits [31:12] of an immediate with
 * the rest filled in by zeros, so no shifting required. Similarly,
 * bit31 contains the signed state, so no sign extension necessary.
 */
#define RV_U_IMM_SIGN_OPOFF	31
#define RV_U_IMM_31_12_OPOFF	12
#define RV_U_IMM_31_12_OFF	12
#define RV_U_IMM_SIGN_OFF	31
#define RV_U_IMM_31_12_MASK	GENMASK(19, 0)

/* The register offset in RVG instruction */
#define RVG_RS1_OPOFF		15
#define RVG_RS2_OPOFF		20
#define RVG_RD_OPOFF		7
#define RVG_RS1_MASK		GENMASK(4, 0)
#define RVG_RS2_MASK		GENMASK(4, 0)
#define RVG_RD_MASK		GENMASK(4, 0)

/* Register sizes in RV instructions */
#define RV_STANDARD_REG_BITS	5
#define RV_COMPRESSED_REG_BITS	3
#define RV_STANDARD_REG_MASK	GENMASK(4, 0)
#define RV_COMPRESSED_REG_MASK	GENMASK(2, 0)

/* The bit field for F,D,Q extensions */
#define RVG_FL_FS_WIDTH_OFF	12
#define RVG_FL_FS_WIDTH_MASK	GENMASK(3, 0)
#define RVG_FL_FS_WIDTH_W	2
#define RVG_FL_FS_WIDTH_D	3
#define RVG_LS_FS_WIDTH_Q	4

/* The bit field for Zicsr extension */
#define RVG_SYSTEM_CSR_OPOFF	20
#define RVG_SYSTEM_CSR_MASK	GENMASK(12, 0)

/* RVV widths */
#define RVV_VL_VS_WIDTH_8	0
#define RVV_VL_VS_WIDTH_16	5
#define RVV_VL_VS_WIDTH_32	6
#define RVV_VL_VS_WIDTH_64	7

/* The bit field of immediate value in RVC I instruction */
#define RVC_I_IMM_LO_OPOFF	2
#define RVC_I_IMM_HI_OPOFF	12
#define RVC_I_IMM_LO_OFF	0
#define RVC_I_IMM_HI_OFF	0
#define RVC_I_IMM_LO_MASK	GENMASK(4, 0)
#define RVC_I_IMM_HI_MASK	GENMASK(0, 0)

/* The bit field of immediate value in RVC SS instruction */
#define RVC_SS_IMM_OPOFF	6
#define RVC_SS_IMM_OFF		0
#define RVC_SS_IMM_MASK		GENMASK(5, 0)

/* The bit field of immediate value in RVC IW instruction */
#define RVC_IW_IMM_OPOFF	5
#define RVC_IW_IMM_OFF		0
#define RVC_IW_IMM_MASK		GENMASK(7, 0)

/* The bit field of immediate value in RVC L instruction */
#define RVC_L_IMM_LO_OPOFF	5
#define RVC_L_IMM_HI_OPOFF	10
#define RVC_L_IMM_LO_OFF	0
#define RVC_L_IMM_HI_OFF	0
#define RVC_L_IMM_LO_MASK	GENMASK(1, 0)
#define RVC_L_IMM_HI_MASK	GENMASK(2, 0)

/* The bit field of immediate value in RVC S instruction */
#define RVC_S_IMM_LO_OPOFF	5
#define RVC_S_IMM_HI_OPOFF	10
#define RVC_S_IMM_LO_OFF	0
#define RVC_S_IMM_HI_OFF	0
#define RVC_S_IMM_LO_MASK	GENMASK(1, 0)
#define RVC_S_IMM_HI_MASK	GENMASK(2, 0)

/* The bit field of immediate value in RVC B instruction */
#define RVC_B_IMM_LO_OFF	2
#define RVC_B_IMM_HI_OFF	10
#define RVC_B_IMM_LO_OPOFF	0
#define RVC_B_IMM_HI_OPOFF	0
#define RVC_B_IMM_LO_MASK	GENMASK(4, 0)
#define RVC_B_IMM_HI_MASK	GENMASK(2, 0)

/* The bit field of immediate value in RVC J instruction */
#define RVC_J_IMM_OFF		2
#define RVC_J_IMM_OPOFF		0
#define RVC_J_IMM_MASK		GENMASK(10, 0)

/*
 * Bit field of various RVC instruction immediates.
 * These base OPOFF on the start of the immediate
 * rather than the start of the instruction.
 */

/* The bit field of immediate value in RVC ADDI4SPN instruction */
#define RVC_ADDI4SPN_IMM_5_4_OPOFF	11
#define RVC_ADDI4SPN_IMM_9_6_OPOFF	7
#define RVC_ADDI4SPN_IMM_2_OPOFF	6
#define RVC_ADDI4SPN_IMM_3_OPOFF	5
#define RVC_ADDI4SPN_IMM_5_4_OFF	4
#define RVC_ADDI4SPN_IMM_9_6_OFF	6
#define RVC_ADDI4SPN_IMM_2_OFF		2
#define RVC_ADDI4SPN_IMM_3_OFF		3
#define RVC_ADDI4SPN_IMM_5_4_MASK	GENMASK(1, 0)
#define RVC_ADDI4SPN_IMM_9_6_MASK	GENMASK(3, 0)
#define RVC_ADDI4SPN_IMM_2_MASK		GENMASK(0, 0)
#define RVC_ADDI4SPN_IMM_3_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC FLD instruction */
#define RVC_FLD_IMM_5_3_OPOFF		0
#define RVC_FLD_IMM_7_6_OPOFF		0
#define RVC_FLD_IMM_5_3_OFF		3
#define RVC_FLD_IMM_7_6_OFF		6
#define RVC_FLD_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_FLD_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC LW instruction */
#define RVC_LW_IMM_5_3_OPOFF		0
#define RVC_LW_IMM_2_OPOFF		1
#define RVC_LW_IMM_6_OPOFF		0
#define RVC_LW_IMM_5_3_OFF		3
#define RVC_LW_IMM_2_OFF		2
#define RVC_LW_IMM_6_OFF		6
#define RVC_LW_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_LW_IMM_2_MASK		GENMASK(0, 0)
#define RVC_LW_IMM_6_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC FLW instruction */
#define RVC_FLW_IMM_5_3_OPOFF		0
#define RVC_FLW_IMM_2_OPOFF		1
#define RVC_FLW_IMM_6_OPOFF		0
#define RVC_FLW_IMM_5_3_OFF		3
#define RVC_FLW_IMM_2_OFF		2
#define RVC_FLW_IMM_6_OFF		6
#define RVC_FLW_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_FLW_IMM_2_MASK		GENMASK(0, 0)
#define RVC_FLW_IMM_6_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC LD instruction */
#define RVC_LD_IMM_5_3_OPOFF		0
#define RVC_LD_IMM_7_6_OPOFF		0
#define RVC_LD_IMM_5_3_OFF		3
#define RVC_LD_IMM_7_6_OFF		6
#define RVC_LD_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_LD_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC FSD instruction */
#define RVC_FSD_IMM_5_3_OPOFF		0
#define RVC_FSD_IMM_7_6_OPOFF		0
#define RVC_FSD_IMM_5_3_OFF		3
#define RVC_FSD_IMM_7_6_OFF		6
#define RVC_FSD_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_FSD_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC SW instruction */
#define RVC_SW_IMM_5_3_OPOFF		0
#define RVC_SW_IMM_2_OPOFF		1
#define RVC_SW_IMM_6_OPOFF		0
#define RVC_SW_IMM_5_3_OFF		3
#define RVC_SW_IMM_2_OFF		2
#define RVC_SW_IMM_6_OFF		6
#define RVC_SW_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_SW_IMM_2_MASK		GENMASK(0, 0)
#define RVC_SW_IMM_6_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC FSW instruction */
#define RVC_FSW_IMM_5_3_OPOFF		0
#define RVC_FSW_IMM_2_OPOFF		1
#define RVC_FSW_IMM_6_OPOFF		0
#define RVC_FSW_IMM_5_3_OFF		3
#define RVC_FSW_IMM_2_OFF		2
#define RVC_FSW_IMM_6_OFF		6
#define RVC_FSW_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_FSW_IMM_2_MASK		GENMASK(0, 0)
#define RVC_FSW_IMM_6_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC SD instruction */
#define RVC_SD_IMM_5_3_OPOFF		0
#define RVC_SD_IMM_7_6_OPOFF		0
#define RVC_SD_IMM_5_3_OFF		3
#define RVC_SD_IMM_7_6_OFF		6
#define RVC_SD_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_SD_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC ADDI instruction */
#define RVC_ADDI_IMM_5_OPOFF		0
#define RVC_ADDI_IMM_4_0_OPOFF		0
#define RVC_ADDI_IMM_5_OFF		5
#define RVC_ADDI_IMM_4_0_OFF		0
#define RVC_ADDI_IMM_5_MASK		GENMASK(0, 0)
#define RVC_ADDI_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC JAL instruction */
#define RVC_JAL_IMM_SIGN_OPOFF		12
#define RVC_JAL_IMM_4_OPOFF		11
#define RVC_JAL_IMM_9_8_OPOFF		9
#define RVC_JAL_IMM_10_OPOFF		8
#define RVC_JAL_IMM_6_OPOFF		7
#define RVC_JAL_IMM_7_OPOFF		6
#define RVC_JAL_IMM_3_1_OPOFF		3
#define RVC_JAL_IMM_5_OPOFF		2
#define RVC_JAL_IMM_SIGN_OFF		11
#define RVC_JAL_IMM_4_OFF		4
#define RVC_JAL_IMM_9_8_OFF		8
#define RVC_JAL_IMM_10_OFF		10
#define RVC_JAL_IMM_6_OFF		6
#define RVC_JAL_IMM_7_OFF		7
#define RVC_JAL_IMM_3_1_OFF		1
#define RVC_JAL_IMM_5_OFF		5
#define RVC_JAL_IMM_SIGN_MASK		GENMASK(0, 0)
#define RVC_JAL_IMM_4_MASK		GENMASK(0, 0)
#define RVC_JAL_IMM_9_8_MASK		GENMASK(1, 0)
#define RVC_JAL_IMM_10_MASK		GENMASK(0, 0)
#define RVC_JAL_IMM_6_MASK		GENMASK(0, 0)
#define RVC_JAL_IMM_7_MASK		GENMASK(0, 0)
#define RVC_JAL_IMM_3_1_MASK		GENMASK(2, 0)
#define RVC_JAL_IMM_5_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC ADDIW instruction */
#define RVC_ADDIW_IMM_5_OPOFF		0
#define RVC_ADDIW_IMM_4_0_OPOFF		0
#define RVC_ADDIW_IMM_5_OFF		5
#define RVC_ADDIW_IMM_4_0_OFF		0
#define RVC_ADDIW_IMM_5_MASK		GENMASK(0, 0)
#define RVC_ADDIW_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC LI instruction */
#define RVC_LI_IMM_5_OPOFF		0
#define RVC_LI_IMM_4_0_OPOFF		0
#define RVC_LI_IMM_5_OFF		5
#define RVC_LI_IMM_4_0_OFF		0
#define RVC_LI_IMM_5_MASK		GENMASK(0, 0)
#define RVC_LI_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC ADDI16SP instruction */
#define RVC_ADDI16SP_IMM_9_OPOFF	0
#define RVC_ADDI16SP_IMM_4_OPOFF	4
#define RVC_ADDI16SP_IMM_6_OPOFF	3
#define RVC_ADDI16SP_IMM_8_7_OPOFF	1
#define RVC_ADDI16SP_IMM_5_OPOFF	0
#define RVC_ADDI16SP_IMM_9_OFF		9
#define RVC_ADDI16SP_IMM_4_OFF		4
#define RVC_ADDI16SP_IMM_6_OFF		6
#define RVC_ADDI16SP_IMM_8_7_OFF	7
#define RVC_ADDI16SP_IMM_5_OFF		5
#define RVC_ADDI16SP_IMM_9_MASK		GENMASK(0, 0)
#define RVC_ADDI16SP_IMM_4_MASK		GENMASK(0, 0)
#define RVC_ADDI16SP_IMM_6_MASK		GENMASK(0, 0)
#define RVC_ADDI16SP_IMM_8_7_MASK	GENMASK(1, 0)
#define RVC_ADDI16SP_IMM_5_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC LUI instruction */
#define RVC_LUI_IMM_17_OPOFF		0
#define RVC_LUI_IMM_16_12_OPOFF		0
#define RVC_LUI_IMM_17_OFF		17
#define RVC_LUI_IMM_16_12_OFF		12
#define RVC_LUI_IMM_17_MASK		GENMASK(0, 0)
#define RVC_LUI_IMM_16_12_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC SRLI instruction */
#define RVC_SRLI_IMM_5_OPOFF		3
#define RVC_SRLI_IMM_FUNC2_OPOFF	0
#define RVC_SRLI_IMM_4_0_OPOFF		0
#define RVC_SRLI_IMM_5_OFF		5
#define RVC_SRLI_IMM_4_0_OFF		0
#define RVC_SRLI_IMM_5_MASK		GENMASK(0, 0)
#define RVC_SRLI_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC SRAI instruction */
#define RVC_SRAI_IMM_5_OPOFF		3
#define RVC_SRAI_IMM_FUNC2_OPOFF	0
#define RVC_SRAI_IMM_4_0_OPOFF		0
#define RVC_SRAI_IMM_5_OFF		5
#define RVC_SRAI_IMM_4_0_OFF		0
#define RVC_SRAI_IMM_5_MASK		GENMASK(0, 0)
#define RVC_SRAI_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC ANDI instruction */
#define RVC_ANDI_IMM_5_OPOFF		3
#define RVC_ANDI_IMM_FUNC2_OPOFF	0
#define RVC_ANDI_IMM_4_0_OPOFF		0
#define RVC_ANDI_IMM_5_OFF		5
#define RVC_ANDI_IMM_4_0_OFF		0
#define RVC_ANDI_IMM_5_MASK		GENMASK(0, 0)
#define RVC_ANDI_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC J instruction */
#define RVC_J_IMM_SIGN_OPOFF		12
#define RVC_J_IMM_4_OPOFF		11
#define RVC_J_IMM_9_8_OPOFF		9
#define RVC_J_IMM_10_OPOFF		8
#define RVC_J_IMM_6_OPOFF		7
#define RVC_J_IMM_7_OPOFF		6
#define RVC_J_IMM_3_1_OPOFF		3
#define RVC_J_IMM_5_OPOFF		2
#define RVC_J_IMM_SIGN_OFF		11
#define RVC_J_IMM_4_OFF			4
#define RVC_J_IMM_9_8_OFF		8
#define RVC_J_IMM_10_OFF		10
#define RVC_J_IMM_6_OFF			6
#define RVC_J_IMM_7_OFF			7
#define RVC_J_IMM_3_1_OFF		1
#define RVC_J_IMM_5_OFF			5
#define RVC_J_IMM_SIGN_MASK		GENMASK(0, 0)
#define RVC_J_IMM_4_MASK		GENMASK(0, 0)
#define RVC_J_IMM_9_8_MASK		GENMASK(1, 0)
#define RVC_J_IMM_10_MASK		GENMASK(0, 0)
#define RVC_J_IMM_6_MASK		GENMASK(0, 0)
#define RVC_J_IMM_7_MASK		GENMASK(0, 0)
#define RVC_J_IMM_3_1_MASK		GENMASK(2, 0)
#define RVC_J_IMM_5_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC BEQZ/BNEZ instruction */
#define RVC_BZ_IMM_SIGN_OPOFF		12
#define RVC_BZ_IMM_4_3_OPOFF		10
#define RVC_BZ_IMM_7_6_OPOFF		5
#define RVC_BZ_IMM_2_1_OPOFF		3
#define RVC_BZ_IMM_5_OPOFF		2
#define RVC_BZ_IMM_SIGN_OFF		8
#define RVC_BZ_IMM_4_3_OFF		3
#define RVC_BZ_IMM_7_6_OFF		6
#define RVC_BZ_IMM_2_1_OFF		1
#define RVC_BZ_IMM_5_OFF		5
#define RVC_BZ_IMM_SIGN_MASK		GENMASK(0, 0)
#define RVC_BZ_IMM_4_3_MASK		GENMASK(1, 0)
#define RVC_BZ_IMM_7_6_MASK		GENMASK(1, 0)
#define RVC_BZ_IMM_2_1_MASK		GENMASK(1, 0)
#define RVC_BZ_IMM_5_MASK		GENMASK(0, 0)

/* The bit field of immediate value in RVC SLLI instruction */
#define RVC_SLLI_IMM_5_OPOFF		0
#define RVC_SLLI_IMM_4_0_OPOFF		0
#define RVC_SLLI_IMM_5_OFF		5
#define RVC_SLLI_IMM_4_0_OFF		0
#define RVC_SLLI_IMM_5_MASK		GENMASK(0, 0)
#define RVC_SLLI_IMM_4_0_MASK		GENMASK(4, 0)

/* The bit field of immediate value in RVC FLDSP instruction */
#define RVC_FLDSP_IMM_5_OPOFF		0
#define RVC_FLDSP_IMM_4_3_OPOFF		3
#define RVC_FLDSP_IMM_8_6_OPOFF		0
#define RVC_FLDSP_IMM_5_OFF		5
#define RVC_FLDSP_IMM_4_3_OFF		3
#define RVC_FLDSP_IMM_8_6_OFF		6
#define RVC_FLDSP_IMM_5_MASK		GENMASK(0, 0)
#define RVC_FLDSP_IMM_4_3_MASK		GENMASK(1, 0)
#define RVC_FLDSP_IMM_8_6_MASK		GENMASK(2, 0)

/* The bit field of immediate value in RVC LWSP instruction */
#define RVC_LWSP_IMM_5_OPOFF		0
#define RVC_LWSP_IMM_4_2_OPOFF		2
#define RVC_LWSP_IMM_7_6_OPOFF		0
#define RVC_LWSP_IMM_5_OFF		5
#define RVC_LWSP_IMM_4_2_OFF		2
#define RVC_LWSP_IMM_7_6_OFF		6
#define RVC_LWSP_IMM_5_MASK		GENMASK(0, 0)
#define RVC_LWSP_IMM_4_2_MASK		GENMASK(2, 0)
#define RVC_LWSP_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC FLWSP instruction */
#define RVC_FLWSP_IMM_5_OPOFF		0
#define RVC_FLWSP_IMM_4_2_OPOFF		2
#define RVC_FLWSP_IMM_7_6_OPOFF		0
#define RVC_FLWSP_IMM_5_OFF		5
#define RVC_FLWSP_IMM_4_2_OFF		2
#define RVC_FLWSP_IMM_7_6_OFF		6
#define RVC_FLWSP_IMM_5_MASK		GENMASK(0, 0)
#define RVC_FLWSP_IMM_4_2_MASK		GENMASK(2, 0)
#define RVC_FLWSP_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC LDSP instruction */
#define RVC_LDSP_IMM_5_OPOFF		0
#define RVC_LDSP_IMM_4_3_OPOFF		3
#define RVC_LDSP_IMM_8_6_OPOFF		0
#define RVC_LDSP_IMM_5_OFF		5
#define RVC_LDSP_IMM_4_3_OFF		3
#define RVC_LDSP_IMM_8_6_OFF		6
#define RVC_LDSP_IMM_5_MASK		GENMASK(0, 0)
#define RVC_LDSP_IMM_4_3_MASK		GENMASK(1, 0)
#define RVC_LDSP_IMM_8_6_MASK		GENMASK(2, 0)

/* The bit field of immediate value in RVC FSDSP instruction */
#define RVC_FSDSP_IMM_5_3_OPOFF		3
#define RVC_FSDSP_IMM_8_6_OPOFF		0
#define RVC_FSDSP_IMM_5_3_OFF		3
#define RVC_FSDSP_IMM_8_6_OFF		6
#define RVC_FSDSP_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_FSDSP_IMM_8_6_MASK		GENMASK(2, 0)

/* The bit field of immediate value in RVC SWSP instruction */
#define RVC_SWSP_IMM_5_2_OPOFF		3
#define RVC_SWSP_IMM_7_6_OPOFF		0
#define RVC_SWSP_IMM_5_2_OFF		2
#define RVC_SWSP_IMM_7_6_OFF		6
#define RVC_SWSP_IMM_5_2_MASK		GENMASK(3, 0)
#define RVC_SWSP_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC FSWSP instruction */
#define RVC_FSWSP_IMM_5_2_OPOFF		3
#define RVC_FSWSP_IMM_7_6_OPOFF		0
#define RVC_FSWSP_IMM_5_2_OFF		2
#define RVC_FSWSP_IMM_7_6_OFF		6
#define RVC_FSWSP_IMM_5_2_MASK		GENMASK(3, 0)
#define RVC_FSWSP_IMM_7_6_MASK		GENMASK(1, 0)

/* The bit field of immediate value in RVC SDSP instruction */
#define RVC_SDSP_IMM_5_3_OPOFF		3
#define RVC_SDSP_IMM_8_6_OPOFF		0
#define RVC_SDSP_IMM_5_3_OFF		3
#define RVC_SDSP_IMM_8_6_OFF		6
#define RVC_SDSP_IMM_5_3_MASK		GENMASK(2, 0)
#define RVC_SDSP_IMM_8_6_MASK		GENMASK(2, 0)

/* Bit fields for RVC parts */
#define RVC_INSN_FUNCT6_MASK		GENMASK(5, 0)
#define RVC_INSN_FUNCT6_OPOFF		10
#define RVC_INSN_FUNCT4_MASK		GENMASK(3, 0)
#define RVC_INSN_FUNCT4_OPOFF		12
#define RVC_INSN_FUNCT3_MASK		GENMASK(2, 0)
#define RVC_INSN_FUNCT3_OPOFF		13
#define RVC_INSN_FUNCT2_MASK		GENMASK(1, 0)
#define RVC_INSN_FUNCT2_CB_OPOFF	10
#define RVC_INSN_FUNCT2_CA_OPOFF	5
#define RVC_INSN_OPCODE_MASK		GENMASK(1, 0)

/* Compositions of RVC Immediates */
#define RVC_ADDI4SPN_IMM(imm) \
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_ADDI4SPN_IMM_5_4_OFF, RVC_ADDI4SPN_IMM_5_4_MASK) \
		<< RVC_ADDI4SPN_IMM_5_4_OPOFF) | \
	(RV_X(_imm, RVC_ADDI4SPN_IMM_9_6_OFF, RVC_ADDI4SPN_IMM_9_6_MASK) \
		<< RVC_ADDI4SPN_IMM_9_6_OPOFF) | \
	(RV_X(_imm, RVC_ADDI4SPN_IMM_2_OFF, RVC_ADDI4SPN_IMM_2_MASK) \
		<< RVC_ADDI4SPN_IMM_2_OPOFF) | \
	(RV_X(_imm, RVC_ADDI4SPN_IMM_3_OFF, RVC_ADDI4SPN_IMM_3_MASK) \
		<< RVC_ADDI4SPN_IMM_3_OPOFF)); })

#define RVC_FLD_IMM_HI(imm)	\
	(RV_X(imm, RVC_FLD_IMM_5_3_OPOFF, RVC_FLD_IMM_5_3_OFF) \
		<< RVC_FLD_IMM_5_3_MASK)
#define RVC_FLD_IMM_LO(imm)	\
	(RV_X(imm, RVC_FLD_IMM_7_6_OPOFF, RVC_FLD_IMM_7_6_OFF) \
		<< RVC_FLD_IMM_7_6_MASK)

#define RVC_LW_IMM_HI(imm)	\
	((RV_X(imm, RVC_LW_IMM_5_3_OFF, RVC_LW_IMM_5_3_MASK) \
		<< RVC_LW_IMM_5_3_OPOFF))
#define RVC_LW_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_LW_IMM_2_OFF, RVC_LW_IMM_2_MASK) \
		<< RVC_LW_IMM_2_OPOFF) | \
	(RV_X(_imm, RVC_LW_IMM_6_OFF, RVC_LW_IMM_6_MASK) \
		<< RVC_LW_IMM_6_OPOFF)); })

#define RVC_FLW_IMM_HI(imm)	\
	((RV_X(imm, RVC_FLW_IMM_5_3_OFF, RVC_FLW_IMM_5_3_MASK) \
		<< RVC_FLW_IMM_5_3_OPOFF))
#define RVC_FLW_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_FLW_IMM_2_OFF, RVC_FLW_IMM_2_MASK) \
		<< RVC_FLW_IMM_2_OPOFF) |	\
	(RV_X(_imm, RVC_FLW_IMM_6_OFF, RVC_FLW_IMM_6_MASK) \
		<< RVC_FLW_IMM_6_OPOFF)); })

#define RVC_LD_IMM_HI(imm)	\
	(RV_X(imm, RVC_LD_IMM_5_3_OPOFF, RVC_LD_IMM_5_3_OFF) \
		<< RVC_LD_IMM_5_3_MASK)
#define RVC_LD_IMM_LO(imm)	\
	(RV_X(imm, RVC_LD_IMM_7_6_OPOFF, RVC_LD_IMM_7_6_OFF) \
		<< RVC_LD_IMM_7_6_MASK)

#define RVC_FSD_IMM_HI(imm)	\
	(RV_X(imm, RVC_FSD_IMM_5_3_OPOFF, RVC_FSD_IMM_5_3_OFF) \
		<< RVC_FSD_IMM_5_3_MASK)
#define RVC_FSD_IMM_LO(imm)	\
	(RV_X(imm, RVC_FSD_IMM_7_6_OPOFF, RVC_FSD_IMM_7_6_OFF) \
		<< RVC_FSD_IMM_7_6_MASK)

#define RVC_SW_IMM_HI(imm)	\
	(RV_X(imm, RVC_SW_IMM_5_3_OFF, RVC_SW_IMM_5_3_MASK) \
		<< RVC_SW_IMM_5_3_OPOFF)
#define RVC_SW_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_SW_IMM_2_OFF, RVC_SW_IMM_2_MASK) \
		<< RVC_SW_IMM_2_OPOFF) | \
	(RV_X(_imm, RVC_SW_IMM_6_OFF, RVC_SW_IMM_6_MASK) \
		<< RVC_SW_IMM_6_OPOFF)); })

#define RVC_FSW_IMM_HI(imm)	\
	(RV_X(imm, RVC_FSW_IMM_5_3_OFF, RVC_FSW_IMM_5_3_MASK) \
		<< RVC_FSW_IMM_5_3_OPOFF)
#define RVC_FSW_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_FSW_IMM_2_OFF, RVC_FSW_IMM_2_MASK) \
		<< RVC_FSW_IMM_2_OPOFF) |	\
	(RV_X(_imm, RVC_FSW_IMM_6_OFF, RVC_FSW_IMM_6_MASK) \
		<< RVC_FSW_IMM_6_OPOFF)); })

#define RVC_SD_IMM_HI(imm)	\
	(RV_X(imm, RVC_SD_IMM_5_3_OPOFF, RVC_SD_IMM_5_3_OFF) \
		<< RVC_SD_IMM_5_3_MASK)
#define RVC_SD_IMM_LO(imm)	\
	(RV_X(imm, RVC_SD_IMM_7_6_OPOFF, RVC_SD_IMM_7_6_OFF) \
		<< RVC_SD_IMM_7_6_MASK)

#define RVC_ADDI_IMM_HI(imm)		\
	(RV_X(imm, RVC_ADDI_IMM_5_OPOFF, RVC_ADDI_IMM_5_OFF) \
		<< RVC_ADDI_IMM_5_MASK)
#define RVC_ADDI_IMM_LO(imm)		\
	(RV_X(imm, RVC_ADDI_IMM_4_0_OPOFF, RVC_ADDI_IMM_4_0_OFF) \
		<< RVC_ADDI_IMM_4_0_MASK)

#define RVC_JAL_IMM(imm)		\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_JAL_IMM_SIGN_OPOFF, RVC_JAL_IMM_SIGN_OFF) \
		<< RVC_JAL_IMM_SIGN_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_4_OPOFF, RVC_JAL_IMM_4_OFF) \
		<< RVC_JAL_IMM_4_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_9_8_OPOFF, RVC_JAL_IMM_9_8_OFF) \
		<< RVC_JAL_IMM_9_8_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_10_OPOFF, RVC_JAL_IMM_10_OFF) \
		<< RVC_JAL_IMM_10_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_6_OPOFF, RVC_JAL_IMM_6_OFF) \
		<< RVC_JAL_IMM_6_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_7_OPOFF, RVC_JAL_IMM_7_OFF) \
		<< RVC_JAL_IMM_7_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_3_1_OPOFF, RVC_JAL_IMM_3_1_OFF) \
		<< RVC_JAL_IMM_3_1_MASK) |	\
	(RV_X(_imm, RVC_JAL_IMM_5_OPOFF, RVC_JAL_IMM_5_OFF) \
		<< RVC_JAL_IMM_5_MASK)); })

#define RVC_ADDIW_IMM_HI(imm)		\
	(RV_X(imm, RVC_ADDIW_IMM_5_OPOFF, RVC_ADDIW_IMM_5_OFF) \
		<< RVC_ADDIW_IMM_5_MASK)
#define RVC_ADDIW_IMM_LO(imm)		\
	(RV_X(imm, RVC_ADDIW_IMM_4_0_OPOFF, RVC_ADDIW_IMM_4_0_OFF) \
		<< RVC_ADDIW_IMM_4_0_MASK)

#define RVC_LI_IMM_HI(imm)		\
	(RV_X(imm, RVC_LI_IMM_5_OPOFF, RVC_LI_IMM_5_OFF) \
		<< RVC_LI_IMM_5_MASK)
#define RVC_LI_IMM_LO(imm)		\
	(RV_X(imm, RVC_LI_IMM_4_0_OPOFF, RVC_LI_IMM_4_0_OFF) \
		<< RVC_LI_IMM_4_0_MASK)

#define RVC_ADDI16SP_IMM_HI(imm)	\
	(RV_X(imm, RVC_ADDI16SP_IMM_9_OFF, RVC_ADDI16SP_IMM_9_MASK) \
		<< RVC_ADDI16SP_IMM_9_OPOFF)
#define RVC_ADDI16SP_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_ADDI16SP_IMM_4_OFF, RVC_ADDI16SP_IMM_4_MASK) \
		<< RVC_ADDI16SP_IMM_4_OPOFF) |	\
	(RV_X(_imm, RVC_ADDI16SP_IMM_6_OFF, RVC_ADDI16SP_IMM_6_MASK) \
		<< RVC_ADDI16SP_IMM_4_OPOFF) |	\
	(RV_X(_imm, RVC_ADDI16SP_IMM_5_OFF, RVC_ADDI16SP_IMM_5_MASK) \
		<< RVC_ADDI16SP_IMM_4_OPOFF) |	\
	(RV_X(_imm, RVC_ADDI16SP_IMM_8_7_OFF, RVC_ADDI16SP_IMM_8_7_MASK) \
		<< RVC_ADDI16SP_IMM_4_OPOFF)); })

#define RVC_LUI_IMM_HI(imm)		\
	(RV_X(imm, RVC_LUI_IMM_17_OPOFF, RVC_LUI_IMM_17_OFF) \
		<< RVC_LUI_IMM_17_MASK)
#define RVC_LUI_IMM_LO(imm)		\
	(RV_X(imm, RVC_LUI_IMM_16_12_OPOFF, RVC_LUI_IMM_16_12_OFF) \
		<< RVC_LUI_IMM_16_12_MASK)

#define RVC_SRLI_IMM_HI(imm)		\
	(RV_X(imm, RVC_SRLI_IMM_5_OPOFF, RVC_SRLI_IMM_5_OFF) \
		<< RVC_SRLI_IMM_5_MASK)
#define RVC_SRLI_IMM_LO(imm)		\
	(RV_X(imm, RVC_SRLI_IMM_4_0_OPOFF, RVC_SRLI_IMM_4_0_OFF) \
		<< RVC_SRLI_IMM_4_0_MASK)

#define RVC_SRAI_IMM_HI(imm)		\
	(RV_X(imm, RVC_SRAI_IMM_5_OPOFF, RVC_SRAI_IMM_5_OFF) \
		<< RVC_SRAI_IMM_5_MASK)
#define RVC_SRAI_IMM_LO(imm)		\
	(RV_X(imm, RVC_SRAI_IMM_4_0_OPOFF, RVC_SRAI_IMM_4_0_OFF) \
		<< RVC_SRAI_IMM_4_0_MASK)

#define RVC_ANDI_IMM_HI(imm)		\
	(RV_X(imm, RVC_ANDI_IMM_5_OPOFF, RVC_ANDI_IMM_5_OFF) \
		<< RVC_ANDI_IMM_5_MASK)
#define RVC_ANDI_IMM_LO(imm)		\
	(RV_X(imm, RVC_ANDI_IMM_4_0_OPOFF, RVC_ANDI_IMM_4_0_OFF) \
		<< RVC_ANDI_IMM_4_0_MASK)

#define RVC_J_IMM(imm)		\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_J_IMM_SIGN_OPOFF, RVC_J_IMM_SIGN_OFF) \
		<< RVC_J_IMM_SIGN_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_4_OPOFF, RVC_J_IMM_4_OFF) \
		<< RVC_J_IMM_4_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_9_8_OPOFF, RVC_J_IMM_9_8_OFF) \
		<< RVC_J_IMM_9_8_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_10_OPOFF, RVC_J_IMM_10_OFF) \
		<< RVC_J_IMM_10_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_6_OPOFF, RVC_J_IMM_6_OFF) \
		<< RVC_J_IMM_6_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_7_OPOFF, RVC_J_IMM_7_OFF) \
		<< RVC_J_IMM_7_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_3_1_OPOFF, RVC_J_IMM_3_1_OFF) \
		<< RVC_J_IMM_3_1_MASK) |	\
	(RV_X(_imm, RVC_J_IMM_5_OPOFF, RVC_J_IMM_5_OFF) \
		<< RVC_J_IMM_5_MASK)); })

#define RVC_BEQZ_IMM_HI(imm)		\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_BZ_IMM_SIGN_OPOFF, RVC_BZ_IMM_SIGN_OFF) \
		<< RVC_BZ_IMM_SIGN_MASK) |	\
	(RV_X(_imm, RVC_BZ_IMM_4_3_OPOFF, RVC_BZ_IMM_4_3_OFF) \
		<< RVC_BZ_IMM_4_3_MASK)); })
#define RVC_BEQZ_IMM_LO(imm)		\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_BZ_IMM_7_6_OPOFF, RVC_BZ_IMM_7_6_OFF) \
		<< RVC_BZ_IMM_7_6_MASK) |	\
	(RV_X(_imm, RVC_BZ_IMM_2_1_OPOFF, RVC_BZ_IMM_2_1_OFF) \
		<< RVC_BZ_IMM_2_1_MASK) |	\
	(RV_X(_imm, RVC_BZ_IMM_5_OPOFF, RVC_BZ_IMM_5_OFF) \
		<< RVC_BZ_IMM_5_MASK)); })

#define RVC_BNEZ_IMM_HI(imm)		\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_BZ_IMM_SIGN_OPOFF, RVC_BZ_IMM_SIGN_OFF) \
		<< RVC_BZ_IMM_SIGN_MASK) |	\
	(RV_X(_imm, RVC_BZ_IMM_4_3_OPOFF, RVC_BZ_IMM_4_3_OFF) \
		<< RVC_BZ_IMM_4_3_MASK)); })
#define RVC_BNEZ_IMM_LO(imm)		\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_BZ_IMM_7_6_OPOFF, RVC_BZ_IMM_7_6_OFF) \
		<< RVC_BZ_IMM_7_6_MASK) |	\
	(RV_X(_imm, RVC_BZ_IMM_2_1_OPOFF, RVC_BZ_IMM_2_1_OFF) \
		<< RVC_BZ_IMM_2_1_MASK) |	\
	(RV_X(_imm, RVC_BZ_IMM_5_OPOFF, RVC_BZ_IMM_5_OFF) \
		<< RVC_BZ_IMM_5_MASK)); })

#define RVC_SLLI_IMM_HI(imm)	\
	(RV_X(imm, RVC_SLLI_IMM_5_OFF, RVC_SLLI_IMM_5_MASK) \
		<< RVC_SLLI_IMM_5_OPOFF)
#define RVC_SLLI_IMM_LO(imm)	\
	(RV_X(imm, RVC_SLLI_IMM_4_0_OFF, RVC_SLLI_IMM_4_0_MASK) \
		<< RVC_SLLI_IMM_4_0_OPOFF)

#define RVC_FLDSP_IMM_HI(imm)	\
	(RV_X(imm, RVC_FLDSP_IMM_5_OFF, RVC_FLDSP_IMM_5_MASK) \
		<< RVC_FLDSP_IMM_5_OPOFF)
#define RVC_FLDSP_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_FLDSP_IMM_4_3_OFF, RVC_FLDSP_IMM_4_3_MASK) \
		<< RVC_FLDSP_IMM_4_3_OPOFF) |	\
	(RV_X(_imm, RVC_FLDSP_IMM_8_6_OFF, RVC_FLDSP_IMM_8_6_MASK) \
		<< RVC_FLDSP_IMM_8_6_OPOFF)); })

#define RVC_LWSP_IMM_HI(imm)	\
	(RV_X(imm, RVC_LWSP_IMM_5_OFF, RVC_LWSP_IMM_5_MASK) \
		<< RVC_LWSP_IMM_5_OPOFF)
#define RVC_LWSP_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_LWSP_IMM_4_2_OFF, RVC_LWSP_IMM_4_2_MASK) \
		<< RVC_LWSP_IMM_4_2_OPOFF) |	\
	(RV_X(_imm, RVC_LWSP_IMM_7_6_OFF, RVC_LWSP_IMM_7_6_MASK) \
		<< RVC_LWSP_IMM_7_6_OPOFF)); })

#define RVC_FLWSP_IMM_HI(imm)	\
	(RV_X(imm, RVC_FLWSP_IMM_5_OFF, RVC_FLWSP_IMM_5_MASK) \
		<< RVC_FLWSP_IMM_5_OPOFF)
#define RVC_FLWSP_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_FLWSP_IMM_4_2_OFF, RVC_FLWSP_IMM_4_2_MASK) \
		<< RVC_FLWSP_IMM_4_2_OPOFF) |	\
	(RV_X(_imm, RVC_FLWSP_IMM_7_6_OFF, RVC_FLWSP_IMM_7_6_MASK) \
		<< RVC_FLWSP_IMM_7_6_OPOFF)); })

#define RVC_LDSP_IMM_HI(imm)	\
	(RV_X(imm, RVC_LDSP_IMM_5_OPOFF, RVC_LDSP_IMM_5_OFF) \
		<< RVC_LDSP_IMM_5_MASK)
#define RVC_LDSP_IMM_LO(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_LDSP_IMM_4_3_OPOFF, RVC_LDSP_IMM_4_3_OFF) \
		<< RVC_LDSP_IMM_4_3_MASK) |	\
	(RV_X(_imm, RVC_LDSP_IMM_8_6_OPOFF, RVC_LDSP_IMM_8_6_OFF) \
		<< RVC_LDSP_IMM_8_6_MASK)); })

#define RVC_FSDSP_IMM(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_FSDSP_IMM_5_3_OPOFF, RVC_FSDSP_IMM_5_3_OFF) \
		<< RVC_FSDSP_IMM_5_3_MASK) |	\
	(RV_X(_imm, RVC_FSDSP_IMM_8_6_OPOFF, RVC_FSDSP_IMM_8_6_OFF) \
		<< RVC_FSDSP_IMM_8_6_MASK)); })

#define RVC_SWSP_IMM(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_SWSP_IMM_5_2_OPOFF, RVC_SWSP_IMM_5_2_MASK) \
		<< RVC_SWSP_IMM_5_2_OPOFF) |	\
	(RV_X(_imm, RVC_SWSP_IMM_7_6_OPOFF, RVC_SWSP_IMM_7_6_MASK) \
		<< RVC_SWSP_IMM_7_6_OPOFF)); })

#define RVC_FSWSP_IMM(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_FSWSP_IMM_5_2_OPOFF, RVC_FSWSP_IMM_5_2_MASK) \
		<< RVC_FSWSP_IMM_5_2_OPOFF) |	\
	(RV_X(_imm, RVC_FSWSP_IMM_7_6_OPOFF, RVC_FSWSP_IMM_7_6_MASK) \
		<< RVC_FSWSP_IMM_7_6_OPOFF)); })

#define RVC_SDSP_IMM(imm)	\
	({ typeof(imm) _imm = imm; \
	((RV_X(_imm, RVC_SDSP_IMM_5_3_OPOFF, RVC_SDSP_IMM_5_3_OFF) \
		<< RVC_SDSP_IMM_5_3_MASK) |	\
	(RV_X(_imm, RVC_SDSP_IMM_8_6_OPOFF, RVC_SDSP_IMM_8_6_OFF) \
		<< RVC_SDSP_IMM_8_6_MASK)); })

/* The register offset in RVC op=C0 instruction */
#define RVC_C0_RS1_OPOFF	7
#define RVC_C0_RS2_OPOFF	2
#define RVC_C0_RD_OPOFF		2

/* The register offset in RVC op=C1 instruction */
#define RVC_C1_RS1_OPOFF	7
#define RVC_C1_RS2_OPOFF	2
#define RVC_C1_RD_OPOFF		7

/* The register offset in RVC op=C2 instruction */
#define RVC_C2_RS1_OPOFF	7
#define RVC_C2_RS2_OPOFF	2
#define RVC_C2_RD_OPOFF		7

/* RVC RD definitions */
#define RVC_RD_CR(insn)	(((insn) >> RVC_C2_RD_OPOFF) & RV_STANDARD_REG_MASK)
#define RVC_RD_CI(insn)	(((insn) >> RVC_C2_RD_OPOFF) & RV_STANDARD_REG_MASK)
#define RVC_RD_CIW(insn)(((insn) >> RVC_C0_RD_OPOFF) & RV_COMPRESSED_REG_MASK)
#define RVC_RD_CL(insn)	(((insn) >> RVC_C0_RD_OPOFF) & RV_COMPRESSED_REG_MASK)
#define RVC_RD_CA(insn)	(((insn) >> RVC_C2_RD_OPOFF) & RV_COMPRESSED_REG_MASK)
#define RVC_RD_CB(insn)	(((insn) >> RVC_C2_RD_OPOFF) & RV_COMPRESSED_REG_MASK)

/* Special opcodes */
#define RVG_OPCODE_SYSTEM	0b1110011
#define RVG_OPCODE_NOP		0b0010011
#define RVG_OPCODE_BRANCH	0b1100011
/* RVG opcodes */
#define RVG_OPCODE_LUI		0b0110111
#define RVG_OPCODE_AUIPC	0b0010111
#define RVG_OPCODE_JAL		0b1101111
#define RVG_OPCODE_JALR		0b1100111
#define RVG_OPCODE_BEQ		0b1100011
#define RVG_OPCODE_BNE		0b1100011
#define RVG_OPCODE_BLT		0b1100011
#define RVG_OPCODE_BGE		0b1100011
#define RVG_OPCODE_BLTU		0b1100011
#define RVG_OPCODE_BGEU		0b1100011
#define RVG_OPCODE_LB		0b0000011
#define RVG_OPCODE_LH		0b0000011
#define RVG_OPCODE_LW		0b0000011
#define RVG_OPCODE_LBU		0b0000011
#define RVG_OPCODE_LHU		0b0000011
#define RVG_OPCODE_SB		0b0100011
#define RVG_OPCODE_SH		0b0100011
#define RVG_OPCODE_SW		0b0100011
#define RVG_OPCODE_ADDI		0b0010011
#define RVG_OPCODE_SLTI		0b0010011
#define RVG_OPCODE_SLTIU	0b0010011
#define RVG_OPCODE_XORI		0b0010011
#define RVG_OPCODE_ORI		0b0010011
#define RVG_OPCODE_ANDI		0b0010011
#define RVG_OPCODE_SLLI		0b0010011
#define RVG_OPCODE_SRLI		0b0010011
#define RVG_OPCODE_SRAI		0b0010011
#define RVG_OPCODE_ADD		0b0110011
#define RVG_OPCODE_SUB		0b0110011
#define RVG_OPCODE_SLL		0b0110011
#define RVG_OPCODE_SLT		0b0110011
#define RVG_OPCODE_SLTU		0b0110011
#define RVG_OPCODE_XOR		0b0110011
#define RVG_OPCODE_SRL		0b0110011
#define RVG_OPCODE_SRA		0b0110011
#define RVG_OPCODE_OR		0b0110011
#define RVG_OPCODE_AND		0b0110011
#define RVG_OPCODE_FENCE	0b0001111
#define RVG_OPCODE_FENCETSO	0b0001111
#define RVG_OPCODE_PAUSE	0b0001111
#define RVG_OPCODE_ECALL	0b1110011
#define RVG_OPCODE_EBREAK	0b1110011
/* F Standard Extension */
#define RVG_OPCODE_FLW		0b0000111
#define RVG_OPCODE_FSW		0b0100111
/* D Standard Extension */
#define RVG_OPCODE_FLD		0b0000111
#define RVG_OPCODE_FSD		0b0100111
/* Q Standard Extension */
#define RVG_OPCODE_FLQ		0b0000111
#define RVG_OPCODE_FSQ		0b0100111
/* Zicsr Standard Extension */
#define RVG_OPCODE_CSRRW	0b1110011
#define RVG_OPCODE_CSRRS	0b1110011
#define RVG_OPCODE_CSRRC	0b1110011
#define RVG_OPCODE_CSRRWI	0b1110011
#define RVG_OPCODE_CSRRSI	0b1110011
#define RVG_OPCODE_CSRRCI	0b1110011
/* M Standard Extension */
#define RVG_OPCODE_MUL		0b0110011
#define RVG_OPCODE_MULH		0b0110011
#define RVG_OPCODE_MULHSU	0b0110011
#define RVG_OPCODE_MULHU	0b0110011
#define RVG_OPCODE_DIV		0b0110011
#define RVG_OPCODE_DIVU		0b0110011
#define RVG_OPCODE_REM		0b0110011
#define RVG_OPCODE_REMU		0b0110011
/* A Standard Extension */
#define RVG_OPCODE_LR_W		0b0101111
#define RVG_OPCODE_SC_W		0b0101111
#define RVG_OPCODE_AMOSWAP_W	0b0101111
#define RVG_OPCODE_AMOADD_W	0b0101111
#define RVG_OPCODE_AMOXOR_W	0b0101111
#define RVG_OPCODE_AMOAND_W	0b0101111
#define RVG_OPCODE_AMOOR_W	0b0101111
#define RVG_OPCODE_AMOMIN_W	0b0101111
#define RVG_OPCODE_AMOMAX_W	0b0101111
#define RVG_OPCODE_AMOMINU_W	0b0101111
#define RVG_OPCODE_AMOMAXU_W	0b0101111
/* Vector Extension */
#define RVV_OPCODE_VECTOR	0b1010111
#define RVV_OPCODE_VL		RVG_OPCODE_FLW
#define RVV_OPCODE_VS		RVG_OPCODE_FSW

/* RVG 64-bit only opcodes */
#define RVG_OPCODE_LWU		0b0000011
#define RVG_OPCODE_LD		0b0000011
#define RVG_OPCODE_SD		0b0100011
#define RVG_OPCODE_ADDIW	0b0011011
#define RVG_OPCODE_SLLIW	0b0011011
#define RVG_OPCODE_SRLIW	0b0011011
#define RVG_OPCODE_SRAIW	0b0011011
#define RVG_OPCODE_ADDW		0b0111011
#define RVG_OPCODE_SUBW		0b0111011
#define RVG_OPCODE_SLLW		0b0111011
#define RVG_OPCODE_SRLW		0b0111011
#define RVG_OPCODE_SRAW		0b0111011
/* M Standard Extension */
#define RVG_OPCODE_MULW		0b0111011
#define RVG_OPCODE_DIVW		0b0111011
#define RVG_OPCODE_DIVUW	0b0111011
#define RVG_OPCODE_REMW		0b0111011
#define RVG_OPCODE_REMUW	0b0111011
/* A Standard Extension */
#define RVG_OPCODE_LR_D		0b0101111
#define RVG_OPCODE_SC_D		0b0101111
#define RVG_OPCODE_AMOSWAP_D	0b0101111
#define RVG_OPCODE_AMOADD_D	0b0101111
#define RVG_OPCODE_AMOXOR_D	0b0101111
#define RVG_OPCODE_AMOAND_D	0b0101111
#define RVG_OPCODE_AMOOR_D	0b0101111
#define RVG_OPCODE_AMOMIN_D	0b0101111
#define RVG_OPCODE_AMOMAX_D	0b0101111
#define RVG_OPCODE_AMOMINU_D	0b0101111
#define RVG_OPCODE_AMOMAXU_D	0b0101111

/* RVG func3 codes */
#define RVG_FUNCT3_JALR		0b000
#define RVG_FUNCT3_BEQ		0b000
#define RVG_FUNCT3_BNE		0b001
#define RVG_FUNCT3_BLT		0b100
#define RVG_FUNCT3_BGE		0b101
#define RVG_FUNCT3_BLTU		0b110
#define RVG_FUNCT3_BGEU		0b111
#define RVG_FUNCT3_LB		0b000
#define RVG_FUNCT3_LH		0b001
#define RVG_FUNCT3_LW		0b010
#define RVG_FUNCT3_LBU		0b100
#define RVG_FUNCT3_LHU		0b101
#define RVG_FUNCT3_SB		0b000
#define RVG_FUNCT3_SH		0b001
#define RVG_FUNCT3_SW		0b010
#define RVG_FUNCT3_ADDI		0b000
#define RVG_FUNCT3_SLTI		0b010
#define RVG_FUNCT3_SLTIU	0b011
#define RVG_FUNCT3_XORI		0b100
#define RVG_FUNCT3_ORI		0b110
#define RVG_FUNCT3_ANDI		0b111
#define RVG_FUNCT3_SLLI		0b001
#define RVG_FUNCT3_SRLI		0b101
#define RVG_FUNCT3_SRAI		0b101
#define RVG_FUNCT3_ADD		0b000
#define RVG_FUNCT3_SUB		0b000
#define RVG_FUNCT3_SLL		0b001
#define RVG_FUNCT3_SLT		0b010
#define RVG_FUNCT3_SLTU		0b011
#define RVG_FUNCT3_XOR		0b100
#define RVG_FUNCT3_SRL		0b101
#define RVG_FUNCT3_SRA		0b101
#define RVG_FUNCT3_OR		0b110
#define RVG_FUNCT3_AND		0b111
#define RVG_FUNCT3_NOP		RVG_FUNCT3_ADDI
#define RVG_FUNCT3_FENCE	0b000
#define RVG_FUNCT3_FENCETSO	0b000
#define RVG_FUNCT3_PAUSE	0b000
#define RVG_FUNCT3_ECALL	0b000
#define RVG_FUNCT3_EBREAK	0b000
/* F Standard Extension */
#define RVG_FUNCT3_FLW		0b010
#define RVG_FUNCT3_FSW		0b010
/* D Standard Extension */
#define RVG_FUNCT3_FLD		0b011
#define RVG_FUNCT3_FSD		0b011
/* Q Standard Extension */
#define RVG_FUNCT3_FLQ		0b100
#define RVG_FUNCT3_FSQ		0b100
/* Zicsr Standard Extension */
#define RVG_FUNCT3_CSRRW	0b001
#define RVG_FUNCT3_CSRRS	0b010
#define RVG_FUNCT3_CSRRC	0b011
#define RVG_FUNCT3_CSRRWI	0b101
#define RVG_FUNCT3_CSRRSI	0b110
#define RVG_FUNCT3_CSRRCI	0b111
/* M Standard Extension */
#define RVG_FUNCT3_MUL		0b000
#define RVG_FUNCT3_MULH		0b001
#define RVG_FUNCT3_MULHSU	0b010
#define RVG_FUNCT3_MULHU	0b011
#define RVG_FUNCT3_DIV		0b100
#define RVG_FUNCT3_DIVU		0b101
#define RVG_FUNCT3_REM		0b110
#define RVG_FUNCT3_REMU		0b111
/* A Standard Extension */
#define RVG_FUNCT3_LR_W		0b010
#define RVG_FUNCT3_SC_W		0b010
#define RVG_FUNCT3_AMOSWAP_W	0b010
#define RVG_FUNCT3_AMOADD_W	0b010
#define RVG_FUNCT3_AMOXOR_W	0b010
#define RVG_FUNCT3_AMOAND_W	0b010
#define RVG_FUNCT3_AMOOR_W	0b010
#define RVG_FUNCT3_AMOMIN_W	0b010
#define RVG_FUNCT3_AMOMAX_W	0b010
#define RVG_FUNCT3_AMOMINU_W	0b010
#define RVG_FUNCT3_AMOMAXU_W	0b010

/* RVG 64-bit only func3 codes */
#define RVG_FUNCT3_LWU		0b110
#define RVG_FUNCT3_LD		0b011
#define RVG_FUNCT3_SD		0b011
#define RVG_FUNCT3_ADDIW	0b000
#define RVG_FUNCT3_SLLIW	0b001
#define RVG_FUNCT3_SRLIW	0b101
#define RVG_FUNCT3_SRAIW	0b101
#define RVG_FUNCT3_ADDW		0b000
#define RVG_FUNCT3_SUBW		0b000
#define RVG_FUNCT3_SLLW		0b001
#define RVG_FUNCT3_SRLW		0b101
#define RVG_FUNCT3_SRAW		0b101
/* M Standard Extension */
#define RVG_FUNCT3_MULW		0b000
#define RVG_FUNCT3_DIVW		0b100
#define RVG_FUNCT3_DIVUW	0b101
#define RVG_FUNCT3_REMW		0b110
#define RVG_FUNCT3_REMUW	0b111
/* A Standard Extension */
#define RVG_FUNCT3_LR_D		0b011
#define RVG_FUNCT3_SC_D		0b011
#define RVG_FUNCT3_AMOSWAP_D	0b011
#define RVG_FUNCT3_AMOADD_D	0b011
#define RVG_FUNCT3_AMOXOR_D	0b011
#define RVG_FUNCT3_AMOAND_D	0b011
#define RVG_FUNCT3_AMOOR_D	0b011
#define RVG_FUNCT3_AMOMIN_D	0b011
#define RVG_FUNCT3_AMOMAX_D	0b011
#define RVG_FUNCT3_AMOMINU_D	0b011
#define RVG_FUNCT3_AMOMAXU_D	0b011

#if __riscv_xlen == 32
/* RV-32 Shift Instruction Upper Bits */
#define RVG_SLLI_UPPER		0b0000000
#define RVG_SRLI_UPPER		0b0000000
#define RVG_SRAI_UPPER		0b0100000
#elif __riscv_xlen == 64
/* RV-64 Shift Instruction Upper Bits */
#define RVG_SLLI_UPPER		0b000000
#define RVG_SRLI_UPPER		0b000000
#define RVG_SRAI_UPPER		0b010000
#endif /* __riscv_xlen */

/* RVG funct5 codes */
/* A Standard Extension */
#define RVG_FUNCT5_LR_W		0b00010
#define RVG_FUNCT5_SC_W		0b00011
#define RVG_FUNCT5_AMOSWAP_W	0b00001
#define RVG_FUNCT5_AMOADD_W	0b00000
#define RVG_FUNCT5_AMOXOR_W	0b00100
#define RVG_FUNCT5_AMOAND_W	0b01100
#define RVG_FUNCT5_AMOOR_W	0b01000
#define RVG_FUNCT5_AMOMIN_W	0b10000
#define RVG_FUNCT5_AMOMAX_W	0b10100
#define RVG_FUNCT5_AMOMINU_W	0b11000
#define RVG_FUNCT5_AMOMAXU_W	0b11100

/* RVG 64-bit only funct5 codes */
/* A Standard Extension */
#define RVG_FUNCT5_LR_D		0b00010
#define RVG_FUNCT5_SC_D		0b00011
#define RVG_FUNCT5_AMOSWAP_D	0b00001
#define RVG_FUNCT5_AMOADD_D	0b00000
#define RVG_FUNCT5_AMOXOR_D	0b00100
#define RVG_FUNCT5_AMOAND_D	0b01100
#define RVG_FUNCT5_AMOOR_D	0b01000
#define RVG_FUNCT5_AMOMIN_D	0b10000
#define RVG_FUNCT5_AMOMAX_D	0b10100
#define RVG_FUNCT5_AMOMINU_D	0b11000
#define RVG_FUNCT5_AMOMAXU_D	0b11100

/* RVG funct7 codes */
#define RVG_FUNCT7_SLLI		0b0000000
#define RVG_FUNCT7_SRLI		0b0000000
#define RVG_FUNCT7_SRAI		0b0100000
#define RVG_FUNCT7_ADD		0b0000000
#define RVG_FUNCT7_SUB		0b0100000
#define RVG_FUNCT7_SLL		0b0000000
#define RVG_FUNCT7_SLT		0b0000000
#define RVG_FUNCT7_SLTU		0b0000000
#define RVG_FUNCT7_XOR		0b0000000
#define RVG_FUNCT7_SRL		0b0000000
#define RVG_FUNCT7_SRA		0b0100000
#define RVG_FUNCT7_OR		0b0000000
#define RVG_FUNCT7_AND		0b0000000
/* M Standard Extension */
#define RVG_FUNCT7_MUL		0b0000001
#define RVG_FUNCT7_MULH		0b0000001
#define RVG_FUNCT7_MULHSU	0b0000001
#define RVG_FUNCT7_MULHU	0b0000001
#define RVG_FUNCT7_DIV		0b0000001
#define RVG_FUNCT7_DIVU		0b0000001
#define RVG_FUNCT7_REM		0b0000001
#define RVG_FUNCT7_REMU		0b0000001

/* RVG 64-bit only funct7 codes */
#define RVG_FUNCT7_SLLIW	0b0000000
#define RVG_FUNCT7_SRLIW	0b0000000
#define RVG_FUNCT7_SRAIW	0b0100000
#define RVG_FUNCT7_ADDW		0b0000000
#define RVG_FUNCT7_SUBW		0b0100000
#define RVG_FUNCT7_SLLW		0b0000000
#define RVG_FUNCT7_SRLW		0b0000000
#define RVG_FUNCT7_SRAW		0b0100000
/* M Standard Extension */
#define RVG_FUNCT7_MULW		0b0000001
#define RVG_FUNCT7_DIVW		0b0000001
#define RVG_FUNCT7_DIVUW	0b0000001
#define RVG_FUNCT7_REMW		0b0000001
#define RVG_FUNCT7_REMUW	0b0000001

/* RVG funct12 codes */
#define RVG_FUNCT12_ECALL	0b000000000000
#define RVG_FUNCT12_EBREAK	0b000000000001

/* RVG instruction match types */
#define RVG_MATCH_R(f_) \
	(RVG_FUNCT7_##f_ << RV_INSN_FUNCT7_OPOFF | \
	 RVG_FUNCT3_##f_ << RV_INSN_FUNCT3_OPOFF | RVG_OPCODE_##f_)
#define RVG_MATCH_I(f_) \
	(RVG_FUNCT3_##f_ << RV_INSN_FUNCT3_OPOFF | RVG_OPCODE_##f_)
#define RVG_MATCH_S(f_) \
	(RVG_FUNCT3_##f_ << RV_INSN_FUNCT3_OPOFF | RVG_OPCODE_##f_)
#define RVG_MATCH_B(f_) \
	(RVG_FUNCT3_##f_ << RV_INSN_FUNCT3_OPOFF | RVG_OPCODE_##f_)
#define RVG_MATCH_U(f_) (RVG_OPCODE_##f_)
#define RVG_MATCH_J(f_) (RVG_OPCODE_##f_)
#define RVG_MATCH_AMO(f_) \
	(RVG_FUNCT5_##f_ << RV_INSN_FUNCT7_OPOFF | \
	 RVG_FUNCT3_##f_ << RV_INSN_FUNCT3_OPOFF | RVG_OPCODE_##f_)

/* RVG instruction matches */
#define RVG_MATCH_LUI		(RVG_MATCH_U(LUI))
#define RVG_MATCH_AUIPC		(RVG_MATCH_U(AUIPC))
#define RVG_MATCH_JAL		(RVG_MATCH_J(JAL))
#define RVG_MATCH_JALR		(RVG_MATCH_I(JALR))
#define RVG_MATCH_BEQ		(RVG_MATCH_B(BEQ))
#define RVG_MATCH_BNE		(RVG_MATCH_B(BNE))
#define RVG_MATCH_BLT		(RVG_MATCH_B(BLT))
#define RVG_MATCH_BGE		(RVG_MATCH_B(BGE))
#define RVG_MATCH_BLTU		(RVG_MATCH_B(BLTU))
#define RVG_MATCH_BGEU		(RVG_MATCH_B(BGEU))
#define RVG_MATCH_LB		(RVG_MATCH_I(LB))
#define RVG_MATCH_LH		(RVG_MATCH_I(LH))
#define RVG_MATCH_LW		(RVG_MATCH_I(LW))
#define RVG_MATCH_LBU		(RVG_MATCH_I(LBU))
#define RVG_MATCH_LHU		(RVG_MATCH_I(LHU))
#define RVG_MATCH_SB		(RVG_MATCH_S(SB))
#define RVG_MATCH_SH		(RVG_MATCH_S(SH))
#define RVG_MATCH_SW		(RVG_MATCH_S(SW))
#define RVG_MATCH_ADDI		(RVG_MATCH_I(ADDI))
#define RVG_MATCH_SLTI		(RVG_MATCH_I(SLTI))
#define RVG_MATCH_SLTIU		(RVG_MATCH_I(SLTIU))
#define RVG_MATCH_XORI		(RVG_MATCH_I(XORI))
#define RVG_MATCH_ORI		(RVG_MATCH_I(ORI))
#define RVG_MATCH_ANDI		(RVG_MATCH_I(ANDI))
#define RVG_MATCH_SLLI		(RVG_SLLI_UPPER | RVG_MATCH_I(SLLI))
#define RVG_MATCH_SRLI		(RVG_SRLI_UPPER | RVG_MATCH_I(SRLI))
#define RVG_MATCH_SRAI		(RVG_SRAI_UPPER | RVG_MATCH_I(SRAI))
#define RVG_MATCH_ADD		(RVG_MATCH_R(ADD))
#define RVG_MATCH_SUB		(RVG_MATCH_R(SUB))
#define RVG_MATCH_SLL		(RVG_MATCH_R(SLL))
#define RVG_MATCH_SLT		(RVG_MATCH_R(SLT))
#define RVG_MATCH_SLTU		(RVG_MATCH_R(SLTU))
#define RVG_MATCH_XOR		(RVG_MATCH_R(XOR))
#define RVG_MATCH_SRL		(RVG_MATCH_R(SRL))
#define RVG_MATCH_SRA		(RVG_MATCH_R(SRA))
#define RVG_MATCH_OR		(RVG_MATCH_R(OR))
#define RVG_MATCH_AND		(RVG_MATCH_R(AND))
#define RVG_MATCH_NOP		(RVG_MATCH_I(NOP))
#define RVG_MATCH_FENCE		(RVG_FUNCT3_FENCE | RVG_OPCODE_FENCE)
#define RVG_MATCH_FENCETSO	0b1000001100110000000000000
#define RVG_MATCH_PAUSE		0b0000000100000000000000000
#define RVG_MATCH_ECALL		0b0000000000000000000000000
#define RVG_MATCH_EBREAK	0b0000000000010000000000000
/* F Standard Extension */
#define RVG_MATCH_FLW		(RVG_MATCH_I(FLW))
#define RVG_MATCH_FSW		(RVG_MATCH_S(FSW))
/* D Standard Extension */
#define RVG_MATCH_FLD		(RVG_MATCH_I(FLD))
#define RVG_MATCH_FSD		(RVG_MATCH_S(FSD))
/* Q Standard Extension */
#define RVG_MATCH_FLQ		(RVG_MATCH_I(FLQ))
#define RVG_MATCH_FSQ		(RVG_MATCH_S(FSQ))
/* Zicsr Standard Extension */
#define RVG_MATCH_CSRRW		(RVG_MATCH_I(CSRRW))
#define RVG_MATCH_CSRRS		(RVG_MATCH_I(CSRRS))
#define RVG_MATCH_CSRRC		(RVG_MATCH_I(CSRRC))
#define RVG_MATCH_CSRRWI	(RVG_MATCH_I(CSRRWI))
#define RVG_MATCH_CSRRSI	(RVG_MATCH_I(CSRRSI))
#define RVG_MATCH_CSRRCI	(RVG_MATCH_I(CSRRCI))
/* M Standard Extension */
#define RVG_MATCH_MUL		(RVG_MATCH_R(MUL))
#define RVG_MATCH_MULH		(RVG_MATCH_R(MULH))
#define RVG_MATCH_MULHSU	(RVG_MATCH_R(MULHSU))
#define RVG_MATCH_MULHU		(RVG_MATCH_R(MULHU))
#define RVG_MATCH_DIV		(RVG_MATCH_R(DIV))
#define RVG_MATCH_DIVU		(RVG_MATCH_R(DIVU))
#define RVG_MATCH_REM		(RVG_MATCH_R(REM))
#define RVG_MATCH_REMU		(RVG_MATCH_R(REMU))
/* A Standard Extension */
#define RVG_MATCH_LR_W		(RVG_MATCH_AMO(LR_W))
#define RVG_MATCH_SC_W		(RVG_MATCH_AMO(SC_W))
#define RVG_MATCH_AMOSWAP_W	(RVG_MATCH_AMO(AMOSWAP_W))
#define RVG_MATCH_AMOADD_W	(RVG_MATCH_AMO(AMOADD_W))
#define RVG_MATCH_AMOXOR_W	(RVG_MATCH_AMO(AMOXOR_W))
#define RVG_MATCH_AMOAND_W	(RVG_MATCH_AMO(AMOAND_W))
#define RVG_MATCH_AMOOR_W	(RVG_MATCH_AMO(AMOOR_W))
#define RVG_MATCH_AMOMIN_W	(RVG_MATCH_AMO(AMOMIN_W))
#define RVG_MATCH_AMOMAX_W	(RVG_MATCH_AMO(AMOMAX_W))
#define RVG_MATCH_AMOMINU_W	(RVG_MATCH_AMO(AMOMINU_W))
#define RVG_MATCH_AMOMAXU_W	(RVG_MATCH_AMO(AMOMAXU_W))

/* RVG 64-bit only matches */
#define RVG_MATCH_LWU		(RVG_MATCH_I(LWU))
#define RVG_MATCH_LD		(RVG_MATCH_I(LD))
#define RVG_MATCH_SD		(RVG_MATCH_S(SD))
#define RVG_MATCH_ADDIW		(RVG_MATCH_I(ADDIW))
#define RVG_MATCH_SLLIW		(RVG_MATCH_R(SLLIW))
#define RVG_MATCH_SRLIW		(RVG_MATCH_R(SRLIW))
#define RVG_MATCH_SRAIW		(RVG_MATCH_R(SRAIW))
#define RVG_MATCH_ADDW		(RVG_MATCH_R(ADDW))
#define RVG_MATCH_SUBW		(RVG_MATCH_R(SUBW))
#define RVG_MATCH_SLLW		(RVG_MATCH_R(SLLW))
#define RVG_MATCH_SRLW		(RVG_MATCH_R(SRLW))
#define RVG_MATCH_SRAW		(RVG_MATCH_R(SRAW))
/* M Standard Extension */
#define RVG_MATCH_MULW		(RVG_MATCH_R(MULW))
#define RVG_MATCH_DIVW		(RVG_MATCH_R(DIVW))
#define RVG_MATCH_DIVUW		(RVG_MATCH_R(DIVUW))
#define RVG_MATCH_REMW		(RVG_MATCH_R(REMW))
#define RVG_MATCH_REMUW		(RVG_MATCH_R(REMUW))
/* A Standard Extension */
#define RVG_MATCH_LR_D		(RVG_MATCH_AMO(LR_W))
#define RVG_MATCH_SC_D		(RVG_MATCH_AMO(SC_W))
#define RVG_MATCH_AMOSWAP_D	(RVG_MATCH_AMO(AMOSWAP_W))
#define RVG_MATCH_AMOADD_D	(RVG_MATCH_AMO(AMOADD_W))
#define RVG_MATCH_AMOXOR_D	(RVG_MATCH_AMO(AMOXOR_W))
#define RVG_MATCH_AMOAND_D	(RVG_MATCH_AMO(AMOAND_W))
#define RVG_MATCH_AMOOR_D	(RVG_MATCH_AMO(AMOOR_W))
#define RVG_MATCH_AMOMIN_D	(RVG_MATCH_AMO(AMOMIN_W))
#define RVG_MATCH_AMOMAX_D	(RVG_MATCH_AMO(AMOMAX_W))
#define RVG_MATCH_AMOMINU_D	(RVG_MATCH_AMO(AMOMINU_W))
#define RVG_MATCH_AMOMAXU_D	(RVG_MATCH_AMO(AMOMAXU_W))

/* Privileged instruction match */
#define RV_MATCH_SRET		0b00010000001000000000000001110011
#define RV_MATCH_WFI		0b00010000010100000000000001110011

/* Bit masks for each type of RVG instruction */
#define RVG_MASK_R \
	((RV_INSN_FUNCT7_MASK << RV_INSN_FUNCT7_OPOFF) | \
	 (RV_INSN_FUNCT3_MASK << RV_INSN_FUNCT3_OPOFF) | RV_INSN_OPCODE_MASK)
#define RVG_MASK_I \
	((RV_INSN_FUNCT3_MASK << RV_INSN_FUNCT3_OPOFF) | RV_INSN_OPCODE_MASK)
#define RVG_MASK_S \
	((RV_INSN_FUNCT3_MASK << RV_INSN_FUNCT3_OPOFF) | RV_INSN_OPCODE_MASK)
#define RVG_MASK_B \
	((RV_INSN_FUNCT3_MASK << RV_INSN_FUNCT3_OPOFF) | RV_INSN_OPCODE_MASK)
#define RVG_MASK_U	(RV_INSN_OPCODE_MASK)
#define RVG_MASK_J	(RV_INSN_OPCODE_MASK)
#define RVG_MASK_AMO \
	((RV_INSN_FUNCT5_MASK << RV_INSN_FUNCT5_OPOFF) | \
	 (RV_INSN_FUNCT3_MASK << RV_INSN_FUNCT3_OPOFF) | RV_INSN_OPCODE_MASK)

#if __riscv_xlen == 32
#define RVG_MASK_SHIFT (GENMASK(6, 0) << 25)
#elif __riscv_xlen == 64
#define RVG_MASK_SHIFT (GENMASK(5, 0) << 26)
#endif /* __riscv_xlen */

/* RVG instruction masks */
#define RVG_MASK_LUI		(RVG_MASK_U)
#define RVG_MASK_AUIPC		(RVG_MASK_U)
#define RVG_MASK_JAL		(RVG_MASK_J)
#define RVG_MASK_JALR		(RVG_MASK_I)
#define RVG_MASK_BEQ		(RVG_MASK_B)
#define RVG_MASK_BNE		(RVG_MASK_B)
#define RVG_MASK_BLT		(RVG_MASK_B)
#define RVG_MASK_BGE		(RVG_MASK_B)
#define RVG_MASK_BLTU		(RVG_MASK_B)
#define RVG_MASK_BGEU		(RVG_MASK_B)
#define RVG_MASK_LB		(RVG_MASK_I)
#define RVG_MASK_LH		(RVG_MASK_I)
#define RVG_MASK_LW		(RVG_MASK_I)
#define RVG_MASK_LBU		(RVG_MASK_I)
#define RVG_MASK_LHU		(RVG_MASK_I)
#define RVG_MASK_SB		(RVG_MASK_S)
#define RVG_MASK_SH		(RVG_MASK_S)
#define RVG_MASK_SW		(RVG_MASK_S)
#define RVG_MASK_ADDI		(RVG_MASK_I)
#define RVG_MASK_SLTI		(RVG_MASK_I)
#define RVG_MASK_SLTIU		(RVG_MASK_I)
#define RVG_MASK_XORI		(RVG_MASK_I)
#define RVG_MASK_ORI		(RVG_MASK_I)
#define RVG_MASK_ANDI		(RVG_MASK_I)
#define RVG_MASK_SLLI		(RVG_MASK_SHIFT | RVG_MASK_I)
#define RVG_MASK_SRLI		(RVG_MASK_SHIFT | RVG_MASK_I)
#define RVG_MASK_SRAI		(RVG_MASK_SHIFT | RVG_MASK_I)
#define RVG_MASK_ADD		(RVG_MASK_R)
#define RVG_MASK_SUB		(RVG_MASK_R)
#define RVG_MASK_SLL		(RVG_MASK_R)
#define RVG_MASK_SLT		(RVG_MASK_R)
#define RVG_MASK_SLTU		(RVG_MASK_R)
#define RVG_MASK_XOR		(RVG_MASK_R)
#define RVG_MASK_SRL		(RVG_MASK_R)
#define RVG_MASK_SRA		(RVG_MASK_R)
#define RVG_MASK_OR		(RVG_MASK_R)
#define RVG_MASK_AND		(RVG_MASK_R)
#define RVG_MASK_NOP		(RVG_MASK_I)
#define RVG_MASK_FENCE		(RVG_MASK_I)
#define RVG_MASK_FENCETSO	0xffffffff
#define RVG_MASK_PAUSE		0xffffffff
#define RVG_MASK_ECALL		0xffffffff
#define RVG_MASK_EBREAK		0xffffffff
/* F Standard Extension */
#define RVG_MASK_FLW		(RVG_MASK_I)
#define RVG_MASK_FSW		(RVG_MASK_S)
/* D Standard Extension */
#define RVG_MASK_FLD		(RVG_MASK_I)
#define RVG_MASK_FSD		(RVG_MASK_S)
/* Q Standard Extension */
#define RVG_MASK_FLQ		(RVG_MASK_I)
#define RVG_MASK_FSQ		(RVG_MASK_S)
/* Zicsr Standard Extension */
#define RVG_MASK_CSRRW		(RVG_MASK_I)
#define RVG_MASK_CSRRS		(RVG_MASK_I)
#define RVG_MASK_CSRRC		(RVG_MASK_I)
#define RVG_MASK_CSRRWI		(RVG_MASK_I)
#define RVG_MASK_CSRRSI		(RVG_MASK_I)
#define RVG_MASK_CSRRCI		(RVG_MASK_I)
/* M Standard Extension */
#define RVG_MASK_MUL		(RVG_MASK_R)
#define RVG_MASK_MULH		(RVG_MASK_R)
#define RVG_MASK_MULHSU		(RVG_MASK_R)
#define RVG_MASK_MULHU		(RVG_MASK_R)
#define RVG_MASK_DIV		(RVG_MASK_R)
#define RVG_MASK_DIVU		(RVG_MASK_R)
#define RVG_MASK_REM		(RVG_MASK_R)
#define RVG_MASK_REMU		(RVG_MASK_R)
/* A Standard Extension */
#define RVG_MASK_LR_W		(RVG_MASK_AMO)
#define RVG_MASK_SC_W		(RVG_MASK_AMO)
#define RVG_MASK_AMOSWAP_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOADD_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOXOR_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOAND_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOOR_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOMIN_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOMAX_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOMINU_W	(RVG_MASK_AMO)
#define RVG_MASK_AMOMAXU_W	(RVG_MASK_AMO)

/* RVG 64-bit only masks */
#define RVG_MASK_LWU		(RVG_MASK_I)
#define RVG_MASK_LD		(RVG_MASK_I)
#define RVG_MASK_SD		(RVG_MASK_S)
#define RVG_MASK_ADDIW		(RVG_MASK_I)
#define RVG_MASK_SLLIW		(RVG_MASK_R)
#define RVG_MASK_SRLIW		(RVG_MASK_R)
#define RVG_MASK_SRAIW		(RVG_MASK_R)
#define RVG_MASK_ADDW		(RVG_MASK_R)
#define RVG_MASK_SUBW		(RVG_MASK_R)
#define RVG_MASK_SLLW		(RVG_MASK_R)
#define RVG_MASK_SRLW		(RVG_MASK_R)
#define RVG_MASK_SRAW		(RVG_MASK_R)
/* M Standard Extension */
#define RVG_MASK_MULW		(RVG_MASK_R)
#define RVG_MASK_DIVW		(RVG_MASK_R)
#define RVG_MASK_DIVUW		(RVG_MASK_R)
#define RVG_MASK_REMW		(RVG_MASK_R)
#define RVG_MASK_REMUW		(RVG_MASK_R)
/* A Standard Extension */
#define RVG_MASK_LR_D		(RVG_MASK_AMO)
#define RVG_MASK_SC_D		(RVG_MASK_AMO)
#define RVG_MASK_AMOSWAP_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOADD_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOXOR_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOAND_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOOR_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOMIN_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOMAX_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOMINU_D	(RVG_MASK_AMO)
#define RVG_MASK_AMOMAXU_D	(RVG_MASK_AMO)

/* Privileged instruction masks */
#define RV_MASK_SRET		0xffffffff
#define RV_MASK_WFI		0xffffffff

/* RVC opcodes */
#define RVC_OPCODE_C0		0x0
#define RVC_OPCODE_C1		0x1
#define RVC_OPCODE_C2		0x2

/* RVC Segments */
#define RVC_6_2			(GENMASK(4, 0) << 2)
#define RVC_11_7		(GENMASK(4, 0) << 7)
#define RVC_TWO_11_7		(BIT(8))

/* RVC Quadrant 1 FUNCT2 */
#define RVC_FUNCT2_C_SRLI	0b00
#define RVC_FUNCT2_C_SRAI	0b01
#define RVC_FUNCT2_C_ANDI	0b10
#define RVC_FUNCT2_C_SUB	0b00
#define RVC_FUNCT2_C_XOR	0b01
#define RVC_FUNCT2_C_OR		0b10
#define RVC_FUNCT2_C_AND	0b11
#define RVC_FUNCT2_C_SUBW	0b00
#define RVC_FUNCT2_C_ADDW	0b01

/* RVC Quadrant 0 FUNCT3 */
#define RVC_FUNCT3_C_ADDI4SPN	0b000
#define RVC_FUNCT3_C_FLD	0b001
#define RVC_FUNCT3_C_LW		0b010
#define RVC_FUNCT3_C_FLW	0b011
#define RVC_FUNCT3_C_LD		0b011
#define RVC_FUNCT3_C_FSD	0b101
#define RVC_FUNCT3_C_SW		0b110
#define RVC_FUNCT3_C_FSW	0b111
#define RVC_FUNCT3_C_SD		0b111
/* RVC Quadrant 1 FUNCT3 */
#define RVC_FUNCT3_C_NOP	0b000
#define RVC_FUNCT3_C_ADDI	0b000
#define RVC_FUNCT3_C_JAL	0b001
#define RVC_FUNCT3_C_ADDIW	0b001
#define RVC_FUNCT3_C_LI		0b010
#define RVC_FUNCT3_C_ADDI16SP	0b011
#define RVC_FUNCT3_C_LUI	0b011
#define RVC_FUNCT3_C_SRLI	0b100
#define RVC_FUNCT3_C_SRAI	0b100
#define RVC_FUNCT3_C_ANDI	0b100
#define RVC_FUNCT3_C_J		0b101
#define RVC_FUNCT3_C_BEQZ	0b110
#define RVC_FUNCT3_C_BNEZ	0b111
/* RVC Quadrant 2 FUNCT3 */
#define RVC_FUNCT3_C_SLLI	0b000
#define RVC_FUNCT3_C_FLDSP	0b001
#define RVC_FUNCT3_C_LWSP	0b010
#define RVC_FUNCT3_C_FLWSP	0b011
#define RVC_FUNCT3_C_LDSP	0b011
#define RVC_FUNCT3_C_FSDSP	0b101
#define RVC_FUNCT3_C_SWSP	0b110
#define RVC_FUNCT3_C_FSWSP	0b111
#define RVC_FUNCT3_C_SDSP	0b111

/* RVC Quadrant 2 FUNCT4 */
#define RVC_FUNCT4_C_JR		0b1000
#define RVC_FUNCT4_C_MV		0b1000
#define RVC_FUNCT4_C_EBREAK	0b1001
#define RVC_FUNCT4_C_JALR	0b1001
#define RVC_FUNCT4_C_ADD	0b1001

/* RVC Quadrant 1 FUNCT6 */
#define RVC_FUNCT6_C_SUB	0b100011
#define RVC_FUNCT6_C_XOR	0b100011
#define RVC_FUNCT6_C_OR		0b100011
#define RVC_FUNCT6_C_AND	0b100011
#define RVC_FUNCT6_C_SUBW	0b100111
#define RVC_FUNCT6_C_ADDW	0b100111

/* RVC instruction match types */
#define RVC_MATCH_CR(f_)	(RVC_FUNCT4_C_##f_ << RVC_INSN_FUNCT4_OPOFF)
#define RVC_MATCH_CI(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)
#define RVC_MATCH_CSS(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)
#define RVC_MATCH_CIW(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)
#define RVC_MATCH_CL(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)
#define RVC_MATCH_CS(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)
#define RVC_MATCH_CA(f_)	(RVC_FUNCT6_C_##f_ << RVC_INSN_FUNCT6_OPOFF | \
			RVC_FUNCT2_C_##f_ << RVC_INSN_FUNCT2_CA_OPOFF)
#define RVC_MATCH_CB(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)
#define RVC_MATCH_CJ(f_)	(RVC_FUNCT3_C_##f_ << RVC_INSN_FUNCT3_OPOFF)

/* RVC Quadrant 0 matches */
#define RVC_MATCH_C_ADDI4SPN	(RVC_MATCH_CIW(ADDI4SPN) | RVC_OPCODE_C0)
#define RVC_MATCH_C_FLD		(RVC_MATCH_CL(FLD) | RVC_OPCODE_C0)
#define RVC_MATCH_C_LW		(RVC_MATCH_CL(LW) | RVC_OPCODE_C0)
#define RVC_MATCH_C_FLW		(RVC_MATCH_CL(FLW) | RVC_OPCODE_C0)
#define RVC_MATCH_C_LD		(RVC_MATCH_CL(LD) | RVC_OPCODE_C0)
#define RVC_MATCH_C_FSD		(RVC_MATCH_CS(FSD) | RVC_OPCODE_C0)
#define RVC_MATCH_C_SW		(RVC_MATCH_CS(SW) | RVC_OPCODE_C0)
#define RVC_MATCH_C_FSW		(RVC_MATCH_CS(FSW) | RVC_OPCODE_C0)
#define RVC_MATCH_C_SD		(RVC_MATCH_CS(SD) | RVC_OPCODE_C0)
/* RVC Quadrant 1 matches */
#define RVC_MATCH_C_NOP		(RVC_MATCH_CI(NOP) | RVC_OPCODE_C1)
#define RVC_MATCH_C_ADDI	(RVC_MATCH_CI(ADDI) | RVC_OPCODE_C1)
#define RVC_MATCH_C_JAL		(RVC_MATCH_CJ(JAL) | RVC_OPCODE_C1)
#define RVC_MATCH_C_ADDIW	(RVC_MATCH_CI(ADDIW) | RVC_OPCODE_C1)
#define RVC_MATCH_C_LI		(RVC_MATCH_CI(LI) | RVC_OPCODE_C1)
#define RVC_MATCH_C_ADDI16SP \
	(RVC_MATCH_CI(ADDI16SP) | RVC_TWO_11_7 | RVC_OPCODE_C1)
#define RVC_MATCH_C_LUI (RVC_MATCH_CI(LUI) | RVC_OPCODE_C1)
#define RVC_MATCH_C_SRLI \
	(RVC_MATCH_CB(SRLI) | RVC_FUNCT2_C_SRLI << RVC_INSN_FUNCT2_CB_OPOFF | \
	 RVC_OPCODE_C1)
#define RVC_MATCH_C_SRAI \
	(RVC_MATCH_CB(SRAI) | RVC_FUNCT2_C_SRAI << RVC_INSN_FUNCT2_CB_OPOFF | \
	 RVC_OPCODE_C1)
#define RVC_MATCH_C_ANDI \
	(RVC_MATCH_CB(ANDI) | RVC_FUNCT2_C_ANDI << RVC_INSN_FUNCT2_CB_OPOFF | \
	 RVC_OPCODE_C1)
#define RVC_MATCH_C_SUB (RVC_MATCH_CA(SUB) | RVC_OPCODE_C1)
#define RVC_MATCH_C_XOR		(RVC_MATCH_CA(XOR) | RVC_OPCODE_C1)
#define RVC_MATCH_C_OR		(RVC_MATCH_CA(OR) | RVC_OPCODE_C1)
#define RVC_MATCH_C_AND		(RVC_MATCH_CA(AND) | RVC_OPCODE_C1)
#define RVC_MATCH_C_SUBW	(RVC_MATCH_CA(SUBW) | RVC_OPCODE_C1)
#define RVC_MATCH_C_ADDW	(RVC_MATCH_CA(ADDW) | RVC_OPCODE_C1)
#define RVC_MATCH_C_J		(RVC_MATCH_CJ(J) | RVC_OPCODE_C1)
#define RVC_MATCH_C_BEQZ	(RVC_MATCH_CB(BEQZ) | RVC_OPCODE_C1)
#define RVC_MATCH_C_BNEZ	(RVC_MATCH_CB(BNEZ) | RVC_OPCODE_C1)
/* RVC Quadrant 2 matches */
#define RVC_MATCH_C_SLLI	(RVC_MATCH_CI(SLLI) | RVC_OPCODE_C2)
#define RVC_MATCH_C_FLDSP	(RVC_MATCH_CI(FLDSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_LWSP	(RVC_MATCH_CI(LWSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_FLWSP	(RVC_MATCH_CI(FLWSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_LDSP	(RVC_MATCH_CI(LDSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_JR		(RVC_MATCH_CR(JR) | RVC_OPCODE_C2)
#define RVC_MATCH_C_MV		(RVC_MATCH_CR(MV) | RVC_OPCODE_C2)
#define RVC_MATCH_C_EBREAK	(RVC_MATCH_CR(EBREAK) | RVC_OPCODE_C2)
#define RVC_MATCH_C_JALR	(RVC_MATCH_CR(JALR) | RVC_OPCODE_C2)
#define RVC_MATCH_C_ADD		(RVC_MATCH_CR(ADD) | RVC_OPCODE_C2)
#define RVC_MATCH_C_FSDSP	(RVC_MATCH_CSS(FSDSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_SWSP	(RVC_MATCH_CSS(SWSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_FSWSP	(RVC_MATCH_CSS(FSWSP) | RVC_OPCODE_C2)
#define RVC_MATCH_C_SDSP	(RVC_MATCH_CSS(SDSP) | RVC_OPCODE_C2)

/* Bit masks for each type of RVC instruction */
#define RVC_MASK_CR \
	(RVC_INSN_FUNCT4_MASK << RVC_INSN_FUNCT4_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CI \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CSS \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CIW \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CL \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CS \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CA \
	(RVC_INSN_FUNCT6_MASK << RVC_INSN_FUNCT6_OPOFF | \
	 RVC_INSN_FUNCT2_MASK << RVC_INSN_FUNCT2_CA_OPOFF | \
	 RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CB \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)
#define RVC_MASK_CJ \
	(RVC_INSN_FUNCT3_MASK << RVC_INSN_FUNCT3_OPOFF | RVC_INSN_OPCODE_MASK)

/* RVC Quadrant 0 masks */
#define RVC_MASK_C_ADDI4SPN	(RVC_MASK_CIW)
#define RVC_MASK_C_FLD		(RVC_MASK_CL)
#define RVC_MASK_C_LW		(RVC_MASK_CL)
#define RVC_MASK_C_FLW		(RVC_MASK_CL)
#define RVC_MASK_C_LD		(RVC_MASK_CL)
#define RVC_MASK_C_FSD		(RVC_MASK_CS)
#define RVC_MASK_C_SW		(RVC_MASK_CS)
#define RVC_MASK_C_FSW		(RVC_MASK_CS)
#define RVC_MASK_C_SD		(RVC_MASK_CS)
/* RVC Quadrant 1 masks */
#define RVC_MASK_C_NOP		(RVC_MASK_CI)
#define RVC_MASK_C_ADDI		(RVC_MASK_CI)
#define RVC_MASK_C_JAL		(RVC_MASK_CJ)
#define RVC_MASK_C_ADDIW	(RVC_MASK_CI)
#define RVC_MASK_C_LI		(RVC_MASK_CI)
#define RVC_MASK_C_ADDI16SP	(RVC_MASK_CI | RVC_TWO_11_7)
#define RVC_MASK_C_LUI		(RVC_MASK_CI)
#define RVC_MASK_C_SRLI \
	(RVC_MASK_CB | RVC_INSN_FUNCT2_MASK << RVC_INSN_FUNCT2_CB_OPOFF)
#define RVC_MASK_C_SRAI \
	(RVC_MASK_CB | RVC_INSN_FUNCT2_MASK << RVC_INSN_FUNCT2_CB_OPOFF)
#define RVC_MASK_C_ANDI \
	(RVC_MASK_CB | RVC_INSN_FUNCT2_MASK << RVC_INSN_FUNCT2_CB_OPOFF)
#define RVC_MASK_C_SUB		(RVC_MASK_CA)
#define RVC_MASK_C_XOR		(RVC_MASK_CA)
#define RVC_MASK_C_OR		(RVC_MASK_CA)
#define RVC_MASK_C_AND		(RVC_MASK_CA)
#define RVC_MASK_C_SUBW		(RVC_MASK_CA)
#define RVC_MASK_C_ADDW		(RVC_MASK_CA)
#define RVC_MASK_C_J		(RVC_MASK_CJ)
#define RVC_MASK_C_BEQZ		(RVC_MASK_CB)
#define RVC_MASK_C_BNEZ		(RVC_MASK_CB)
/* RVC Quadrant 2 masks */
#define RVC_MASK_C_SLLI		(RVC_MASK_CI)
#define RVC_MASK_C_FLDSP	(RVC_MASK_CI)
#define RVC_MASK_C_LWSP		(RVC_MASK_CI)
#define RVC_MASK_C_FLWSP	(RVC_MASK_CI)
#define RVC_MASK_C_LDSP		(RVC_MASK_CI)
#define RVC_MASK_C_JR		(RVC_MASK_CR | RVC_6_2)
#define RVC_MASK_C_MV		(RVC_MASK_CR)
#define RVC_MASK_C_EBREAK	(RVC_MASK_CR | RVC_11_7 | RVC_6_2)
#define RVC_MASK_C_JALR		(RVC_MASK_CR | RVC_6_2)
#define RVC_MASK_C_ADD		(RVC_MASK_CR)
#define RVC_MASK_C_FSDSP	(RVC_MASK_CSS)
#define RVC_MASK_C_SWSP		(RVC_MASK_CSS)
#define RVC_MASK_C_FSWSP	(RVC_MASK_CSS)
#define RVC_MASK_C_SDSP		(RVC_MASK_CSS)

#define INSN_C_MASK		0x3
#define INSN_IS_C(insn)	(((insn) & INSN_C_MASK) != INSN_C_MASK)
#define INSN_LEN(insn)	(INSN_IS_C(insn) ? 2 : 4)

#define __RISCV_INSN_FUNCS(name, mask, val)				\
static __always_inline bool riscv_insn_is_##name(u32 code)		\
{									\
	BUILD_BUG_ON(~(mask) & (val));					\
	return (code & (mask)) == (val);				\
}

/* R-Type Instructions */
#define __RISCV_RTYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rd, u8 rs1, u8 rs2)	\
{									\
	return rv_r_insn(RVG_FUNCT7_##upper_name, rs2, rs1,		\
				RVG_FUNCT3_##upper_name, rd,		\
				RVG_OPCODE_##upper_name);		\
}

/* I-Type Instructions */
#define __RISCV_ITYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rd, u8 rs1, u16 imm11_0) \
{									\
	return rv_i_insn(imm11_0, rs1, RVG_FUNCT3_##upper_name,		\
				rd, RVG_OPCODE_##upper_name);		\
}

/* S-Type Instructions */
#define __RISCV_STYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rs1, u16 imm11_0, u8 rs2) \
{									\
	return rv_s_insn(imm11_0, rs2, rs1, RVG_FUNCT3_##upper_name,	\
				RVG_OPCODE_##upper_name);		\
}

/* B-Type Instructions */
#define __RISCV_BTYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rs1, u8 rs2, u16 imm12_1) \
{									\
	return rv_b_insn(imm12_1, rs2, rs1, RVG_FUNCT3_##upper_name,	\
				RVG_OPCODE_##upper_name);		\
}

/* Reversed B-Type Instructions */
#define __RISCV_REV_BTYPE_FUNCS(name, upper_name)			\
static __always_inline bool rv_##name(u8 rs1, u8 rs2, u16 imm12_1) \
{									\
	return rv_b_insn(imm12_1, rs1, rs2, RVG_FUNCT3_##upper_name,	\
				RVG_OPCODE_##upper_name);		\
}

/* U-Type Instructions */
#define __RISCV_UTYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rd, u32 imm31_12)	\
{									\
	return rv_u_insn(imm31_12, rd, RVG_OPCODE_##upper_name);	\
}

/* J-Type Instructions */
#define __RISCV_JTYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rd, u32 imm20_1)	\
{									\
	return rv_j_insn(imm20_1, rd, RVG_OPCODE_##upper_name);		\
}

/* AMO-Type Instructions */
#define __RISCV_AMOTYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_##name(u8 rd, u8 rs2, u8 rs1, u8 aq, \
						u8 rl)			\
{									\
	return rv_amo_insn(RVG_FUNCT5_##upper_name, aq, rl, rs2, rs1,	\
			RVG_FUNCT3_##upper_name, rd, RVG_OPCODE_##upper_name); \
}

/* FENCE Instruction */
#define __RISCV_NOPTYPE_FUNCS(name, upper_name)				\
static __always_inline bool rv_nop(void)				\
{									\
	return RVG_MATCH_NOP;						\
}

/* FENCE Instruction */
#define __RISCV_FENCETYPE_FUNCS(name, upper_name)			\
static __always_inline bool rv_fence(u8 pred, u8 succ)			\
{									\
	u16 imm11_0 = pred << 4 | succ;					\
	return rv_i_insn(imm11_0, 0, 0, 0, RVG_OPCODE_FENCE);		\
}

/* FENCETSO Instruction */
#define __RISCV_FENCETSOTYPE_FUNCS(name, upper_name)			\
static __always_inline bool rv_fencetso(void)				\
{									\
	return RVG_MATCH_FENCETSO; \
}

/* PAUSE Instruction */
#define __RISCV_PAUSETYPE_FUNCS(name, upper_name)			\
static __always_inline bool rv_pause(void)				\
{									\
	return RVG_MATCH_PAUSE; \
}

/* ECALL Instruction */
#define __RISCV_ECALLTYPE_FUNCS(name, upper_name)			\
static __always_inline bool rv_ecall(void)				\
{									\
	return RVG_MATCH_ECALL; \
}

/* EBREAK Instruction */
#define __RISCV_EBREAKTYPE_FUNCS(name, upper_name)			\
static __always_inline bool rv_ebreak(void)				\
{									\
	return RVG_MATCH_EBREAK; \
}

#define __RVG_INSN_FUNCS(name, upper_name, type)			\
static __always_inline bool riscv_insn_is_##name(u32 code)		\
{									\
	BUILD_BUG_ON(~(RVG_MASK_##upper_name) & (RVG_MATCH_##upper_name)); \
	return (code & (RVG_MASK_##upper_name)) == (RVG_MATCH_##upper_name); \
}									\
__RISCV_##type##TYPE_FUNCS(name, upper_name)

/* Compressed instruction types */

/* CR-Type Instructions */
#define __RISCV_CRTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rd, u8 rs)			\
{									\
	return rv_cr_insn(RVC_FUNCT4_##upper_name, rd, rs,		\
			RVC_OPCODE_##opcode);				\
}

#define __RISCV_CR_ZERO_RSTYPE_FUNCS(name, upper_name, opcode)		\
static __always_inline bool rv##name(u8 rs1)				\
{									\
	return rv_cr_insn(RVC_FUNCT4_##upper_name, rs1, RV_REG_ZERO,	\
			RVC_OPCODE_##opcode);				\
}

/* CI-Type Instructions */
#define __RISCV_CITYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rd, u32 imm)			\
{									\
	u32 imm_hi = RV##upper_name##_IMM_HI(imm);			\
	u32 imm_lo = RV##upper_name##_IMM_LO(imm);			\
	return rv_ci_insn(RVC_FUNCT3_##upper_name, imm_hi, rd,		\
			imm_lo, RVC_OPCODE_##opcode);			\
}

#define __RISCV_CI_SPTYPE_FUNCS(name, upper_name, opcode)		\
static __always_inline bool rv##name(u32 imm)			\
{									\
	u32 imm_hi = RV##upper_name##_IMM_HI(imm);			\
	u32 imm_lo = RV##upper_name##_IMM_LO(imm);			\
	return rv_ci_insn(RVC_FUNCT3_##upper_name, imm_hi, 2,		\
			imm_lo, RVC_OPCODE_##opcode);			\
}

/* CSS-Type Instructions */
#define __RISCV_CSSTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u32 imm, u8 rs2)			\
{									\
	imm = RV##upper_name##_IMM(imm);				\
	return rv_css_insn(RVC_FUNCT3_##upper_name, imm, rs2,		\
			RVC_OPCODE_##opcode);				\
}

/* CIW-Type Instructions */
#define __RISCV_CIWTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rd, u32 imm)			\
{									\
	imm = RV##upper_name##_IMM(imm);				\
	return rv_ciw_insn(RVC_FUNCT3_##upper_name, imm, rd,		\
			RVC_OPCODE_##opcode);				\
}

/* CL-Type Instructions */
#define __RISCV_CLTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rd, u32 imm, u8 rs1)		\
{									\
	u32 imm_hi = RV##upper_name##_IMM_HI(imm);			\
	u32 imm_lo = RV##upper_name##_IMM_LO(imm);			\
	return rv_cl_insn(RVC_FUNCT3_##upper_name, imm_hi, rs1, rd,	\
			imm_lo, RVC_OPCODE_##opcode);			\
}

/* CS-Type Instructions */
#define __RISCV_CSTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rs1, u32 imm, u8 rs2)		\
{									\
	u32 imm_hi = RV##upper_name##_IMM_HI(imm);			\
	u32 imm_lo = RV##upper_name##_IMM_LO(imm);			\
	return rv_cs_insn(RVC_FUNCT3_##upper_name, imm_hi, rs1, imm_lo,	\
			rs2, RVC_OPCODE_##opcode);			\
}

/* CA-Type Instructions */
#define __RISCV_CATYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rd, u8 rs2)			\
{									\
	return rv_ca_insn(RVC_FUNCT6_##upper_name, rd,			\
			RVC_FUNCT2_##upper_name, rs2,			\
			RVC_OPCODE_##opcode);				\
}

/* CB-Type Instructions */
#define __RISCV_CBTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u8 rd, u32 imm)			\
{									\
	u32 imm_hi = RV##upper_name##_IMM_HI(imm);			\
	u32 imm_lo = RV##upper_name##_IMM_LO(imm);			\
	return rv_cb_insn(RVC_FUNCT3_##upper_name, imm_hi, rd, imm_lo,	\
			RVC_OPCODE_##opcode);				\
}

#define __RISCV_CB_FUNCT2TYPE_FUNCS(name, upper_name, opcode)		\
static __always_inline bool rv##name(u8 rd, u32 imm)			\
{									\
	u32 imm_hi = RV##upper_name##_IMM_HI(imm);			\
	u32 imm_lo = RV##upper_name##_IMM_LO(imm);			\
	imm_hi = (imm_hi << 2) | RVC_FUNCT2_##upper_name;		\
	return rv_cb_insn(RVC_FUNCT3_##upper_name, imm_hi, rd, imm_lo,	\
			RVC_OPCODE_##opcode);				\
}

/* CJ-Type Instructions */
#define __RISCV_CJTYPE_FUNCS(name, upper_name, opcode)			\
static __always_inline bool rv##name(u32 imm)				\
{									\
	imm = RV##upper_name##_IMM(imm);				\
	return rv_cj_insn(RVC_FUNCT3_##upper_name, imm,			\
			RVC_OPCODE_##opcode);				\
}

/* CEBREAK instruction */
#define __RISCV_CEBREAKTYPE_FUNCS(name, upper_name, opcode)		\
static __always_inline bool rv##name(u32 imm)				\
{									\
	return RVC_MATCH_C_EBREAK;					\
}

/* CNOP instruction */
#define __RISCV_CNOPTYPE_FUNCS(name, upper_name, opcode)		\
static __always_inline bool rv##name(u32 imm)				\
{									\
	return RVC_MATCH_C_NOP;						\
}

#define __RVC_INSN_IS_DEFAULTTYPE(name, upper_name)			\
static __always_inline bool riscv_insn_is_##name(u32 code)		\
{									\
	BUILD_BUG_ON(~(RVC_MASK_##upper_name) & (RVC_MATCH_##upper_name)); \
	return (code & (RVC_MASK_##upper_name)) == (RVC_MATCH_##upper_name); \
}

#define __RVC_INSN_IS_NON_ZERO_RS1_RDTYPE(name, upper_name)		\
static __always_inline bool riscv_insn_is_##name(u32 code)		\
{									\
	BUILD_BUG_ON(~(RVC_MASK_##upper_name) & (RVC_MATCH_##upper_name)); \
	return ((code & (RVC_MASK_##upper_name)) == (RVC_MATCH_##upper_name)) \
		&& (RVC_X(code, RVC_C0_RS1_OPOFF, RV_STANDARD_REG_MASK) != 0); \
}

#define __RVC_INSN_IS_NON_ZERO_TWO_RDTYPE(name, upper_name)		\
static __always_inline bool riscv_insn_is_##name(u32 code)		\
{									\
	BUILD_BUG_ON(~(RVC_MASK_##upper_name) & (RVC_MATCH_##upper_name)); \
	return ((code & (RVC_MASK_##upper_name)) == (RVC_MATCH_##upper_name)) \
		&& (RVC_X(code, RVC_C0_RS1_OPOFF, RV_STANDARD_REG_MASK) != 0) \
		&& (RVC_X(code, RVC_C0_RS1_OPOFF, RV_STANDARD_REG_MASK) != 2); \
}

#define __RVC_INSN_IS_NON_ZERO_RD_RS2TYPE(name, upper_name)		\
static __always_inline bool riscv_insn_is_##name(u32 code)		\
{									\
	BUILD_BUG_ON(~(RVC_MASK_##upper_name) & (RVC_MATCH_##upper_name)); \
	return ((code & (RVC_MASK_##upper_name)) == (RVC_MATCH_##upper_name)) \
		&& (RVC_X(code, RVC_C0_RS1_OPOFF, RV_STANDARD_REG_MASK) != 0) \
		&& (RVC_X(code, RVC_C0_RD_OPOFF, RV_STANDARD_REG_MASK) != 0); \
}

#define __RVC_INSN_FUNCS(name, upper_name, type, opcode, equality_type)	\
__RVC_INSN_IS_##equality_type##TYPE(name, upper_name)			\
__RISCV_##type##TYPE_FUNCS(name, upper_name, opcode)

/* special case to catch _any_ system instruction */
static __always_inline bool riscv_insn_is_system(u32 code)
{
	return (code & RV_INSN_OPCODE_MASK) == RVG_OPCODE_SYSTEM;
}

/* special case to catch _any_ branch instruction */
static __always_inline bool riscv_insn_is_branch(u32 code)
{
	return (code & RV_INSN_OPCODE_MASK) == RVG_OPCODE_BRANCH;
}

#define RV_IMM_SIGN(x) (-(((x) >> 31) & 1))
#define RVC_IMM_SIGN(x) (-(((x) >> 12) & 1))
#define RV_X(X, s, mask)  (((X) >> (s)) & (mask))
#define RVC_X(X, s, mask) RV_X(X, s, mask)

#define RV_EXTRACT_RS1_REG(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RVG_RS1_OPOFF, RVG_RS1_MASK)); })

#define RV_EXTRACT_RS2_REG(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RVG_RS2_OPOFF, RVG_RS2_MASK)); })

#define RV_EXTRACT_RD_REG(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RVG_RD_OPOFF, RVG_RD_MASK)); })

#define RVC_EXTRACT_R_RS2_REG(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RVC_C0_RS2_OPOFF, RV_COMPRESSED_REG_MASK)); })

#define RVC_EXTRACT_SA_RS2_REG(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RVC_C2_RS2_OPOFF, RV_STANDARD_REG_MASK)); })

#define RV_EXTRACT_FUNCT3(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RV_INSN_FUNCT3_OPOFF, RV_INSN_FUNCT3_MASK)); })

#define RV_EXTRACT_UTYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RV_U_IMM_31_12_OPOFF, RV_U_IMM_31_12_MASK) \
		<< RV_U_IMM_31_12_OFF) | \
	(RV_IMM_SIGN(x_) << RV_U_IMM_SIGN_OFF); })

#define RV_EXTRACT_JTYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RV_J_IMM_10_1_OPOFF, RV_J_IMM_10_1_MASK) \
		<< RV_J_IMM_10_1_OFF) | \
	(RV_X(x_, RV_J_IMM_11_OPOFF, RV_J_IMM_11_MASK) \
		<< RV_J_IMM_11_OFF) | \
	(RV_X(x_, RV_J_IMM_19_12_OPOFF, RV_J_IMM_19_12_MASK) \
		<< RV_J_IMM_19_12_OFF) | \
	(RV_IMM_SIGN(x_) << RV_J_IMM_SIGN_OFF); })

#define RV_EXTRACT_ITYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RV_I_IMM_11_0_OPOFF, RV_I_IMM_11_0_MASK) \
		<< RV_I_IMM_11_0_OFF) | \
	(RV_IMM_SIGN(x_) << RV_I_IMM_SIGN_OFF); })

#define RV_EXTRACT_BTYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	(RV_X(x_, RV_B_IMM_4_1_OPOFF, RV_B_IMM_4_1_MASK) \
		<< RV_B_IMM_4_1_OFF) | \
	(RV_X(x_, RV_B_IMM_10_5_OPOFF, RV_B_IMM_10_5_MASK) \
		<< RV_B_IMM_10_5_OFF) | \
	(RV_X(x_, RV_B_IMM_11_OPOFF, RV_B_IMM_11_MASK) << RV_B_IMM_11_OFF) | \
	(RV_IMM_SIGN(x_) << RV_B_IMM_SIGN_OFF); })

#define RVC_EXTRACT_JTYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	(RVC_X(x_, RVC_J_IMM_3_1_OPOFF, RVC_J_IMM_3_1_MASK) \
		<< RVC_J_IMM_3_1_OFF) | \
	(RVC_X(x_, RVC_J_IMM_4_OPOFF, RVC_J_IMM_4_MASK) << RVC_J_IMM_4_OFF) | \
	(RVC_X(x_, RVC_J_IMM_5_OPOFF, RVC_J_IMM_5_MASK) << RVC_J_IMM_5_OFF) | \
	(RVC_X(x_, RVC_J_IMM_6_OPOFF, RVC_J_IMM_6_MASK) << RVC_J_IMM_6_OFF) | \
	(RVC_X(x_, RVC_J_IMM_7_OPOFF, RVC_J_IMM_7_MASK) << RVC_J_IMM_7_OFF) | \
	(RVC_X(x_, RVC_J_IMM_9_8_OPOFF, RVC_J_IMM_9_8_MASK) \
		<< RVC_J_IMM_9_8_OFF) | \
	(RVC_X(x_, RVC_J_IMM_10_OPOFF, RVC_J_IMM_10_MASK) \
		<< RVC_J_IMM_10_OFF) | \
	(RVC_IMM_SIGN(x_) << RVC_J_IMM_SIGN_OFF); })

#define RVC_EXTRACT_BTYPE_IMM(x) \
	({typeof(x) x_ = (x); \
	(RVC_X(x_, RVC_BZ_IMM_2_1_OPOFF, RVC_BZ_IMM_2_1_MASK) \
		<< RVC_BZ_IMM_2_1_OFF) | \
	(RVC_X(x_, RVC_BZ_IMM_4_3_OPOFF, RVC_BZ_IMM_4_3_MASK) \
		<< RVC_BZ_IMM_4_3_OFF) | \
	(RVC_X(x_, RVC_BZ_IMM_5_OPOFF, RVC_BZ_IMM_5_MASK) \
		<< RVC_BZ_IMM_5_OFF) | \
	(RVC_X(x_, RVC_BZ_IMM_7_6_OPOFF, RVC_BZ_IMM_7_6_MASK) \
		<< RVC_BZ_IMM_7_6_OFF) | \
	(RVC_IMM_SIGN(x_) << RVC_BZ_IMM_SIGN_OFF); })

#define RVG_EXTRACT_SYSTEM_CSR(x) \
	({typeof(x) x_ = (x); \
	RV_X(x_, RVG_SYSTEM_CSR_OPOFF, RVG_SYSTEM_CSR_MASK); })

#define RVFDQ_EXTRACT_FL_FS_WIDTH(x) \
	({typeof(x) x_ = (x); RV_X(x_, RVG_FL_FS_WIDTH_OFF, \
				RVG_FL_FS_WIDTH_MASK); })

#define RVV_EXRACT_VL_VS_WIDTH(x) RVFDQ_EXTRACT_FL_FS_WIDTH(x)

/*
 * Get the rd from an RVG instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline u32 riscv_insn_extract_rd(u32 insn)
{
	return RV_EXTRACT_RD_REG(insn);
}

/*
 * Get the rs1 from an RVG instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline u32 riscv_insn_extract_rs1(u32 insn)
{
	return RV_EXTRACT_RS1_REG(insn);
}

/*
 * Get the rs2 from an RVG instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline u32 riscv_insn_extract_rs2(u32 insn)
{
	return RV_EXTRACT_RS2_REG(insn);
}

/*
 * Get the rs2 from a CR instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline u32 riscv_insn_extract_cr_rs2(u32 insn)
{
	return RVC_EXTRACT_R_RS2_REG(insn);
}

/*
 * Get the rs2 from a CS or a CA instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline u32 riscv_insn_extract_csca_rs2(u32 insn)
{
	return RVC_EXTRACT_SA_RS2_REG(insn);
}

/*
 * Get the funct3 from an RVG instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline u32 riscv_insn_extract_funct3(u32 insn)
{
	return RV_EXTRACT_FUNCT3(insn);
}

/*
 * Get the immediate from a I-type instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline s32 riscv_insn_extract_itype_imm(u32 insn)
{
	return RV_EXTRACT_ITYPE_IMM(insn);
}

/*
 * Get the immediate from a U-type instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline s32 riscv_insn_extract_utype_imm(u32 insn)
{
	return RV_EXTRACT_UTYPE_IMM(insn);
}

/*
 * Get the immediate from a B-type instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline s32 riscv_insn_extract_btype_imm(u32 insn)
{
	return RV_EXTRACT_BTYPE_IMM(insn);
}

/*
 * Get the immediate from a J-type instruction.
 *
 * @insn: instruction to process
 * Return: immediate
 */
static inline s32 riscv_insn_extract_jtype_imm(u32 insn)
{
	return RV_EXTRACT_JTYPE_IMM(insn);
}

/*
 * Update a I-type instruction with an immediate value.
 *
 * @insn: pointer to the itype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_itype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all I-type IMM bits sit at 31:20 */
	*insn &= ~GENMASK(31, 20);
	*insn |= (RV_X(imm, RV_I_IMM_11_0_OFF, RV_I_IMM_11_0_MASK)
		  << RV_I_IMM_11_0_OPOFF);
}

/*
 * Update a S-type instruction with an immediate value.
 *
 * @insn: pointer to the stype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_stype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all S-type IMM bits sit at 31:25 and 11:7 */
	*insn &= ~(GENMASK(31, 25) | GENMASK(11, 7));
	*insn |= (RV_X(imm, RV_S_IMM_4_0_OFF, RV_S_IMM_4_0_MASK)
		  << RV_S_IMM_4_0_OPOFF) |
		 (RV_X(imm, RV_S_IMM_11_5_OFF, RV_S_IMM_11_5_MASK)
		  << RV_S_IMM_11_5_OPOFF);
}

/*
 * Update a B-type instruction with an immediate value.
 *
 * @insn: pointer to the btype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_btype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all B-type IMM bits sit at 31:25 and 11:7 */
	*insn &= ~(GENMASK(31, 25) | GENMASK(11, 7));
	*insn |= (RV_X(imm, RV_B_IMM_4_1_OFF, RV_B_IMM_4_1_MASK)
		  << RV_B_IMM_4_1_OPOFF) |
		 (RV_X(imm, RV_B_IMM_10_5_OFF, RV_B_IMM_10_5_MASK)
		  << RV_B_IMM_10_5_OPOFF) |
		 (RV_X(imm, RV_B_IMM_11_OFF, RV_B_IMM_11_MASK)
		  << RV_B_IMM_11_OPOFF) |
		 (RV_X(imm, RV_B_IMM_SIGN_OFF, RV_B_IMM_SIGN_MASK)
		  << RV_B_IMM_SIGN_OPOFF);
}

/*
 * Update a U-type instruction with an immediate value.
 *
 * @insn: pointer to the jtype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_utype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all U-type IMM bits sit at 31:12 */
	*insn &= ~GENMASK(31, 12);
	*insn |= (RV_X(imm, RV_S_IMM_31_12_OFF, RV_S_IMM_31_12_MASK)
		  << RV_S_IMM_31_12_OPOFF);
}

/*
 * Update a J-type instruction with an immediate value.
 *
 * @insn: pointer to the jtype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_jtype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all J-type IMM bits sit at 31:12 */
	*insn &= ~GENMASK(31, 12);
	*insn |= (RV_X(imm, RV_J_IMM_10_1_OFF, RV_J_IMM_10_1_MASK)
		  << RV_J_IMM_10_1_OPOFF) |
		 (RV_X(imm, RV_J_IMM_11_OFF, RV_J_IMM_11_MASK)
		  << RV_J_IMM_11_OPOFF) |
		 (RV_X(imm, RV_J_IMM_19_12_OFF, RV_J_IMM_19_12_MASK)
		  << RV_J_IMM_19_12_OPOFF) |
		 (RV_X(imm, RV_J_IMM_SIGN_OFF, 1) << RV_J_IMM_SIGN_OPOFF);
}

/*
 * Update a CI-type instruction with an immediate value.
 * slot.
 *
 * @insn: pointer to the citype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_citype_imm(u32 *insn, u32 imm_hi,
						u32 imm_lo)
{
	/* drop the old IMMs, all CI-type IMM bits sit at 12 and 6:2 */
	*insn &= ~(12 | GENMASK(6, 2));
	*insn |= (RV_X(imm_lo, RVC_I_IMM_LO_OFF, RVC_I_IMM_LO_MASK)
		  << RVC_I_IMM_LO_OPOFF) |
		 (RV_X(imm_hi, RVC_I_IMM_HI_OFF, RVC_I_IMM_HI_MASK)
		  << RVC_I_IMM_HI_OPOFF);
}

/*
 * Update a CSS-type instruction with an immediate value.
 *
 * @insn: pointer to the csstype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_csstype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all CSS-type IMM bits sit at 11:6 */
	*insn &= ~GENMASK(11, 6);
	*insn |= (RV_X(imm, RVC_SS_IMM_OFF, RVC_SS_IMM_MASK)
		  << RVC_SS_IMM_OPOFF);
}

/*
 * Update a CIW-type instruction with an immediate value.
 *
 * @insn: pointer to the ciwtype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_ciwtype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all CIW-type IMM bits sit at 11:6 */
	*insn &= ~GENMASK(11, 6);
	*insn |= (RV_X(imm, RVC_IW_IMM_OFF, RVC_IW_IMM_MASK)
		  << RVC_IW_IMM_OPOFF);
}

/*
 * Update a CL-type instruction with an immediate value.
 *
 * @insn: pointer to the cltype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_cltype_imm(u32 *insn, u32 imm_hi,
						u32 imm_lo)
{
	/* drop the old IMMs, all CL-type IMM bits sit at 11:6 */
	*insn &= ~GENMASK(11, 6);
	*insn |= (RV_X(imm_lo, RVC_L_IMM_LO_OFF, RVC_L_IMM_LO_MASK)
		  << RVC_L_IMM_LO_OPOFF) |
		 (RV_X(imm_hi, RVC_L_IMM_HI_OFF, RVC_L_IMM_HI_MASK)
		  << RVC_L_IMM_HI_OPOFF);
}

/*
 * Update a CS-type instruction with an immediate value.
 *
 * @insn: pointer to the cstype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_cstype_imm(u32 *insn, u32 imm_hi,
						u32 imm_lo)
{
	/* drop the old IMMs, all CS-type IMM bits sit at 11:6 */
	*insn &= ~GENMASK(11, 6);
	*insn |= (RV_X(imm_lo, RVC_S_IMM_LO_OFF, RVC_S_IMM_LO_MASK)
		  << RVC_S_IMM_LO_OPOFF) |
		 (RV_X(imm_hi, RVC_S_IMM_HI_OFF, RVC_S_IMM_HI_MASK)
		  << RVC_S_IMM_HI_OPOFF);
}

/*
 * Update a RVC BEQZ/BNEZ instruction with an immediate value.
 *
 * @insn: pointer to the cbtype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_cbztype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all CB-type IMM bits sit at 12:10 and 6:2 */
	*insn &= ~(GENMASK(12, 10) | GENMASK(6, 2));
	*insn |= (RV_X(imm, RVC_BZ_IMM_SIGN_OFF, RVC_BZ_IMM_SIGN_MASK)
		  << RVC_BZ_IMM_SIGN_OPOFF) |
		 (RV_X(imm, RVC_BZ_IMM_4_3_OFF, RVC_BZ_IMM_4_3_MASK)
		  << RVC_BZ_IMM_4_3_OPOFF) |
		 (RV_X(imm, RVC_BZ_IMM_7_6_OFF, RVC_BZ_IMM_7_6_MASK)
		  << RVC_BZ_IMM_7_6_OPOFF) |
		 (RV_X(imm, RVC_BZ_IMM_2_1_OFF, RVC_BZ_IMM_2_1_MASK)
		  << RVC_BZ_IMM_2_1_OPOFF) |
		 (RV_X(imm, RVC_BZ_IMM_5_OFF, RVC_BZ_IMM_5_MASK)
		  << RVC_BZ_IMM_5_OPOFF);
}

/*
 * Update a CJ-type instruction with an immediate value.
 *
 * @insn: pointer to the cjtype instruction
 * @imm: the immediate to insert into the instruction
 */
static inline void riscv_insn_insert_cjtype_imm(u32 *insn, s32 imm)
{
	/* drop the old IMMs, all CJ-type IMM bits sit at 12:2 */
	*insn &= ~GENMASK(12, 2);
	*insn |= (RV_X(imm, RVC_J_IMM_SIGN_OFF, RVC_J_IMM_SIGN_MASK)
		  << RVC_J_IMM_SIGN_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_4_OFF, RVC_J_IMM_4_MASK)
		  << RVC_J_IMM_4_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_9_8_OFF, RVC_J_IMM_9_8_MASK)
		  << RVC_J_IMM_9_8_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_10_OFF, RVC_J_IMM_10_MASK)
		  << RVC_J_IMM_10_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_6_OFF, RVC_J_IMM_6_MASK)
		  << RVC_J_IMM_6_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_7_OFF, RVC_J_IMM_7_MASK)
		  << RVC_J_IMM_7_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_3_1_OFF, RVC_J_IMM_3_1_MASK)
		  << RVC_J_IMM_3_1_OPOFF) |
		 (RV_X(imm, RVC_J_IMM_5_OFF, RVC_J_IMM_5_MASK)
		  << RVC_J_IMM_5_OPOFF);
}

/*
 * Put together one immediate from a U-type and I-type instruction pair.
 *
 * The U-type contains an upper immediate, meaning bits[31:12] with [11:0]
 * being zero, while the I-type contains a 12bit immediate.
 * Combined these can encode larger 32bit values and are used for example
 * in auipc + jalr pairs to allow larger jumps.
 *
 * @utype_insn: instruction containing the upper immediate
 * @itype_insn: instruction
 * Return: combined immediate
 */
static inline s32 riscv_insn_extract_utype_itype_imm(u32 utype_insn,
						     u32 itype_insn)
{
	s32 imm;

	imm = RV_EXTRACT_UTYPE_IMM(utype_insn);
	imm += RV_EXTRACT_ITYPE_IMM(itype_insn);

	return imm;
}

/*
 * Update a set of two instructions (U-type + I-type) with an immediate value.
 *
 * Used for example in auipc+jalrs pairs the U-type instructions contains
 * a 20bit upper immediate representing bits[31:12], while the I-type
 * instruction contains a 12bit immediate representing bits[11:0].
 *
 * This also takes into account that both separate immediates are
 * considered as signed values, so if the I-type immediate becomes
 * negative (BIT(11) aka 0x800 set) the U-type part gets adjusted.
 *
 * @utype_insn: pointer to the utype instruction of the pair
 * @itype_insn: pointer to the itype instruction of the pair
 * @imm: the immediate to insert into the two instructions
 */
static inline void riscv_insn_insert_utype_itype_imm(u32 *utype_insn,
						     u32 *itype_insn, s32 imm)
{
	/* drop possible old IMM values */
	*utype_insn &= ~(RV_U_IMM_31_12_MASK << RV_U_IMM_31_12_OPOFF);
	*itype_insn &= ~(RV_I_IMM_11_0_MASK << RV_I_IMM_11_0_OPOFF);

	/* add the adapted IMMs */
	*utype_insn |=
		((imm + 0x800) & (RV_U_IMM_31_12_MASK << RV_U_IMM_31_12_OPOFF));
	*itype_insn |= ((imm & RV_I_IMM_11_0_MASK) << RV_I_IMM_11_0_OPOFF);
}

static inline bool rvc_enabled(void)
{
	return IS_ENABLED(CONFIG_RISCV_ISA_C);
}

/* RISC-V instruction formats. */

static inline u32 rv_r_insn(u8 funct7, u8 rs2, u8 rs1, u8 funct3, u8 rd,
			    u8 opcode)
{
	return (funct7 << RV_INSN_FUNCT7_OPOFF) | (rs2 << RV_INSN_RS2_OPOFF) |
		(rs1 << RV_INSN_RS1_OPOFF) | (funct3 << RV_INSN_FUNCT3_OPOFF) |
		(rd << RV_INSN_RD_OPOFF) | opcode;
}

static inline u32 rv_i_insn(u16 imm11_0, u8 rs1, u8 funct3, u8 rd, u8 opcode)
{
	u32 imm = 0;

	riscv_insn_insert_stype_imm(&imm, imm11_0);
	return imm | (rs1 << RV_INSN_RS1_OPOFF) |
		(funct3 << RV_INSN_FUNCT3_OPOFF) | (rd << RV_INSN_RD_OPOFF) |
		opcode;
}

static inline u32 rv_s_insn(u16 imm11_0, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u32 imm = 0;

	riscv_insn_insert_stype_imm(&imm, imm11_0);
	return imm | (rs2 << RV_INSN_RS2_OPOFF) | (rs1 << RV_INSN_RS1_OPOFF) |
		(funct3 << RV_INSN_FUNCT3_OPOFF) | opcode;
}

static inline u32 rv_b_insn(u16 imm12_1, u8 rs2, u8 rs1, u8 funct3, u8 opcode)
{
	u32 imm = 0;

	riscv_insn_insert_btype_imm(&imm, imm12_1);
	return imm | (rs2 << RV_INSN_RS2_OPOFF) | (rs1 << RV_INSN_RS1_OPOFF) |
		(funct3 << RV_INSN_FUNCT3_OPOFF) | opcode;
}

static inline u32 rv_u_insn(u32 imm31_12, u8 rd, u8 opcode)
{
	u32 imm = 0;

	riscv_insn_insert_btype_imm(&imm, imm31_12);
	return imm | (rd << RV_INSN_RD_OPOFF) | opcode;
}

static inline u32 rv_j_insn(u32 imm20_1, u8 rd, u8 opcode)
{
	u32 imm = 0;

	riscv_insn_insert_jtype_imm(&imm, imm20_1);
	return imm | (rd << RV_INSN_RD_OPOFF) | opcode;
}

static inline u32 rv_amo_insn(u8 funct5, u8 aq, u8 rl, u8 rs2, u8 rs1,
			      u8 funct3, u8 rd, u8 opcode)
{
	u8 funct7 = (funct5 << RV_INSN_FUNCT5_IN_OPOFF) |
		(aq << RV_INSN_AQ_IN_OPOFF) | (rl << RV_INSN_RL_IN_OPOFF);

	return rv_r_insn(funct7, rs2, rs1, funct3, rd, opcode);
}

/* RISC-V compressed instruction formats. */

static inline u16 rv_cr_insn(u8 funct4, u8 rd, u8 rs2, u8 op)
{
	return (funct4 << RVC_INSN_FUNCT4_OPOFF) | (rd << RVC_C2_RD_OPOFF) |
		(rs2 << RVC_C2_RS2_OPOFF) | op;
}

static inline u16 rv_ci_insn(u8 funct3, u32 imm_hi, u8 rd, u32 imm_lo, u8 op)
{
	u32 imm;

	imm = (RV_X(imm_lo, RVC_I_IMM_LO_OFF, RVC_I_IMM_LO_MASK)
			<< RVC_I_IMM_LO_OPOFF) |
		(RV_X(imm_hi, RVC_I_IMM_HI_OFF, RVC_I_IMM_HI_MASK)
			<< RVC_I_IMM_HI_OPOFF);

	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) |
		(rd << RVC_C1_RD_OPOFF) | op;
}

static inline u16 rv_css_insn(u8 funct3, u32 uimm, u8 rs2, u8 op)
{
	u32 imm;

	imm = (RV_X(uimm, RVC_SS_IMM_OFF, RVC_SS_IMM_MASK) << RVC_SS_IMM_OPOFF);
	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) |
		(rs2 << RVC_C2_RS2_OPOFF) | op;
}

static inline u16 rv_ciw_insn(u8 funct3, u32 uimm, u8 rd, u8 op)
{
	u32 imm;

	imm = (RV_X(uimm, RVC_IW_IMM_OFF, RVC_IW_IMM_MASK) << RVC_IW_IMM_OPOFF);
	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) |
		(rd << RVC_C0_RD_OPOFF) | op;
}

static inline u16 rv_cl_insn(u8 funct3, u32 imm_hi, u8 rs1, u8 rd, u32 imm_lo,
			     u8 op)
{
	u32 imm;

	imm = (RV_X(imm_lo, RVC_L_IMM_LO_OFF, RVC_L_IMM_LO_MASK)
			<< RVC_L_IMM_LO_OPOFF) |
		(RV_X(imm_hi, RVC_L_IMM_HI_OFF, RVC_L_IMM_HI_MASK)
			<< RVC_L_IMM_HI_OPOFF);
	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) |
		(rs1 << RVC_C0_RS1_OPOFF) | (rd << RVC_C0_RD_OPOFF) | op;
}

static inline u16 rv_cs_insn(u8 funct3, u32 imm_hi, u8 rs1, u32 imm_lo, u8 rs2,
			     u8 op)
{
	u32 imm;

	imm = (RV_X(imm_lo, RVC_S_IMM_LO_OFF, RVC_S_IMM_LO_MASK)
			<< RVC_S_IMM_LO_OPOFF) |
		(RV_X(imm_hi, RVC_S_IMM_HI_OFF, RVC_S_IMM_HI_MASK)
			<< RVC_S_IMM_HI_OPOFF);
	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) |
		(rs1 << RVC_C0_RS1_OPOFF) | (rs2 << RVC_C0_RS2_OPOFF) | op;
}

static inline u16 rv_ca_insn(u8 funct6, u8 rd, u8 funct2, u8 rs2, u8 op)
{
	return (funct6 << RVC_INSN_FUNCT6_OPOFF) | (rd << RVC_C1_RD_OPOFF) |
		(funct2 << RVC_INSN_FUNCT2_CA_OPOFF) |
		(rs2 << RVC_C0_RS2_OPOFF) | op;
}

static inline u16 rv_cb_insn(u8 funct3, u32 off_hi, u8 rd, u32 off_lo, u8 op)
{
	u32 imm;

	imm = (RV_X(off_lo, RVC_B_IMM_LO_OFF, RVC_B_IMM_LO_MASK)
			<< RVC_B_IMM_LO_OPOFF) |
		(RV_X(off_hi, RVC_B_IMM_HI_OFF, RVC_B_IMM_HI_MASK)
			<< RVC_B_IMM_HI_OPOFF);
	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) |
		(rd << RVC_C1_RD_OPOFF) | op;
}

static inline u16 rv_cj_insn(u8 funct3, u32 uimm, u8 op)
{
	u32 imm;

	imm = (RV_X(uimm, RVC_J_IMM_OFF, RVC_J_IMM_MASK) << RVC_J_IMM_OPOFF);
	return imm | (funct3 << RVC_INSN_FUNCT3_OPOFF) | op;
}

/* RVG instructions */
__RVG_INSN_FUNCS(lui, LUI, U)
__RVG_INSN_FUNCS(auipc, AUIPC, U)
__RVG_INSN_FUNCS(jal, JAL, J)
__RVG_INSN_FUNCS(jalr, JALR, I)
__RVG_INSN_FUNCS(beq, BEQ, B)
__RVG_INSN_FUNCS(bne, BNE, B)
__RVG_INSN_FUNCS(blt, BLT, B)
__RVG_INSN_FUNCS(bge, BGE, B)
__RVG_INSN_FUNCS(bltu, BLTU, B)
__RVG_INSN_FUNCS(bgeu, BGEU, B)
__RVG_INSN_FUNCS(lb, LB, I)
__RVG_INSN_FUNCS(lh, LH, I)
__RVG_INSN_FUNCS(lw, LW, I)
__RVG_INSN_FUNCS(lbu, LBU, I)
__RVG_INSN_FUNCS(lhu, LHU, I)
__RVG_INSN_FUNCS(sb, SB, S)
__RVG_INSN_FUNCS(sh, SH, S)
__RVG_INSN_FUNCS(sw, SW, S)
__RVG_INSN_FUNCS(addi, ADDI, I)
__RVG_INSN_FUNCS(slti, SLTI, I)
__RVG_INSN_FUNCS(sltiu, SLTIU, I)
__RVG_INSN_FUNCS(xori, XORI, I)
__RVG_INSN_FUNCS(ori, ORI, I)
__RVG_INSN_FUNCS(andi, ANDI, I)
__RVG_INSN_FUNCS(slli, SLLI, I)
__RVG_INSN_FUNCS(srli, SRLI, I)
__RVG_INSN_FUNCS(srai, SRAI, I)
__RVG_INSN_FUNCS(add, ADD, R)
__RVG_INSN_FUNCS(sub, SUB, R)
__RVG_INSN_FUNCS(sll, SLL, R)
__RVG_INSN_FUNCS(slt, SLT, R)
__RVG_INSN_FUNCS(sltu, SLTU, R)
__RVG_INSN_FUNCS(xor, XOR, R)
__RVG_INSN_FUNCS(srl, SRL, R)
__RVG_INSN_FUNCS(sra, SRA, R)
__RVG_INSN_FUNCS(or, OR, R)
__RVG_INSN_FUNCS(and, AND, R)
__RVG_INSN_FUNCS(nop, NOP, NOP)
__RVG_INSN_FUNCS(fence, FENCE, FENCE)
__RVG_INSN_FUNCS(fencetso, FENCETSO, FENCETSO)
__RVG_INSN_FUNCS(pause, PAUSE, PAUSE)
__RVG_INSN_FUNCS(ecall, ECALL, ECALL)
__RVG_INSN_FUNCS(ebreak, EBREAK, EBREAK)
/* Extra Instructions */
__RVG_INSN_FUNCS(bgtu, BLTU, REV_B)
__RVG_INSN_FUNCS(bleu, BGEU, REV_B)
__RVG_INSN_FUNCS(bgt, BLT, REV_B)
__RVG_INSN_FUNCS(ble, BGE, REV_B)
/* F Standard Extension */
__RVG_INSN_FUNCS(flw, FLW, I)
__RVG_INSN_FUNCS(fsw, FSW, S)
/* D Standard Extension */
__RVG_INSN_FUNCS(fld, FLD, I)
__RVG_INSN_FUNCS(fsd, FSD, S)
/* Q Standard Extension */
__RVG_INSN_FUNCS(flq, FLQ, I)
__RVG_INSN_FUNCS(fsq, FSQ, S)
/* Zicsr Standard Extension */
__RVG_INSN_FUNCS(csrrw, CSRRW, I)
__RVG_INSN_FUNCS(csrrs, CSRRS, I)
__RVG_INSN_FUNCS(csrrc, CSRRC, I)
__RVG_INSN_FUNCS(csrrwi, CSRRWI, I)
__RVG_INSN_FUNCS(csrrsi, CSRRSI, I)
__RVG_INSN_FUNCS(csrrci, CSRRCI, I)
/* M Standard Extension */
__RVG_INSN_FUNCS(mul, MUL, R)
__RVG_INSN_FUNCS(mulh, MULH, R)
__RVG_INSN_FUNCS(mulhsu, MULHSU, R)
__RVG_INSN_FUNCS(mulhu, MULHU, R)
__RVG_INSN_FUNCS(div, DIV, R)
__RVG_INSN_FUNCS(divu, DIVU, R)
__RVG_INSN_FUNCS(rem, REM, R)
__RVG_INSN_FUNCS(remu, REMU, R)
/* A Standard Extension */
__RVG_INSN_FUNCS(lr_w, LR_W, AMO)
__RVG_INSN_FUNCS(sc_w, SC_W, AMO)
__RVG_INSN_FUNCS(amoswap_w, AMOSWAP_W, AMO)
__RVG_INSN_FUNCS(amoadd_w, AMOADD_W, AMO)
__RVG_INSN_FUNCS(amoxor_w, AMOXOR_W, AMO)
__RVG_INSN_FUNCS(amoand_w, AMOAND_W, AMO)
__RVG_INSN_FUNCS(amoor_w, AMOOR_W, AMO)
__RVG_INSN_FUNCS(amomin_w, AMOMIN_W, AMO)
__RVG_INSN_FUNCS(amomax_w, AMOMAX_W, AMO)
__RVG_INSN_FUNCS(amominu_w, AMOMINU_W, AMO)
__RVG_INSN_FUNCS(amomaxu_w, AMOMAXU_W, AMO)

/* RVG 64-bit only instructions*/
__RVG_INSN_FUNCS(lwu, LWU, I)
__RVG_INSN_FUNCS(ld, LD, I)
__RVG_INSN_FUNCS(sd, SD, S)
__RVG_INSN_FUNCS(addiw, ADDIW, I)
__RVG_INSN_FUNCS(slliw, SLLIW, I)
__RVG_INSN_FUNCS(srliw, SRLIW, I)
__RVG_INSN_FUNCS(sraiw, SRAIW, I)
__RVG_INSN_FUNCS(addw, ADDW, R)
__RVG_INSN_FUNCS(subw, SUBW, R)
__RVG_INSN_FUNCS(sllw, SLLW, R)
__RVG_INSN_FUNCS(srlw, SRLW, R)
__RVG_INSN_FUNCS(sraw, SRAW, R)
/* M Standard Extension */
__RVG_INSN_FUNCS(divw, DIVW, R)
__RVG_INSN_FUNCS(mulw, MULW, R)
__RVG_INSN_FUNCS(divuw, DIVUW, R)
__RVG_INSN_FUNCS(remw, REMW, R)
__RVG_INSN_FUNCS(remuw, REMUW, R)
/* A Standard Extension */
__RVG_INSN_FUNCS(lr_d, LR_D, AMO)
__RVG_INSN_FUNCS(sc_d, SC_D, AMO)
__RVG_INSN_FUNCS(amoswap_d, AMOSWAP_D, AMO)
__RVG_INSN_FUNCS(amoadd_d, AMOADD_D, AMO)
__RVG_INSN_FUNCS(amoxor_d, AMOXOR_D, AMO)
__RVG_INSN_FUNCS(amoand_d, AMOAND_D, AMO)
__RVG_INSN_FUNCS(amoor_d, AMOOR_D, AMO)
__RVG_INSN_FUNCS(amomin_d, AMOMIN_D, AMO)
__RVG_INSN_FUNCS(amomax_d, AMOMAX_D, AMO)
__RVG_INSN_FUNCS(amominu_d, AMOMINU_D, AMO)
__RVG_INSN_FUNCS(amomaxu_d, AMOMAXU_D, AMO)
/* Privileged instructions */
__RISCV_INSN_FUNCS(sret, RV_MASK_SRET, RV_MATCH_SRET)

/* RVC Quadrant 0 instructions */
__RVC_INSN_FUNCS(c_addi4spn, C_ADDI4SPN, CIW, C0, DEFAULT)
__RVC_INSN_FUNCS(c_fld, C_FLD, CL, C0, DEFAULT)
__RVC_INSN_FUNCS(c_lw, C_LW, CL, C0, DEFAULT)
__RVC_INSN_FUNCS(c_fsd, C_FSD, CS, C0, DEFAULT)
__RVC_INSN_FUNCS(c_sw, C_SW, CS, C0, DEFAULT)
/* RVC Quadrant 1 instructions */
__RVC_INSN_FUNCS(c_nop, C_NOP, CNOP, C1, DEFAULT)
__RVC_INSN_FUNCS(c_addi, C_ADDI, CI, C1, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_li, C_LI, CI, C1, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_addi16sp, C_ADDI16SP, CI_SP, C1, DEFAULT)
__RVC_INSN_FUNCS(c_lui, C_LUI, CI, C1, NON_ZERO_TWO_RD)
__RVC_INSN_FUNCS(c_srli, C_SRLI, CB, C1, DEFAULT)
__RVC_INSN_FUNCS(c_srai, C_SRAI, CB, C1, DEFAULT)
__RVC_INSN_FUNCS(c_andi, C_ANDI, CB, C1, DEFAULT)
__RVC_INSN_FUNCS(c_sub, C_SUB, CA, C1, DEFAULT)
__RVC_INSN_FUNCS(c_or, C_OR, CA, C1, DEFAULT)
__RVC_INSN_FUNCS(c_and, C_AND, CA, C1, DEFAULT)
__RVC_INSN_FUNCS(c_xor, C_XOR, CA, C1, DEFAULT)
__RVC_INSN_FUNCS(c_j, C_J, CJ, C1, DEFAULT)
__RVC_INSN_FUNCS(c_beqz, C_BEQZ, CB, C1, DEFAULT)
__RVC_INSN_FUNCS(c_bnez, C_BNEZ, CB, C1, DEFAULT)
/* RVC Quadrant 2 instructions */
__RVC_INSN_FUNCS(c_slli, C_SLLI, CI, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_fldsp, C_FLDSP, CI, C2, DEFAULT)
__RVC_INSN_FUNCS(c_lwsp, C_LWSP, CI, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_jr, C_JR, CR_ZERO_RS, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_mv, C_MV, CR, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_ebreak, C_EBREAK, CEBREAK, C2, DEFAULT)
__RVC_INSN_FUNCS(c_jalr, C_JALR, CR_ZERO_RS, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_add, C_ADD, CR, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_fsdsp, C_FSDSP, CSS, C2, DEFAULT)
__RVC_INSN_FUNCS(c_swsp, C_SWSP, CSS, C2, DEFAULT)

#if __riscv_xlen == 32
/* RV32C-only instructions */
__RVC_INSN_FUNCS(c_flw, C_FLW, CL, C0, DEFAULT)
__RVC_INSN_FUNCS(c_fsw, C_FSW, CS, C0, DEFAULT)
__RVC_INSN_FUNCS(c_jal, C_JAL, CJ, C1, DEFAULT)
__RVC_INSN_FUNCS(c_flwsp, C_FLWSP, CI, C2, DEFAULT)
__RVC_INSN_FUNCS(c_fswsp, C_FSWSP, CSS, C2, DEFAULT)
#else
#define riscv_insn_is_c_flw(opcode) 0
#define riscv_insn_is_c_fsw(opcode) 0
#define riscv_insn_is_c_jal(opcode) 0
#define riscv_insn_is_c_flwsp(opcode) 0
#define riscv_insn_is_c_fswsp(opcode) 0
#endif

#if __riscv_xlen == 64
/* RV64C-only instructions */
__RVC_INSN_FUNCS(c_ld, C_LD, CL, C0, DEFAULT)
__RVC_INSN_FUNCS(c_sd, C_SD, CS, C0, DEFAULT)
__RVC_INSN_FUNCS(c_addiw, C_ADDIW, CI, C1, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_subw, C_SUBW, CA, C1, DEFAULT)
__RVC_INSN_FUNCS(c_ldsp, C_LDSP, CI, C2, NON_ZERO_RS1_RD)
__RVC_INSN_FUNCS(c_sdsp, C_SDSP, CSS, C2, DEFAULT)
#else
#define riscv_insn_is_c_ld(opcode) 0
#define riscv_insn_is_c_sd(opcode) 0
#define riscv_insn_is_c_addi(opcode) 0
#define riscv_insn_is_c_subw(opcode) 0
#define riscv_insn_is_c_ldsp(opcode) 0
#define riscv_insn_is_c_sdsp(opcode) 0
#endif

#endif /* _ASM_RISCV_INSN_H */
