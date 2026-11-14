/* SPDX-License-Identifier: GPL-2.0 */
/*
 * SiTime SiT9531x register definitions
 *
 * Copyright (C) 2026 SiTime Corp.
 * Author: Ali Rouhi <arouhi@sitime.com>
 * Author: Oleg Zadorozhnyi <Oleg.Zadorozhnyi@devoxsoftware.com>
 */

#ifndef _SIT9531X_REGS_H
#define _SIT9531X_REGS_H

/*
 * The page select is at offset 0xFF in every page; some pages are paired, e.g.
 * 0x0A/0x1A for PLLA.
 */
#define SIT9531X_PAGE_SEL		0xFF
#define SIT9531X_PAGE_SIZE		0x100
#define SIT9531X_NUM_PAGES		32

#define SIT9531X_REG(_page, _offset)		(((_page) << 8) | (_offset))
#define SIT9531X_REG_PAGE(_reg)		((_reg) >> 8)
#define SIT9531X_REG_OFFSET(_reg)		((_reg) & 0xFF)

#define SIT9531X_PAGE_OUTSYS0		0x03
#define SIT9531X_PAGE_OUTSYS1		0x04
#define SIT9531X_PAGE_PLLA			0x0A
#define SIT9531X_PAGE_PLLA_EXT		0x1A

/* Reg 0x03 holds an unrelated revision byte, not part of the variant ID */
#define SIT9531X_REG_VARIANT_ID		SIT9531X_REG(0x00, 0x02)

/* PLL inner loop loss-of-lock */
#define SIT9531X_REG_PLL_INNER_LOL_STATUS	SIT9531X_REG(0x00, 0x92)
#define SIT9531X_REG_PLL_INNER_LOL_NOTIF	SIT9531X_REG(0x00, 0x93)

/* Clock monitor PLL / XO status */
#define SIT9531X_REG_CMON_NOTIF		SIT9531X_REG(0x00, 0x9E)

/* PLL outer-loop loss-of-lock */
#define SIT9531X_REG_OUTER_LOL_STATUS	SIT9531X_REG(0x00, 0x06)
#define SIT9531X_REG_OUTER_LOL_NOTIF		SIT9531X_REG(0x00, 0x07)

/* PLL holdover freeze status */
#define SIT9531X_REG_HO_FREEZE_STATUS	SIT9531X_REG(0x00, 0x0A)
#define SIT9531X_REG_HO_FREEZE_NOTIF	SIT9531X_REG(0x00, 0x0B)

/* INTSYNC (inter-PLL synchronization) global enable */
#define SIT9531X_REG_INTSYNC_GLOBAL		SIT9531X_REG(0x00, 0x40)
#define SIT9531X_INTSYNC_EN_BIT		6

/*
 * Priority table: six registers per PLL from 0x16 + 6 * PLL, holding slots
 * 0-10 and the active-reference nibble; slot 2n in [7:4], 2n+1 in [3:0].
 *
 * Source encoding (4-bit):
 *   0-3 = IN0P-IN3P, 5 = OCXO, 6 = INTSYNC, 7-10 = IN0N-IN3N
 *
 * Codes 4 and 11 take the place of a fifth input pair; they read back as no
 * valid reference.
 */
#define SIT9531X_PAGE_PRIOSYS		0x01
#define SIT9531X_PRIO_BASE_REG		0x16
#define SIT9531X_PRIO_REGS_PER_PLL		6
#define SIT9531X_PRIO_SLOTS_PER_REG		2
/*
 * CLK_SPARE0SEL_PLL..CLK_SPARE10SEL_PLL; the twelfth nibble is
 * CLK_ACTIVESEL_PLL.
 */
#define SIT9531X_PRIO_MAX_SLOTS		11
/* Number of source encodings (0-11), unrelated to the slot count */
#define SIT9531X_PRIO_NUM_SRC		12
#define SIT9531X_PRIO_NIBBLE_MASK		0x0F
#define SIT9531X_PRIO_HI_SHIFT		4
/* Codes 4 and 11 both mean no source; the driver writes 4 to empty a slot. */
#define SIT9531X_PRIO_SRC_NONE			4
#define SIT9531X_PRIO_SRC_OCXO		5
#define SIT9531X_PRIO_SRC_INTSYNC		6
#define SIT9531X_PRIO_SRC_N_BASE		7
/*
 * Low nibble of the last priority register: CLK_ACTIVESEL_PLL, the PLL's active
 * reference, in the same encoding.
 */
#define SIT9531X_PRIO_ACTIVESEL_OFF		5

/*
 * PRG_Directives_GENERIC_0; every page has a copy at offset 0x0F:
 *   bit 6  proceed from the PRG_CMD state to loop lock / active state
 *   bit 4  update the NVM bank from the efuse
 *   bit 3  read the efuse into the volatile registers
 *   bit 2  program the efuse (the driver never issues it)
 *   bit 1  small change update
 *   bit 0  escape to the PRG_CMD state
 * PRG_CMD sequences close with bit 4, as the documented sequences do.
 */
#define SIT9531X_REG_GLOBAL_UPDATE		SIT9531X_REG(0x00, 0x0F)
#define SIT9531X_SMALL_UPDATE_CMD		0x02

/* PLL holdover control (PLL page offset) */
#define SIT9531X_PLL_REG_HO_CTRL		0x6F
#define SIT9531X_PLL_HO_FORCE_BIT		4

/* One bit per input PAIR (bit 0 = CLKIN0, ..., bit 3 = CLKIN3) */
#define SIT9531X_REG_IN_DE_FORCE		SIT9531X_REG(0x02, 0xE8)
#define SIT9531X_REG_IN_DE_STATE		SIT9531X_REG(0x02, 0xE9)
#define SIT9531X_REG_IN_SEP_FORCE		SIT9531X_REG(0x02, 0xEA)
#define SIT9531X_REG_IN_SEP_STATE		SIT9531X_REG(0x02, 0xEB)
#define SIT9531X_REG_IN_SEN_FORCE		SIT9531X_REG(0x02, 0xF2)
#define SIT9531X_REG_IN_SEN_STATE		SIT9531X_REG(0x02, 0xF3)

/*
 * SE_P_EN/SE_N_EN set: that lane is single-ended; both clear: the pair is
 * differential.
 */
#define SIT9531X_REG_IN_MODE(_pair)		\
	SIT9531X_REG(0x02, 0x1B + 0x10 * (_pair))
#define SIT9531X_IN_MODE_SE_P_EN		BIT(0)
#define SIT9531X_IN_MODE_SE_N_EN		BIT(1)

#define SIT9531X_REG_HIZ_DIFF_07_MASK	SIT9531X_REG(0x03, 0xF2)
#define SIT9531X_REG_HIZ_DIFF_07_STATE	SIT9531X_REG(0x03, 0xF3)
#define SIT9531X_REG_HIZ_DIFF_811_MASK	SIT9531X_REG(0x03, 0xF4)
#define SIT9531X_REG_HIZ_DIFF_811_STATE	SIT9531X_REG(0x03, 0xF5)
#define SIT9531X_REG_HIZ_SE_07_MASK		SIT9531X_REG(0x03, 0xF8)
#define SIT9531X_REG_HIZ_SE_07_STATE		SIT9531X_REG(0x03, 0xF9)
#define SIT9531X_REG_HIZ_SE_811_MASK		SIT9531X_REG(0x03, 0xFA)
#define SIT9531X_REG_HIZ_SE_811_STATE	SIT9531X_REG(0x03, 0xFB)
/*
 * The SE pairs force the OutP pad of a CMOS output; the OutN pad uses 0xF6/0xF7
 * for slots 0-7 and 0xF4/0xF5 bits 7:4 for slots 8-11.
 */
#define SIT9531X_REG_HIZ_SEN_07_MASK	SIT9531X_REG(0x03, 0xF6)
#define SIT9531X_REG_HIZ_SEN_07_STATE	SIT9531X_REG(0x03, 0xF7)
#define SIT9531X_HIZ_SEN_811_SHIFT		4

/*
 * Either CMOS enable set: single-ended (one lane, or both as CMOS); neither:
 * differential.
 */
#define SIT9531X_OUT_MISC0_BASE		0x1E
#define SIT9531X_OUT_MISC0_STRIDE		0x10
#define SIT9531X_OUT_CMOS_ENP		BIT(3)
#define SIT9531X_OUT_CMOS_ENN		BIT(2)

/*
 * Output divider: 34 bits in 5 bytes, LSB at the slot base, MSB in base-4
 * [1:0]. Slots 0-5 on page 3, 6-11 on page 4; clkout_map[] gives the slot.
 */
#define SIT9531X_PAGE_OUTSYS0_SLOT_MAX	5   /* slots 0-5 on Page 0x03 */

#define SIT9531X_REG_PRG_DIR_GEN		SIT9531X_REG(0x03, 0x0F)
#define SIT9531X_PRG_CMD_STATE		0x01
#define SIT9531X_UPDATE_NVM			0x10
#define SIT9531X_LOOP_LOCK			0x40

/* Debug register (same offset, per-page) */
#define SIT9531X_REG_OUTSYS_DEBUG		SIT9531X_REG(0x03, 0xBD)
#define SIT9531X_DEBUG_UNLOCK_VAL		0xC3
#define SIT9531X_DEBUG_LOCK_VAL			0x00

/*
 * Per-output phase delay: 34-bit coarse in VCO cycles plus a 3-bit fine
 * field in 30 ps steps, in a five-byte block PROG6..PROG2:
 *
 *   base + 0     PROG6  [7:5] OPSTG_VCASC_BUMP (preserve)
 *                       [4:2] PRG_RST_FINE_DELAY[2:0]
 *                       [1:0] PRG_RST_DELAY[33:32]
 *   base + 1..4  PROG5..PROG2  PRG_RST_DELAY[31:0], MSB first
 *
 * Block base is 0x15 + 16 * (slot % 6), slot from clkout_map[]; slots 0-5
 * on page 3, 6-11 on page 4.
 */
#define SIT9531X_OUT_PRG_DELAY_BASE		0x15
#define SIT9531X_OUT_PRG_SLOT_STRIDE		0x10
#define SIT9531X_OUT_PRG_BYTES			5
#define SIT9531X_OUT_PRG_OPSTG_MASK		0xE0
#define SIT9531X_OUT_PRG_FINE_SHIFT		2
#define SIT9531X_OUT_PRG_FINE_MASK		0x1C	/* bits [4:2] */
#define SIT9531X_OUT_PRG_COARSE_HI_MASK		0x03	/* bits [1:0] */
/*
 * The divider takes two VCO cycles to act on a programmed delay; the encoded
 * value includes them, as in the reference flow.
 */
#define SIT9531X_OUT_PRG_DIVO_CYCLES	2

#define SIT9531X_OUT_PRG_FINE_STEP_PS		30
#define SIT9531X_OUT_PRG_FINE_MAX		7	/* 3-bit field */
#define SIT9531X_OUT_PRG_COARSE_BITS		34

/*
 * Register-triggered phase flush: DIVO_PHASE_SEL_REG selects the register
 * trigger; pulsing DIVO_PHASE_TRIG high then low flushes. Preserve the OEb
 * trigger bits [7:6].
 */
#define SIT9531X_REG_GPIO_FUNC_CTRL1	SIT9531X_REG(0x00, 0x65)
#define SIT9531X_DIVO_PHASE_SEL_REG	BIT(5)
#define SIT9531X_DIVO_PHASE_TRIG	BIT(4)

/* PLL page register offsets, pages 0x0A-0x0D */
#define SIT9531X_PLL_REG_SMALL_UPDATE	0x0F

/* On-demand phase-flush enable (PLL page reg 0x3D bit 7) */
#define SIT9531X_PLL_REG_PHFL_CTRL	0x3D
#define SIT9531X_PLL_PHFL_ON_DEMAND_EN	BIT(7)

/* Whether the PLL has the phase-flush feature (PLL page reg 0x47 bit 7) */
#define SIT9531X_PLL_REG_CONFIG47	0x47
#define SIT9531X_PLL_CONFIG47_PHFL_EN	BIT(7)

/* Directives_GENERIC_PLL: the restart bit restarts the PLL, self-clearing */
#define SIT9531X_PLL_REG_DIRECTIVES	0x05
#define SIT9531X_PLL_DIRECTIVE_RESTART	BIT(0)

/*
 * PLL page regs 0x10-0x15 hold the loop-filter coefficients (3 normal, 3
 * fast-lock); they are GUI generated and must not be changed at runtime.
 */

/*
 * Output-enable mask, twelve bits: bits 0-7 in LO, bits 8-11 in HI[3:0].
 * OUTn is bit n on PLLA and PLLB and bit 11 - n on PLLC and PLLD.
 */
#define SIT9531X_PLL_REG_OUT_MAP_HI		0x27
#define SIT9531X_PLL_REG_OUT_MAP_LO		0x28
#define SIT9531X_PLL_REG_STATUS		0x31

/* DIVN registers (free-run divider readback) */
#define SIT9531X_PLL_REG_DIVN_INT		0x30
#define SIT9531X_PLL_REG_DIVN_NUM		0x32  /* 4 bytes (0x32-0x35) */
#define SIT9531X_PLL_REG_DIVN_DEN		0x38  /* 4 bytes (0x38-0x3B) */

/*
 * Signal pathway debug readback: Dig_Sys_ReadCode selects the tap,
 * Dig_Sys_WriteCode its modifiers; a read of the debug status data register
 * latches a sample into Dig_Sys_read7..read0.
 */
#define SIT9531X_PLL_REG_DBG_READ_CODE	0xB3
#define SIT9531X_PLL_REG_DBG_WRITE_CODE	0xB4
#define SIT9531X_DBG_LOW_FREQ_CLK_BIT	BIT(7)
#define SIT9531X_PLL_REG_DBG_DATA_0		0xB5  /* [7:0] */
#define SIT9531X_PLL_REG_DBG_DATA_1		0xB6  /* [15:8] */
#define SIT9531X_PLL_REG_DBG_DATA_2		0xB7  /* [23:16] */
#define SIT9531X_PLL_REG_DBG_DATA_3		0xB8  /* [31:24] */
#define SIT9531X_PLL_REG_DBG_DATA_4		0xB9  /* [34:32] + sign */

/* Read code of the TDC phase tap, and the sign bit of its sample */
#define SIT9531X_DBG_READ_CODE_TDC		69
#define SIT9531X_TDC_SIGN_BIT		3
#define SIT9531X_TDC_MAG_HI_MASK	GENMASK(2, 0)

/* DIVN is carried as fixed point, in steps of 1e-12 of a whole divider */
#define SIT9531X_DIVN_SCALE		1000000000000ULL

#define SIT9531X_PLL_REG_ACTIVE		0x02
#define SIT9531X_PLL_ACTIVE_BIT		BIT(0)  /* PLL reached active state */

/* PLL EXT page INTSYNC configuration registers */
#define SIT9531X_PLL_EXT_PAGE(_idx)	(SIT9531X_PAGE_PLLA_EXT + (_idx))

#define SIT9531X_PLL_STATUS_OUTER_DIS	BIT(5)

/*
 * Writing the key unlocks the page's debug registers; writing zero locks them.
 */
#define SIT9531X_PLL_REG_DEBUG		0xBD
#define SIT9531X_PLL_DEBUG_UNLOCK		0xC3
#define SIT9531X_PLL_DEBUG_LOCK			0x00

/*
 * The address register selects the block the data register reports. A data read
 * returns what the previous read latched; the documented procedures read it
 * three times.
 */
#define SIT9531X_PLL_REG_DBG_STATUS_ADDR	0xD1
#define SIT9531X_PLL_REG_DBG_STATUS_DATA	0xD0
#define SIT9531X_DBG_STATUS_READS		3

/*
 * Low nibble: the source the input subsystem routes to the PLL, in the
 * priority-table encoding.
 */
#define SIT9531X_DBG_STATUS_ROUTED_SRC	0xB0
#define SIT9531X_DBG_ROUTED_SRC_MASK		GENMASK(3, 0)

/*
 * PLL_CONFIG1F_PLL bit 6: manual active select, no priority arbitration. The
 * register is GUI generated; the driver only reads it.
 */
#define SIT9531X_PLL_REG_CONFIG1F		0x1F
#define SIT9531X_PLL_CONFIG1F_MANUAL_SEL	BIT(6)

/*
 * MISCINNER_PLL bit 5: in manual active select, use the manual input select.
 * The register is GUI generated; the driver only reads it.
 */
#define SIT9531X_PLL_REG_MISCINNER		0x18
#define SIT9531X_PLL_MISCINNER_MAN_IN_SEL	BIT(5)

/*
 * GPIO_INPUT_FUNC_CTRL5..8, one per PLL: with bit 4 set the manual input is the
 * low nibble, otherwise the input-select pins. Bit 6 enables the indirect
 * choice and bit 5 picks active or spare; the driver does not decode them.
 */
#define SIT9531X_REG_MAN_IN_SEL(_pll)	SIT9531X_REG(0x00, 0xE8 + (_pll))
#define SIT9531X_MAN_IN_SEL_FROM_REG		BIT(4)
#define SIT9531X_MAN_IN_SEL_MASK		GENMASK(3, 0)

/*
 * HO_VALID: holdover memory has been acquired. HO_FREEZE (page 0, reg 0x0A)
 * means the PLL is in holdover.
 */
#define SIT9531X_PLL_REG_STATUS_1		0x06
#define SIT9531X_PLL_STATUS_1_HO_VALID	BIT(2)

/*
 * Clock monitor status, one nibble per input lane; the lower-numbered input of
 * each register is in the low nibble.
 */
#define SIT9531X_CLKMON_P_STATUS_01		SIT9531X_REG(0x06, 0x02)
#define SIT9531X_CLKMON_P_STATUS_23		SIT9531X_REG(0x06, 0x06)
#define SIT9531X_CLKMON_N_STATUS_01		SIT9531X_REG(0x06, 0x92)
#define SIT9531X_CLKMON_N_STATUS_23		SIT9531X_REG(0x06, 0x96)
#define SIT9531X_CLKMON_FINE_DRIFT		BIT(0)
#define SIT9531X_CLKMON_COARSE_DRIFT		BIT(1)
#define SIT9531X_CLKMON_LOSS			BIT(2)
#define SIT9531X_CLKMON_P_NOTIF_01		SIT9531X_REG(0x06, 0x03)
#define SIT9531X_CLKMON_P_NOTIF_23		SIT9531X_REG(0x06, 0x07)

#define SIT9531X_CLKMON_N_NOTIF_01		SIT9531X_REG(0x06, 0x93)
#define SIT9531X_CLKMON_N_NOTIF_23		SIT9531X_REG(0x06, 0x97)

/*
 * The device compares the CRC stored in the EEPROM with the one it computes.
 * NOTIFY_4 bits are sticky; a good load leaves only the read-done bit set.
 */
/* 4 bytes each, MSB first */
#define SIT9531X_REG_REC_CRC		SIT9531X_REG(0x00, 0x8A)
#define SIT9531X_REG_CAL_CRC		SIT9531X_REG(0x00, 0x8E)
#define SIT9531X_REG_EEPROM_NOTIF		SIT9531X_REG(0x00, 0x97)
#define SIT9531X_EEPROM_READ_DONE		BIT(0)

/* Profile identifier of the loaded configuration, page 1: 3 bytes, LSB first */
#define SIT9531X_REG_PROFILE_ID		SIT9531X_REG(0x01, 0x44)

/* Consecutive failed INTRB acknowledgements before the IRQ is disabled */
#define SIT9531X_IRQ_ACK_TRIES			8

#define SIT9531X_VARIANT_ID_95317	0x17
#define SIT9531X_VARIANT_ID_95316	0x31

#endif /* _SIT9531X_REGS_H */
