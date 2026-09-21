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
 * I2C register model:
 *   - Page select register at offset 0xFF, present in every page
 *   - Each page has 256 registers (0x00-0xFF)
 *   - Some pages are paired (e.g. 0x0A/0x1A for PLLA)
 */
#define SIT9531X_PAGE_SEL		0xFF
#define SIT9531X_PAGE_SIZE		0x100
#define SIT9531X_NUM_PAGES		32

/* Helper macros for page:offset addressing */
#define SIT9531X_REG(_page, _offset)		(((_page) << 8) | (_offset))
#define SIT9531X_REG_PAGE(_reg)		((_reg) >> 8)
#define SIT9531X_REG_OFFSET(_reg)		((_reg) & 0xFF)

#define SIT9531X_PAGE_OUTSYS0		0x03
#define SIT9531X_PAGE_OUTSYS1		0x04
#define SIT9531X_PAGE_PLLA			0x0A
#define SIT9531X_PAGE_PLLA_EXT		0x1A

/*
 * VARIANT_ID is a single byte at page 0 reg 0x02 (95317 = 0x17, 95316 = 0x31).
 * Reg 0x03 carries an unrelated revision byte and must not be combined into
 * the variant identifier.
 */
#define SIT9531X_REG_VARIANT_ID		SIT9531X_REG(0x00, 0x02)

/* DCO trigger pulse timing: minimum 6 ns required by hardware */

/* Page 0 -- PLL inner loop loss-of-lock */
#define SIT9531X_REG_PLL_INNER_LOL_STATUS	SIT9531X_REG(0x00, 0x92)
#define SIT9531X_REG_PLL_INNER_LOL_NOTIF	SIT9531X_REG(0x00, 0x93)

/* Page 0 -- Clock monitor PLL / XO status */
#define SIT9531X_REG_CMON_NOTIF		SIT9531X_REG(0x00, 0x9E)

/* Page 0 -- PLL outer-loop loss-of-lock */
#define SIT9531X_REG_OUTER_LOL_STATUS	SIT9531X_REG(0x00, 0x06)
#define SIT9531X_REG_OUTER_LOL_NOTIF		SIT9531X_REG(0x00, 0x07)

/* Page 0 -- PLL holdover freeze status */
#define SIT9531X_REG_HO_FREEZE_STATUS	SIT9531X_REG(0x00, 0x0A)
#define SIT9531X_REG_HO_FREEZE_NOTIF	SIT9531X_REG(0x00, 0x0B)

/* Page 0 -- INTSYNC (inter-PLL synchronization) global enable */
#define SIT9531X_REG_INTSYNC_GLOBAL		SIT9531X_REG(0x00, 0x40)
#define SIT9531X_INTSYNC_EN_BIT		6

/*
 * Priority table: 6 registers per PLL, each holds two priority slots
 * nibble-packed.  The register holding slots 2n and 2n+1 keeps the
 * earlier slot (CLK_SPARE<2n>SEL_PLL) in [7:4] and the later one in
 * [3:0].
 *
 * Base registers for PLLA: 0x16-0x1B (slots 0-10 plus the
 * active-reference nibble).
 * For PLL N:  base + 6 * N  (e.g. PLLB starts at 0x1C).
 *
 * Input source encoding (4-bit value):
 *   0=IN0P, 1=IN1P, 2=IN2P, 3=IN3P,
 *   5=OCXO, 6=INTSYNC,
 *   7=IN0N, 8=IN1N, 9=IN2N, 10=IN3N
 *
 * Codes 4 and 11 address a fifth input pair that this part does
 * not have.  They read back as no valid reference.
 */
#define SIT9531X_PAGE_PRIOSYS		0x01
#define SIT9531X_PRIO_BASE_REG		0x16
#define SIT9531X_PRIO_REGS_PER_PLL		6
#define SIT9531X_PRIO_SLOTS_PER_REG		2
/*
 * 11 priority slots, CLK_SPARE0SEL_PLL through CLK_SPARE10SEL_PLL.
 * The twelfth nibble of the block is not a slot: it is
 * CLK_ACTIVESEL_PLL, see SIT9531X_PRIO_ACTIVESEL_OFF below.
 */
#define SIT9531X_PRIO_MAX_SLOTS		11
/* Number of source encodings (0-11), unrelated to the slot count */
#define SIT9531X_PRIO_NUM_SRC		12
#define SIT9531X_PRIO_NIBBLE_MASK		0x0F
#define SIT9531X_PRIO_HI_SHIFT		4
/* Input source encoding values (see table above) */
/*
 * Either of the two codes for the absent fifth pair works as "no source";
 * the driver writes this one when it empties a slot.
 */
#define SIT9531X_PRIO_SRC_NONE			4
#define SIT9531X_PRIO_SRC_OCXO		5
#define SIT9531X_PRIO_SRC_INTSYNC		6
#define SIT9531X_PRIO_SRC_N_BASE		7
/*
 * The last register of each PLL's priority block holds, in its low
 * nibble, the input source the PLL has currently selected as its
 * active reference (CLK_ACTIVESEL_PLL, same 4-bit encoding as above).
 */
#define SIT9531X_PRIO_ACTIVESEL_OFF		5

/*
 * Page 0 -- PRG_Directives_GENERIC_0, the main system's programming
 * directive register.  Every page carries its own copy of this
 * register at offset 0x0F with the same bit layout:
 *
 *   bit 6  proceed to loop lock / active state from the PRG_CMD state
 *   bit 4  update the NVM bank from the efuse contents
 *   bit 3  read the efuse into the volatile registers
 *   bit 2  program the efuse
 *   bit 1  small change update (SIT9531X_SMALL_UPDATE_CMD)
 *   bit 0  escape to the PRG_CMD state
 *
 * The NVM bank is a volatile shadow, so bits 4 and 1 are both fine in
 * a runtime path: bit 1 for a change made in the active state, bit 4
 * to close a PRG_CMD sequence.  Only bit 2 writes non-volatile
 * storage, and the driver never issues it.
 */
#define SIT9531X_REG_GLOBAL_UPDATE		SIT9531X_REG(0x00, 0x0F)
#define SIT9531X_SMALL_UPDATE_CMD		0x02

/* One bit per input PAIR (bit 0 = CLKIN0, ..., bit 3 = CLKIN3) */
#define SIT9531X_REG_IN_DE_FORCE		SIT9531X_REG(0x02, 0xE8)
#define SIT9531X_REG_IN_DE_STATE		SIT9531X_REG(0x02, 0xE9)
#define SIT9531X_REG_IN_SEP_FORCE		SIT9531X_REG(0x02, 0xEA)
#define SIT9531X_REG_IN_SEP_STATE		SIT9531X_REG(0x02, 0xEB)
#define SIT9531X_REG_IN_SEN_FORCE		SIT9531X_REG(0x02, 0xF2)
#define SIT9531X_REG_IN_SEN_STATE		SIT9531X_REG(0x02, 0xF3)

/*
 * One register per input pair at 0x1B + 0x10 * pair
 * (CLKIN0 = 0x1B, CLKIN1 = 0x2B, CLKIN2 = 0x3B, CLKIN3 = 0x4B).
 * SE_P_EN/SE_N_EN set means the corresponding lane is configured
 * single-ended; both clear means the pair runs differential.
 */
#define SIT9531X_REG_IN_MODE(_pair)		\
	SIT9531X_REG(0x02, 0x1B + 0x10 * (_pair))
#define SIT9531X_IN_MODE_SE_P_EN		BIT(0)
#define SIT9531X_IN_MODE_SE_N_EN		BIT(1)

/* ---- Page 0x03 (Output System) registers -- Hi-Z control ---- */
#define SIT9531X_REG_HIZ_DIFF_07_MASK	SIT9531X_REG(0x03, 0xF2)
#define SIT9531X_REG_HIZ_DIFF_07_STATE	SIT9531X_REG(0x03, 0xF3)
#define SIT9531X_REG_HIZ_DIFF_811_MASK	SIT9531X_REG(0x03, 0xF4)
#define SIT9531X_REG_HIZ_DIFF_811_STATE	SIT9531X_REG(0x03, 0xF5)
#define SIT9531X_REG_HIZ_SE_07_MASK		SIT9531X_REG(0x03, 0xF8)
#define SIT9531X_REG_HIZ_SE_07_STATE		SIT9531X_REG(0x03, 0xF9)
#define SIT9531X_REG_HIZ_SE_811_MASK		SIT9531X_REG(0x03, 0xFA)
#define SIT9531X_REG_HIZ_SE_811_STATE	SIT9531X_REG(0x03, 0xFB)

/*
 * Output driver configuration.  Either CMOS enable means the output
 * is wired single-ended -- one lane, or both driven as CMOS; with
 * neither set it is a differential pair.
 */
#define SIT9531X_OUT_MISC0_BASE		0x1E
#define SIT9531X_OUT_MISC0_STRIDE		0x10
#define SIT9531X_OUT_CMOS_ENP		BIT(3)
#define SIT9531X_OUT_CMOS_ENN		BIT(2)

/*
 * Output divider registers in Pages 3/4.  Each output has a 34-bit
 * integer divider mapped to 5 bytes (LSB at base reg, MSB at base-4).
 * Outputs 0-5 are on Page 3, outputs 6-11 are on Page 4.
 *
 * The base register for slot N within a page is:
 *   clkout_odr_divn_base[slot] = { 0x14, 0x24, 0x34, 0x44, 0x54, 0x64 }
 *
 * Layout: base=LSB, base-1, base-2, base-3, base-4[1:0]=MSB.
 *
 * Per-chip clkout_map[] translates output index to slot position.
 */
#define SIT9531X_PAGE_OUTSYS0_SLOT_MAX	5   /* slots 0-5 on Page 0x03 */

/* Misc output system registers */
#define SIT9531X_REG_PRG_DIR_GEN		SIT9531X_REG(0x03, 0x0F)
#define SIT9531X_PRG_CMD_STATE		0x01
#define SIT9531X_UPDATE_NVM			0x10
#define SIT9531X_LOOP_LOCK			0x40

/* Debug register (same offset, per-page) */
#define SIT9531X_REG_OUTSYS_DEBUG		SIT9531X_REG(0x03, 0xBD)
#define SIT9531X_DEBUG_UNLOCK_VAL		0xC3

/*
 * On-demand phase-flush fired from a register rather than a GPIO pin.
 * DIVO_PHASE_SEL_REG selects the in-register trigger source and
 * DIVO_PHASE_TRIG flushes the output phase when pulsed high then low.
 * The unrelated OEb trigger pair in bits [7:6] must be preserved.
 */
#define SIT9531X_REG_GPIO_FUNC_CTRL1	SIT9531X_REG(0x00, 0x65)
#define SIT9531X_DIVO_PHASE_SEL_REG	BIT(5)
#define SIT9531X_DIVO_PHASE_TRIG	BIT(4)

/* ---- PLL page registers (apply to pages 0x0A-0x0D) ---- */
#define SIT9531X_PLL_REG_SMALL_UPDATE	0x0F

/*
 * Loop-filter coefficients on PLL_PAGE regs 0x10-0x15 (3 normal +
 * 3 fast-lock) are GUI/NVM-generated by the timing configurator and must not be
 * reprogrammed at runtime; the register map flags them as
 * "GUI generated configuration should not change manually".
 */

#define SIT9531X_PLL_REG_OUT_MAP_HI		0x27
#define SIT9531X_PLL_REG_OUT_MAP_LO		0x28
#define SIT9531X_PLL_REG_STATUS		0x31

#define SIT9531X_PLL_REG_ACTIVE		0x02
#define SIT9531X_PLL_ACTIVE_BIT		BIT(0)  /* PLL reached active state */

#define SIT9531X_PLL_STATUS_OUTER_DIS	BIT(5)

/*
 * Per-PLL status register.  HO_VALID says the holdover window holds a
 * valid frequency estimate, i.e. holdover memory has been acquired; it is
 * not the same as HO_FREEZE (page 0, reg 0x0A), which says the PLL has
 * already switched over to holdover.
 */
#define SIT9531X_PLL_REG_STATUS_1		0x06
#define SIT9531X_PLL_STATUS_1_HO_VALID	BIT(2)

#define SIT9531X_CLKMON_P_NOTIF_01		SIT9531X_REG(0x06, 0x03)
#define SIT9531X_CLKMON_P_NOTIF_23		SIT9531X_REG(0x06, 0x07)

#define SIT9531X_CLKMON_N_NOTIF_01		SIT9531X_REG(0x06, 0x93)
#define SIT9531X_CLKMON_N_NOTIF_23		SIT9531X_REG(0x06, 0x97)

/* Per-input bit offsets within clock monitor nibble */

/*
 * EEPROM profile load, page 0.  The device compares the CRC stored in the
 * EEPROM against the one it computes from what it read; a mismatch means
 * the profile on the part is not the profile the board expects.
 * NOTIFY_4 collects the read-done bit and the defect bits, all sticky, so
 * a healthy load leaves exactly the read-done bit set.
 */
/* 4 bytes each, MSB first */
#define SIT9531X_REG_REC_CRC		SIT9531X_REG(0x00, 0x8A)
#define SIT9531X_REG_CAL_CRC		SIT9531X_REG(0x00, 0x8E)
#define SIT9531X_REG_EEPROM_NOTIF		SIT9531X_REG(0x00, 0x97)
#define SIT9531X_EEPROM_READ_DONE		BIT(0)

/* Profile identifier the loaded configuration carries, page 1, 24 bits */
/* 3 bytes, LSB first */
#define SIT9531X_REG_PROFILE_ID		SIT9531X_REG(0x01, 0x44)

/* Consecutive failed INTRB acknowledgements before the line is given up */
#define SIT9531X_IRQ_ACK_TRIES			8

/* ---- Variant ID values (one byte at SIT9531X_REG_VARIANT_ID) ---- */
#define SIT9531X_VARIANT_ID_95317	0x17
#define SIT9531X_VARIANT_ID_95316	0x31

#endif /* _SIT9531X_REGS_H */
