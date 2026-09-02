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

/* ---- Page definitions ---- */
#define SIT9531X_PAGE_MAINSYS0		0x00
#define SIT9531X_PAGE_MAINSYS1		0x01
#define SIT9531X_PAGE_INPUTSYS		0x02
#define SIT9531X_PAGE_OUTSYS0		0x03
#define SIT9531X_PAGE_OUTSYS1		0x04
#define SIT9531X_PAGE_CLKMON0		0x06
#define SIT9531X_PAGE_CLKMON1		0x07
#define SIT9531X_PAGE_PLLA			0x0A
#define SIT9531X_PAGE_PLLA_EXT		0x1A
#define SIT9531X_PAGE_PLLB			0x0B
#define SIT9531X_PAGE_PLLB_EXT		0x1B
#define SIT9531X_PAGE_PLLC			0x0C
#define SIT9531X_PAGE_PLLC_EXT		0x1C
#define SIT9531X_PAGE_PLLD			0x0D
#define SIT9531X_PAGE_PLLD_EXT		0x1D

/*
 * VARIANT_ID is a single byte at page 0 reg 0x02 (95317 = 0x17, 95316 = 0x31).
 * Reg 0x03 carries an unrelated revision byte and must not be combined into
 * the variant identifier.
 */
#define SIT9531X_REG_VARIANT_ID		SIT9531X_REG(0x00, 0x02)

/* DCO trigger pulse timing: minimum 6 ns required by hardware */

#define SIT9531X_REG_HOLDOVER_HISTORY	SIT9531X_REG(0x00, 0x58)

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
 *   0=IN0P, 1=IN1P, 2=IN2P, 3=IN3P, 4=IN4P,
 *   5=OCXO, 6=INTSYNC,
 *   7=IN0N, 8=IN1N, 9=IN2N, 10=IN3N, 11=IN4N
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
 * Per-output programmable phase delay: 34-bit coarse (in VCO clock
 * cycles) plus a 3-bit fine field with fixed 30 ps steps.  Each output
 * has a five-byte block PROG6..PROG2:
 *
 *   base + 0  PROG6  [7:5] OPSTG_VCASC_BUMP (preserve via RMW)
 *                    [4:2] PRG_RST_FINE_DELAY[2:0]
 *                    [1:0] PRG_RST_DELAY[33:32]
 *   base + 1  PROG5  [7:0] PRG_RST_DELAY[31:24]
 *   base + 2  PROG4  [7:0] PRG_RST_DELAY[23:16]
 *   base + 3  PROG3  [7:0] PRG_RST_DELAY[15:8]
 *   base + 4  PROG2  [7:0] PRG_RST_DELAY[7:0]
 *
 * Outputs 0-5 are on Page 3, outputs 6-11 on Page 4.  The block base
 * within a page is 0x15 + 16 * (out_idx % 6).
 */
#define SIT9531X_OUT_PRG_DELAY_BASE		0x15
#define SIT9531X_OUT_PRG_SLOT_STRIDE		0x10
#define SIT9531X_OUT_PRG_OPSTG_MASK		0xE0	/* bits [7:5], preserve */
#define SIT9531X_OUT_PRG_FINE_SHIFT		2
#define SIT9531X_OUT_PRG_FINE_MASK		0x1C	/* bits [4:2] */
#define SIT9531X_OUT_PRG_COARSE_HI_MASK		0x03	/* bits [1:0] */
#define SIT9531X_OUT_PRG_FINE_STEP_PS		30
#define SIT9531X_OUT_PRG_FINE_MAX		7	/* 3-bit field */
#define SIT9531X_OUT_PRG_COARSE_BITS		34

/*
 * Per-output pulse-count control byte used in SYSREF / SYNCB modes.
 * Slot N within a page sits at 0x1B + 16 * (slot % 6).  Same page
 * mapping as PRG_RST_DELAY: slots 0-5 on Page 3, slots 6-11 on Page 4.
 */
#define SIT9531X_OUT_PROG0_BASE		0x1B

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

/* On-demand phase-flush enable (PLL page reg 0x3D bit 7) */
#define SIT9531X_PLL_REG_PHFL_CTRL	0x3D
#define SIT9531X_PLL_PHFL_ON_DEMAND_EN	BIT(7)

/*
 * Loop-filter coefficients on PLL_PAGE regs 0x10-0x15 (3 normal +
 * 3 fast-lock) are GUI/NVM-generated by the timing configurator and must not be
 * reprogrammed at runtime; the register map flags them as
 * "GUI generated configuration should not change manually".
 */

#define SIT9531X_PLL_REG_OUT_MAP_HI		0x27
#define SIT9531X_PLL_REG_OUT_MAP_LO		0x28
#define SIT9531X_PLL_REG_STATUS		0x31
#define SIT9531X_PLL_REG_NVM_UPDATE		0x3F

/* DIVN registers (free-run divider readback) */
#define SIT9531X_PLL_REG_DIVN_INT		0x30
#define SIT9531X_PLL_REG_DIVN_NUM		0x32  /* 4 bytes (0x32-0x35) */
#define SIT9531X_PLL_REG_DIVN_DEN		0x38  /* 4 bytes (0x38-0x3B) */

/*
 * DIVN carried as fixed point, and the unit the DPLL ABI wants the
 * fractional frequency offset in.  Equal in value, distinct in meaning.
 */
#define SIT9531X_DIVN_SCALE		1000000000000ULL
#define SIT9531X_PPT_PER_UNIT		1000000000000ULL

#define SIT9531X_PLL_REG_ACTIVE		0x02
#define SIT9531X_PLL_ACTIVE_BIT		BIT(0)  /* PLL reached active state */
#define SIT9531X_PLL_REG_ZDB0		0x2B
#define SIT9531X_PLL_REG_ZDB1		0x1E
#define SIT9531X_PLL_ZDB_EN_BIT		BIT(4)  /* zero-delay buffer enabled */

/* PLL STATUS register bits */
#define SIT9531X_PLL_STATUS_LOCK		BIT(0)
#define SIT9531X_PLL_STATUS_OUTER_DIS	BIT(5)

/*
 * Per-PLL status register.  HO_VALID says the holdover window holds a
 * valid frequency estimate, i.e. holdover memory has been acquired; it is
 * not the same as HO_FREEZE (page 0, reg 0x0A), which says the PLL has
 * already switched over to holdover.
 */
#define SIT9531X_PLL_REG_STATUS_1		0x06
#define SIT9531X_PLL_STATUS_1_HO_VALID	BIT(2)

/* P-polarity status registers */
#define SIT9531X_CLKMON_P_STATUS_01		SIT9531X_REG(0x06, 0x02)  /* inputs 0,1 */
#define SIT9531X_CLKMON_P_NOTIF_01		SIT9531X_REG(0x06, 0x03)
#define SIT9531X_CLKMON_P_STATUS_23		SIT9531X_REG(0x06, 0x06)  /* inputs 2,3 */
#define SIT9531X_CLKMON_P_NOTIF_23		SIT9531X_REG(0x06, 0x07)

/* N-polarity status registers */
#define SIT9531X_CLKMON_N_STATUS_01		SIT9531X_REG(0x06, 0x92)  /* inputs 0,1 */
#define SIT9531X_CLKMON_N_NOTIF_01		SIT9531X_REG(0x06, 0x93)
#define SIT9531X_CLKMON_N_STATUS_23		SIT9531X_REG(0x06, 0x96)  /* inputs 2,3 */
#define SIT9531X_CLKMON_N_NOTIF_23		SIT9531X_REG(0x06, 0x97)

/* Per-input bit offsets within clock monitor nibble */
#define SIT9531X_CLKMON_FREQ_FINE		0  /* bit 0 / bit 4 */
#define SIT9531X_CLKMON_FREQ_COARSE		1  /* bit 1 / bit 5 */
#define SIT9531X_CLKMON_CLK_LOSS		2  /* bit 2 / bit 6 */
#define SIT9531X_CLKMON_CLK_LOSS_FD		3  /* bit 3 / bit 7 */

/* ---- Debug / NVM unlock registers ---- */
#define SIT9531X_REG_DBG_UNLOCK1		0x24
#define SIT9531X_REG_DBG_UNLOCK2		0x25

/*
 * EEPROM profile load, page 0.  The device compares the CRC stored in the
 * EEPROM against the one it computes from what it read; a mismatch means
 * the profile on the part is not the profile the board expects.
 * NOTIFY_4 collects the read-done bit and the defect bits, all sticky, so
 * a healthy load leaves exactly the read-done bit set.
 */
#define SIT9531X_REG_REC_CRC		SIT9531X_REG(0x00, 0x8A)  /* 4 bytes, MSB first */
#define SIT9531X_REG_CAL_CRC		SIT9531X_REG(0x00, 0x8E)  /* 4 bytes, MSB first */
#define SIT9531X_REG_EEPROM_NOTIF		SIT9531X_REG(0x00, 0x97)
#define SIT9531X_EEPROM_READ_DONE		BIT(0)

/* Profile identifier the loaded configuration carries, page 1, 24 bits */
#define SIT9531X_REG_PROFILE_ID		SIT9531X_REG(0x01, 0x44)  /* 3 bytes, LSB first */

/* ---- Variant ID values (single byte read from SIT9531X_REG_VARIANT_ID) ---- */
#define SIT9531X_VARIANT_ID_95317	0x17
#define SIT9531X_VARIANT_ID_95316	0x31

#endif /* _SIT9531X_REGS_H */
