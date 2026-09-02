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

/* PLL index to page mapping */
#define SIT9531X_PLL_PAGE(_idx) \
	(SIT9531X_PAGE_PLLA + (_idx))

/*
 * VARIANT_ID is a single byte at page 0 reg 0x02 (95317 = 0x17, 95316 = 0x31).
 * Reg 0x03 carries an unrelated revision byte and must not be combined into
 * the variant identifier.
 */
#define SIT9531X_REG_VARIANT_ID		SIT9531X_REG(0x00, 0x02)

/* Variant ID values (page 0 reg 0x02) */
#define SIT9531X_VARIANT_ID_95317	0x17
#define SIT9531X_VARIANT_ID_95316	0x31

#endif /* _SIT9531X_REGS_H */
