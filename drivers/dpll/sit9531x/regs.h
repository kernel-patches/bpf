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

#define SIT9531X_VARIANT_ID_95317	0x17
#define SIT9531X_VARIANT_ID_95316	0x31

#endif /* _SIT9531X_REGS_H */
