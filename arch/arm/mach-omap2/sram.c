// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * OMAP SRAM detection and management
 *
 * Copyright (C) 2005 Nokia Corporation
 * Written by Tony Lindgren <tony@atomide.com>
 *
 * Copyright (C) 2009-2012 Texas Instruments
 * Added OMAP4/5 support - Santosh Shilimkar <santosh.shilimkar@ti.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/set_memory.h>

#include <asm/fncpy.h>
#include <asm/tlb.h>
#include <asm/cacheflush.h>

#include <asm/mach/map.h>

#include "soc.h"
#include "iomap.h"
#include "prm2xxx_3xxx.h"
#include "sdrc.h"
#include "sram.h"

#define OMAP3_SRAM_PUB_PA       (OMAP3_SRAM_PA + 0x8000)

#define SRAM_BOOTLOADER_SZ	0x00

#define OMAP34XX_VA_REQINFOPERM0	OMAP2_L3_IO_ADDRESS(0x68012848)
#define OMAP34XX_VA_READPERM0		OMAP2_L3_IO_ADDRESS(0x68012850)
#define OMAP34XX_VA_WRITEPERM0		OMAP2_L3_IO_ADDRESS(0x68012858)
#define OMAP34XX_VA_ADDR_MATCH2		OMAP2_L3_IO_ADDRESS(0x68012880)
#define OMAP34XX_VA_SMS_RG_ATT0		OMAP2_L3_IO_ADDRESS(0x6C000048)

#define GP_DEVICE		0x300

#define ROUND_DOWN(value, boundary)	((value) & (~((boundary) - 1)))

static unsigned long omap_sram_start;
static unsigned long omap_sram_size;
static void __iomem *omap_sram_base;
static unsigned long omap_sram_skip;
static void __iomem *omap_sram_ceil;

/*
 * Memory allocator for SRAM: calculates the new ceiling address
 * for pushing a function using the fncpy API.
 *
 * Note that fncpy requires the returned address to be aligned
 * to an 8-byte boundary.
 */
static void *omap_sram_push_address(unsigned long size)
{
	unsigned long available, new_ceil = (unsigned long)omap_sram_ceil;

	available = omap_sram_ceil - (omap_sram_base + omap_sram_skip);

	if (size > available) {
		pr_err("Not enough space in SRAM\n");
		return NULL;
	}

	new_ceil -= size;
	new_ceil = ROUND_DOWN(new_ceil, FNCPY_ALIGN);
	omap_sram_ceil = IOMEM(new_ceil);

	return (void __force *)omap_sram_ceil;
}

void *omap_sram_push(void *funcp, unsigned long size)
{
	void *sram;
	unsigned long base;
	int pages;
	void *dst = NULL;

	sram = omap_sram_push_address(size);
	if (!sram)
		return NULL;

	base = (unsigned long)sram & PAGE_MASK;
	pages = PAGE_ALIGN(size) / PAGE_SIZE;

	set_memory_rw(base, pages);

	dst = fncpy(sram, funcp, size);

	set_memory_rox(base, pages);

	return dst;
}

/*
 * The SRAM context is lost during off-idle and stack
 * needs to be reset.
 */
static void omap_sram_reset(void)
{
	omap_sram_ceil = omap_sram_base + omap_sram_size;
}

/*
 * Depending on the target RAMFS firewall setup, the public usable amount of
 * SRAM varies.  The default accessible size for all device types is 2k. A GP
 * device allows ARM11 but not other initiators for full size. This
 * functionality seems ok until some nice security API happens.
 */
static int is_sram_locked(void)
{
	if (omap_type() == OMAP2_DEVICE_TYPE_GP) {
		/* RAMFW: R/W access to all initiators for all qualifier sets */
		writel_relaxed(0xFFFF, OMAP34XX_VA_REQINFOPERM0); /* all q-vects */
		writel_relaxed(0xFFFF, OMAP34XX_VA_READPERM0);  /* all i-read */
		writel_relaxed(0xFFFF, OMAP34XX_VA_WRITEPERM0); /* all i-write */
		writel_relaxed(0x0, OMAP34XX_VA_ADDR_MATCH2);
		writel_relaxed(0xFFFFFFFF, OMAP34XX_VA_SMS_RG_ATT0);
		return 0;
	} else
		return 1; /* assume locked with no PPA or security driver */
}

/*
 * The amount of SRAM depends on the core type.
 * Note that we cannot try to test for SRAM here because writes
 * to secure SRAM will hang the system. Also the SRAM is not
 * yet mapped at this point.
 */
static void __init omap_detect_sram(void)
{
	omap_sram_skip = SRAM_BOOTLOADER_SZ;
	if (is_sram_locked()) {
		omap_sram_start = OMAP3_SRAM_PUB_PA;
		if ((omap_type() == OMAP2_DEVICE_TYPE_EMU) ||
		    (omap_type() == OMAP2_DEVICE_TYPE_SEC)) {
			omap_sram_size = 0x7000; /* 28K */
			omap_sram_skip += SZ_16K;
		} else {
			omap_sram_size = 0x8000; /* 32K */
		}
	} else {
		omap_sram_start = OMAP3_SRAM_PA;
		omap_sram_size = 0x10000; /* 64K */
	}
}

/*
 * Note that we cannot use ioremap for SRAM, as clock init needs SRAM early.
 */
static void __init omap2_map_sram(void)
{
	unsigned long base;
	int pages;

	if (omap_sram_size == 0)
		return;

	omap_sram_start = ROUND_DOWN(omap_sram_start, PAGE_SIZE);
	/*
	 * SRAM must be marked as non-cached on OMAP3 since the
	 * CORE DPLL M2 divider change code (in SRAM) runs with the
	 * SDRAM controller disabled, and if it is marked cached,
	 * the ARM may attempt to write cache lines back to SDRAM
	 * which will cause the system to hang.
	 */

	omap_sram_base = __arm_ioremap_exec(omap_sram_start, omap_sram_size, 0);
	if (!omap_sram_base) {
		pr_err("SRAM: Could not map\n");
		return;
	}

	omap_sram_reset();

	/*
	 * Looks like we need to preserve some bootloader code at the
	 * beginning of SRAM for jumping to flash for reboot to work...
	 */
	memset_io(omap_sram_base + omap_sram_skip, 0,
		  omap_sram_size - omap_sram_skip);

	base = (unsigned long)omap_sram_base;
	pages = PAGE_ALIGN(omap_sram_size) / PAGE_SIZE;

	set_memory_rox(base, pages);
}

void omap3_sram_restore_context(void)
{
	omap_sram_reset();

	omap_push_sram_idle();
}

static inline int omap34xx_sram_init(void)
{
	omap3_sram_restore_context();
	return 0;
}

int __init omap_sram_init(void)
{
	omap_detect_sram();
	omap2_map_sram();
	omap34xx_sram_init();

	return 0;
}
