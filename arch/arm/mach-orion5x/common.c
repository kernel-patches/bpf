// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/arm/mach-orion5x/common.c
 *
 * Core functions for Marvell Orion 5x SoCs
 *
 * Maintainer: Tzachi Perelstein <tzachi@marvell.com>
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/mbus.h>
#include <asm/page.h>
#include <asm/setup.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/time.h>

#include "bridge-regs.h"
#include "common.h"
#include "orion5x.h"

/*****************************************************************************
 * I/O Address Mapping
 ****************************************************************************/
static struct map_desc orion5x_io_desc[] __initdata = {
	{
		.virtual	= (unsigned long) ORION5X_REGS_VIRT_BASE,
		.pfn		= __phys_to_pfn(ORION5X_REGS_PHYS_BASE),
		.length		= ORION5X_REGS_SIZE,
		.type		= MT_DEVICE,
	}, {
		.virtual	= (unsigned long) ORION5X_PCIE_WA_VIRT_BASE,
		.pfn		= __phys_to_pfn(ORION5X_PCIE_WA_PHYS_BASE),
		.length		= ORION5X_PCIE_WA_SIZE,
		.type		= MT_DEVICE,
	},
};

void __init orion5x_map_io(void)
{
	iotable_init(orion5x_io_desc, ARRAY_SIZE(orion5x_io_desc));
}

void orion5x_setup_wins(void)
{
	/*
	 * The PCIe windows will no longer be statically allocated
	 * here once Orion5x is migrated to the pci-mvebu driver.
	 */
	mvebu_mbus_add_window_remap_by_id(ORION_MBUS_PCIE_IO_TARGET,
					  ORION_MBUS_PCIE_IO_ATTR,
					  ORION5X_PCIE_IO_PHYS_BASE,
					  ORION5X_PCIE_IO_SIZE,
					  ORION5X_PCIE_IO_BUS_BASE);
	mvebu_mbus_add_window_by_id(ORION_MBUS_PCIE_MEM_TARGET,
				    ORION_MBUS_PCIE_MEM_ATTR,
				    ORION5X_PCIE_MEM_PHYS_BASE,
				    ORION5X_PCIE_MEM_SIZE);
	mvebu_mbus_add_window_remap_by_id(ORION_MBUS_PCI_IO_TARGET,
					  ORION_MBUS_PCI_IO_ATTR,
					  ORION5X_PCI_IO_PHYS_BASE,
					  ORION5X_PCI_IO_SIZE,
					  ORION5X_PCI_IO_BUS_BASE);
	mvebu_mbus_add_window_by_id(ORION_MBUS_PCI_MEM_TARGET,
				    ORION_MBUS_PCI_MEM_ATTR,
				    ORION5X_PCI_MEM_PHYS_BASE,
				    ORION5X_PCI_MEM_SIZE);
}

/*****************************************************************************
 * General
 ****************************************************************************/
/*
 * Identify device ID and rev from PCIe configuration header space '0'.
 */
void __init orion5x_id(u32 *dev, u32 *rev, char **dev_name)
{
	orion5x_pcie_id(dev, rev);

	if (*dev == MV88F5281_DEV_ID) {
		if (*rev == MV88F5281_REV_D2) {
			*dev_name = "MV88F5281-D2";
		} else if (*rev == MV88F5281_REV_D1) {
			*dev_name = "MV88F5281-D1";
		} else if (*rev == MV88F5281_REV_D0) {
			*dev_name = "MV88F5281-D0";
		} else {
			*dev_name = "MV88F5281-Rev-Unsupported";
		}
	} else if (*dev == MV88F5182_DEV_ID) {
		if (*rev == MV88F5182_REV_A2) {
			*dev_name = "MV88F5182-A2";
		} else {
			*dev_name = "MV88F5182-Rev-Unsupported";
		}
	} else if (*dev == MV88F5181_DEV_ID) {
		if (*rev == MV88F5181_REV_B1) {
			*dev_name = "MV88F5181-Rev-B1";
		} else if (*rev == MV88F5181L_REV_A1) {
			*dev_name = "MV88F5181L-Rev-A1";
		} else {
			*dev_name = "MV88F5181(L)-Rev-Unsupported";
		}
	} else if (*dev == MV88F6183_DEV_ID) {
		if (*rev == MV88F6183_REV_B0) {
			*dev_name = "MV88F6183-Rev-B0";
		} else {
			*dev_name = "MV88F6183-Rev-Unsupported";
		}
	} else {
		*dev_name = "Device-Unknown";
	}
}

void orion5x_restart(enum reboot_mode mode, const char *cmd)
{
	/*
	 * Enable and issue soft reset
	 */
	orion5x_setbits(RSTOUTn_MASK, (1 << 2));
	orion5x_setbits(CPU_SOFT_RESET, 1);
	mdelay(200);
	orion5x_clrbits(CPU_SOFT_RESET, 1);
}

/*
 * Many orion-based systems have buggy bootloader implementations.
 * This is a common fixup for bogus memory tags.
 */
void __init tag_fixup_mem32(struct tag *t, char **from)
{
	for (; t->hdr.size; t = tag_next(t))
		if (t->hdr.tag == ATAG_MEM &&
		    (!t->u.mem.size || t->u.mem.size & ~PAGE_MASK ||
		     t->u.mem.start & ~PAGE_MASK)) {
			printk(KERN_WARNING
			       "Clearing invalid memory bank %dKB@0x%08x\n",
			       t->u.mem.size / 1024, t->u.mem.start);
			t->hdr.tag = 0;
		}
}
