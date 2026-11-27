// SPDX-License-Identifier: GPL-2.0-only
/*
 * arch/arm/mach-orion5x/pci.c
 *
 * PCI and PCIe functions for Marvell Orion System On Chip
 *
 * Maintainer: Tzachi Perelstein <tzachi@marvell.com>
 */

#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/mbus.h>
#include <video/vga.h>
#include <asm/irq.h>
#include "common.h"
#include "orion5x.h"

/*
 * Per-controller structure
 */
struct pci_sys_data {
	struct list_head node;
	int		busnr;		/* primary bus number			*/
	u64		mem_offset;	/* bus->cpu memory mapping offset	*/
	unsigned long	io_offset;	/* bus->cpu IO mapping offset		*/
	struct pci_bus	*bus;		/* PCI bus				*/
	struct list_head resources;	/* root bus resources (apertures)       */
	struct resource io_res;
	char		io_res_name[12];
					/* Bridge swizzling			*/
	u8		(*swizzle)(struct pci_dev *, u8 *);
					/* IRQ mapping				*/
	int		(*map_irq)(const struct pci_dev *, u8, u8);
	void		*private_data;	/* platform controller private data	*/
};

/*****************************************************************************
 * Orion has one PCIe controller and one PCI controller.
 *
 * Note1: The local PCIe bus number is '0'. The local PCI bus number
 * follows the scanned PCIe bridged busses, if any.
 *
 * Note2: It is possible for PCI/PCIe agents to access many subsystem's
 * space, by configuring BARs and Address Decode Windows, e.g. flashes on
 * device bus, Orion registers, etc. However this code only enable the
 * access to DDR banks.
 ****************************************************************************/


/*****************************************************************************
 * PCIe controller
 ****************************************************************************/

/*
 * PCIe unit register offsets.
 */
#define PCIE_DEV_ID_OFF		0x0000
#define PCIE_CMD_OFF		0x0004
#define PCIE_DEV_REV_OFF	0x0008
#define PCIE_BAR_LO_OFF(n)	(0x0010 + ((n) << 3))
#define PCIE_BAR_HI_OFF(n)	(0x0014 + ((n) << 3))
#define PCIE_HEADER_LOG_4_OFF	0x0128
#define PCIE_BAR_CTRL_OFF(n)	(0x1804 + ((n - 1) * 4))
#define PCIE_WIN04_CTRL_OFF(n)	(0x1820 + ((n) << 4))
#define PCIE_WIN04_BASE_OFF(n)	(0x1824 + ((n) << 4))
#define PCIE_WIN04_REMAP_OFF(n)	(0x182c + ((n) << 4))
#define PCIE_WIN5_CTRL_OFF	0x1880
#define PCIE_WIN5_BASE_OFF	0x1884
#define PCIE_WIN5_REMAP_OFF	0x188c
#define PCIE_CONF_ADDR_OFF	0x18f8
#define  PCIE_CONF_ADDR_EN		0x80000000
#define  PCIE_CONF_REG(r)		((((r) & 0xf00) << 16) | ((r) & 0xfc))
#define  PCIE_CONF_BUS(b)		(((b) & 0xff) << 16)
#define  PCIE_CONF_DEV(d)		(((d) & 0x1f) << 11)
#define  PCIE_CONF_FUNC(f)		(((f) & 0x7) << 8)
#define PCIE_CONF_DATA_OFF	0x18fc
#define PCIE_MASK_OFF		0x1910
#define PCIE_CTRL_OFF		0x1a00
#define  PCIE_CTRL_X1_MODE		0x0001
#define PCIE_STAT_OFF		0x1a04
#define  PCIE_STAT_DEV_OFFS		20
#define  PCIE_STAT_DEV_MASK		0x1f
#define  PCIE_STAT_BUS_OFFS		8
#define  PCIE_STAT_BUS_MASK		0xff
#define  PCIE_STAT_LINK_DOWN		1
#define PCIE_DEBUG_CTRL         0x1a60
#define  PCIE_DEBUG_SOFT_RESET		(1<<20)


static u32 orion_pcie_dev_id(void __iomem *base)
{
	return readl(base + PCIE_DEV_ID_OFF) >> 16;
}

static u32 orion_pcie_rev(void __iomem *base)
{
	return readl(base + PCIE_DEV_REV_OFF) & 0xff;
}

static int orion_pcie_link_up(void __iomem *base)
{
	return !(readl(base + PCIE_STAT_OFF) & PCIE_STAT_LINK_DOWN);
}

static void __init orion_pcie_set_local_bus_nr(void __iomem *base, int nr)
{
	u32 stat;

	stat = readl(base + PCIE_STAT_OFF);
	stat &= ~(PCIE_STAT_BUS_MASK << PCIE_STAT_BUS_OFFS);
	stat |= nr << PCIE_STAT_BUS_OFFS;
	writel(stat, base + PCIE_STAT_OFF);
}

/*
 * Setup PCIE BARs and Address Decode Wins:
 * BAR[0,2] -> disabled, BAR[1] -> covers all DRAM banks
 * WIN[0-3] -> DRAM bank[0-3]
 */
static void __init orion_pcie_setup_wins(void __iomem *base)
{
	const struct mbus_dram_target_info *dram;
	u32 size;
	int i;

	dram = mv_mbus_dram_info();

	/*
	 * First, disable and clear BARs and windows.
	 */
	for (i = 1; i <= 2; i++) {
		writel(0, base + PCIE_BAR_CTRL_OFF(i));
		writel(0, base + PCIE_BAR_LO_OFF(i));
		writel(0, base + PCIE_BAR_HI_OFF(i));
	}

	for (i = 0; i < 5; i++) {
		writel(0, base + PCIE_WIN04_CTRL_OFF(i));
		writel(0, base + PCIE_WIN04_BASE_OFF(i));
		writel(0, base + PCIE_WIN04_REMAP_OFF(i));
	}

	writel(0, base + PCIE_WIN5_CTRL_OFF);
	writel(0, base + PCIE_WIN5_BASE_OFF);
	writel(0, base + PCIE_WIN5_REMAP_OFF);

	/*
	 * Setup windows for DDR banks.  Count total DDR size on the fly.
	 */
	size = 0;
	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;

		writel(cs->base & 0xffff0000, base + PCIE_WIN04_BASE_OFF(i));
		writel(0, base + PCIE_WIN04_REMAP_OFF(i));
		writel(((cs->size - 1) & 0xffff0000) |
			(cs->mbus_attr << 8) |
			(dram->mbus_dram_target_id << 4) | 1,
				base + PCIE_WIN04_CTRL_OFF(i));

		size += cs->size;
	}

	/*
	 * Round up 'size' to the nearest power of two.
	 */
	if ((size & (size - 1)) != 0)
		size = 1 << fls(size);

	/*
	 * Setup BAR[1] to all DRAM banks.
	 */
	writel(dram->cs[0].base, base + PCIE_BAR_LO_OFF(1));
	writel(0, base + PCIE_BAR_HI_OFF(1));
	writel(((size - 1) & 0xffff0000) | 1, base + PCIE_BAR_CTRL_OFF(1));
}

static void __init orion_pcie_setup(void __iomem *base)
{
	u16 cmd;
	u32 mask;

	/*
	 * Point PCIe unit MBUS decode windows to DRAM space.
	 */
	orion_pcie_setup_wins(base);

	/*
	 * Master + slave enable.
	 */
	cmd = readw(base + PCIE_CMD_OFF);
	cmd |= PCI_COMMAND_IO;
	cmd |= PCI_COMMAND_MEMORY;
	cmd |= PCI_COMMAND_MASTER;
	writew(cmd, base + PCIE_CMD_OFF);

	/*
	 * Enable interrupt lines A-D.
	 */
	mask = readl(base + PCIE_MASK_OFF);
	mask |= 0x0f000000;
	writel(mask, base + PCIE_MASK_OFF);
}

static int orion_pcie_rd_conf(void __iomem *base, struct pci_bus *bus,
			      u32 devfn, int where, int size, u32 *val)
{
	writel(PCIE_CONF_BUS(bus->number) |
		PCIE_CONF_DEV(PCI_SLOT(devfn)) |
		PCIE_CONF_FUNC(PCI_FUNC(devfn)) |
		PCIE_CONF_REG(where) | PCIE_CONF_ADDR_EN,
			base + PCIE_CONF_ADDR_OFF);

	*val = readl(base + PCIE_CONF_DATA_OFF);

	if (size == 1)
		*val = (*val >> (8 * (where & 3))) & 0xff;
	else if (size == 2)
		*val = (*val >> (8 * (where & 3))) & 0xffff;

	return PCIBIOS_SUCCESSFUL;
}

static int orion_pcie_rd_conf_wa(void __iomem *wa_base, struct pci_bus *bus,
				 u32 devfn, int where, int size, u32 *val)
{
	*val = readl(wa_base + (PCIE_CONF_BUS(bus->number) |
				PCIE_CONF_DEV(PCI_SLOT(devfn)) |
				PCIE_CONF_FUNC(PCI_FUNC(devfn)) |
				PCIE_CONF_REG(where)));

	if (size == 1)
		*val = (*val >> (8 * (where & 3))) & 0xff;
	else if (size == 2)
		*val = (*val >> (8 * (where & 3))) & 0xffff;

	return PCIBIOS_SUCCESSFUL;
}

static int orion_pcie_wr_conf(void __iomem *base, struct pci_bus *bus,
			      u32 devfn, int where, int size, u32 val)
{
	int ret = PCIBIOS_SUCCESSFUL;

	writel(PCIE_CONF_BUS(bus->number) |
		PCIE_CONF_DEV(PCI_SLOT(devfn)) |
		PCIE_CONF_FUNC(PCI_FUNC(devfn)) |
		PCIE_CONF_REG(where) | PCIE_CONF_ADDR_EN,
			base + PCIE_CONF_ADDR_OFF);

	if (size == 4) {
		writel(val, base + PCIE_CONF_DATA_OFF);
	} else if (size == 2) {
		writew(val, base + PCIE_CONF_DATA_OFF + (where & 3));
	} else if (size == 1) {
		writeb(val, base + PCIE_CONF_DATA_OFF + (where & 3));
	} else {
		ret = PCIBIOS_BAD_REGISTER_NUMBER;
	}

	return ret;
}

#define PCIE_BASE	(ORION5X_PCIE_VIRT_BASE)

void __init orion5x_pcie_id(u32 *dev, u32 *rev)
{
	*dev = orion_pcie_dev_id(PCIE_BASE);
	*rev = orion_pcie_rev(PCIE_BASE);
}

static int pcie_valid_config(int bus, int dev)
{
	/*
	 * Don't go out when trying to access --
	 * 1. nonexisting device on local bus
	 * 2. where there's no device connected (no link)
	 */
	if (bus == 0 && dev == 0)
		return 1;

	if (!orion_pcie_link_up(PCIE_BASE))
		return 0;

	if (bus == 0 && dev != 1)
		return 0;

	return 1;
}


/*
 * PCIe config cycles are done by programming the PCIE_CONF_ADDR register
 * and then reading the PCIE_CONF_DATA register. Need to make sure these
 * transactions are atomic.
 */
static DEFINE_SPINLOCK(orion5x_pcie_lock);

static int pcie_rd_conf(struct pci_bus *bus, u32 devfn, int where,
			int size, u32 *val)
{
	unsigned long flags;
	int ret;

	if (pcie_valid_config(bus->number, PCI_SLOT(devfn)) == 0) {
		*val = 0xffffffff;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	spin_lock_irqsave(&orion5x_pcie_lock, flags);
	ret = orion_pcie_rd_conf(PCIE_BASE, bus, devfn, where, size, val);
	spin_unlock_irqrestore(&orion5x_pcie_lock, flags);

	return ret;
}

static int pcie_rd_conf_wa(struct pci_bus *bus, u32 devfn,
			   int where, int size, u32 *val)
{
	int ret;

	if (pcie_valid_config(bus->number, PCI_SLOT(devfn)) == 0) {
		*val = 0xffffffff;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	/*
	 * We only support access to the non-extended configuration
	 * space when using the WA access method (or we would have to
	 * sacrifice 256M of CPU virtual address space.)
	 */
	if (where >= 0x100) {
		*val = 0xffffffff;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	ret = orion_pcie_rd_conf_wa(ORION5X_PCIE_WA_VIRT_BASE,
				    bus, devfn, where, size, val);

	return ret;
}

static int pcie_wr_conf(struct pci_bus *bus, u32 devfn,
			int where, int size, u32 val)
{
	unsigned long flags;
	int ret;

	if (pcie_valid_config(bus->number, PCI_SLOT(devfn)) == 0)
		return PCIBIOS_DEVICE_NOT_FOUND;

	spin_lock_irqsave(&orion5x_pcie_lock, flags);
	ret = orion_pcie_wr_conf(PCIE_BASE, bus, devfn, where, size, val);
	spin_unlock_irqrestore(&orion5x_pcie_lock, flags);

	return ret;
}

static struct pci_ops pcie_ops = {
	.read = pcie_rd_conf,
	.write = pcie_wr_conf,
};


static int __init pcie_setup(struct pci_sys_data *sys)
{
	struct resource *res;
	struct resource realio;
	int dev;

	/*
	 * Generic PCIe unit setup.
	 */
	orion_pcie_setup(PCIE_BASE);

	/*
	 * Check whether to apply Orion-1/Orion-NAS PCIe config
	 * read transaction workaround.
	 */
	dev = orion_pcie_dev_id(PCIE_BASE);
	if (dev == MV88F5181_DEV_ID || dev == MV88F5182_DEV_ID) {
		printk(KERN_NOTICE "Applying Orion-1/Orion-NAS PCIe config "
				   "read transaction workaround\n");
		mvebu_mbus_add_window_by_id(ORION_MBUS_PCIE_WA_TARGET,
					    ORION_MBUS_PCIE_WA_ATTR,
					    ORION5X_PCIE_WA_PHYS_BASE,
					    ORION5X_PCIE_WA_SIZE);
		pcie_ops.read = pcie_rd_conf_wa;
	}

	realio.start = sys->busnr * SZ_64K;
	realio.end = realio.start + SZ_64K - 1;
	pci_remap_iospace(&realio, ORION5X_PCIE_IO_PHYS_BASE);

	/*
	 * Request resources.
	 */
	res = kzalloc_obj(struct resource);
	if (!res)
		panic("pcie_setup unable to alloc resources");

	/*
	 * IORESOURCE_MEM
	 */
	res->name = "PCIe Memory Space";
	res->flags = IORESOURCE_MEM;
	res->start = ORION5X_PCIE_MEM_PHYS_BASE;
	res->end = res->start + ORION5X_PCIE_MEM_SIZE - 1;
	if (request_resource(&iomem_resource, res))
		panic("Request PCIe Memory resource failed\n");
	pci_add_resource_offset(&sys->resources, res, sys->mem_offset);

	return 1;
}

/*****************************************************************************
 * PCI controller
 ****************************************************************************/
#define ORION5X_PCI_REG(x)	(ORION5X_PCI_VIRT_BASE + (x))
#define PCI_MODE		ORION5X_PCI_REG(0xd00)
#define PCI_CMD			ORION5X_PCI_REG(0xc00)
#define PCI_P2P_CONF		ORION5X_PCI_REG(0x1d14)
#define PCI_CONF_ADDR		ORION5X_PCI_REG(0xc78)
#define PCI_CONF_DATA		ORION5X_PCI_REG(0xc7c)

/*
 * PCI_MODE bits
 */
#define PCI_MODE_64BIT			(1 << 2)
#define PCI_MODE_PCIX			((1 << 4) | (1 << 5))

/*
 * PCI_CMD bits
 */
#define PCI_CMD_HOST_REORDER		(1 << 29)

/*
 * PCI_P2P_CONF bits
 */
#define PCI_P2P_BUS_OFFS		16
#define PCI_P2P_BUS_MASK		(0xff << PCI_P2P_BUS_OFFS)
#define PCI_P2P_DEV_OFFS		24
#define PCI_P2P_DEV_MASK		(0x1f << PCI_P2P_DEV_OFFS)

/*
 * PCI_CONF_ADDR bits
 */
#define PCI_CONF_REG(reg)		((reg) & 0xfc)
#define PCI_CONF_FUNC(func)		(((func) & 0x3) << 8)
#define PCI_CONF_DEV(dev)		(((dev) & 0x1f) << 11)
#define PCI_CONF_BUS(bus)		(((bus) & 0xff) << 16)
#define PCI_CONF_ADDR_EN		(1 << 31)

/*
 * Internal configuration space
 */
#define PCI_CONF_FUNC_STAT_CMD		0
#define PCI_CONF_REG_STAT_CMD		4
#define PCIX_STAT			0x64
#define PCIX_STAT_BUS_OFFS		8
#define PCIX_STAT_BUS_MASK		(0xff << PCIX_STAT_BUS_OFFS)

/*
 * PCI Address Decode Windows registers
 */
#define PCI_BAR_SIZE_DDR_CS(n)	(((n) == 0) ? ORION5X_PCI_REG(0xc08) : \
				 ((n) == 1) ? ORION5X_PCI_REG(0xd08) : \
				 ((n) == 2) ? ORION5X_PCI_REG(0xc0c) : \
				 ((n) == 3) ? ORION5X_PCI_REG(0xd0c) : NULL)
#define PCI_BAR_REMAP_DDR_CS(n)	(((n) == 0) ? ORION5X_PCI_REG(0xc48) : \
				 ((n) == 1) ? ORION5X_PCI_REG(0xd48) : \
				 ((n) == 2) ? ORION5X_PCI_REG(0xc4c) : \
				 ((n) == 3) ? ORION5X_PCI_REG(0xd4c) : NULL)
#define PCI_BAR_ENABLE		ORION5X_PCI_REG(0xc3c)
#define PCI_ADDR_DECODE_CTRL	ORION5X_PCI_REG(0xd3c)

/*
 * PCI configuration helpers for BAR settings
 */
#define PCI_CONF_FUNC_BAR_CS(n)		((n) >> 1)
#define PCI_CONF_REG_BAR_LO_CS(n)	(((n) & 1) ? 0x18 : 0x10)
#define PCI_CONF_REG_BAR_HI_CS(n)	(((n) & 1) ? 0x1c : 0x14)

/*
 * PCI config cycles are done by programming the PCI_CONF_ADDR register
 * and then reading the PCI_CONF_DATA register. Need to make sure these
 * transactions are atomic.
 */
static DEFINE_SPINLOCK(orion5x_pci_lock);

static int orion5x_pci_cardbus_mode;

static int orion5x_pci_local_bus_nr(void)
{
	u32 conf = readl(PCI_P2P_CONF);
	return((conf & PCI_P2P_BUS_MASK) >> PCI_P2P_BUS_OFFS);
}

static int orion5x_pci_hw_rd_conf(int bus, int dev, u32 func,
					u32 where, u32 size, u32 *val)
{
	unsigned long flags;
	spin_lock_irqsave(&orion5x_pci_lock, flags);

	writel(PCI_CONF_BUS(bus) |
		PCI_CONF_DEV(dev) | PCI_CONF_REG(where) |
		PCI_CONF_FUNC(func) | PCI_CONF_ADDR_EN, PCI_CONF_ADDR);

	*val = readl(PCI_CONF_DATA);

	if (size == 1)
		*val = (*val >> (8*(where & 0x3))) & 0xff;
	else if (size == 2)
		*val = (*val >> (8*(where & 0x3))) & 0xffff;

	spin_unlock_irqrestore(&orion5x_pci_lock, flags);

	return PCIBIOS_SUCCESSFUL;
}

static int orion5x_pci_hw_wr_conf(int bus, int dev, u32 func,
					u32 where, u32 size, u32 val)
{
	unsigned long flags;
	int ret = PCIBIOS_SUCCESSFUL;

	spin_lock_irqsave(&orion5x_pci_lock, flags);

	writel(PCI_CONF_BUS(bus) |
		PCI_CONF_DEV(dev) | PCI_CONF_REG(where) |
		PCI_CONF_FUNC(func) | PCI_CONF_ADDR_EN, PCI_CONF_ADDR);

	if (size == 4) {
		__raw_writel(val, PCI_CONF_DATA);
	} else if (size == 2) {
		__raw_writew(val, PCI_CONF_DATA + (where & 0x3));
	} else if (size == 1) {
		__raw_writeb(val, PCI_CONF_DATA + (where & 0x3));
	} else {
		ret = PCIBIOS_BAD_REGISTER_NUMBER;
	}

	spin_unlock_irqrestore(&orion5x_pci_lock, flags);

	return ret;
}

static int orion5x_pci_valid_config(int bus, u32 devfn)
{
	if (bus == orion5x_pci_local_bus_nr()) {
		/*
		 * Don't go out for local device
		 */
		if (PCI_SLOT(devfn) == 0 && PCI_FUNC(devfn) != 0)
			return 0;

		/*
		 * When the PCI signals are directly connected to a
		 * Cardbus slot, ignore all but device IDs 0 and 1.
		 */
		if (orion5x_pci_cardbus_mode && PCI_SLOT(devfn) > 1)
			return 0;
	}

	return 1;
}

static int orion5x_pci_rd_conf(struct pci_bus *bus, u32 devfn,
				int where, int size, u32 *val)
{
	if (!orion5x_pci_valid_config(bus->number, devfn)) {
		*val = 0xffffffff;
		return PCIBIOS_DEVICE_NOT_FOUND;
	}

	return orion5x_pci_hw_rd_conf(bus->number, PCI_SLOT(devfn),
					PCI_FUNC(devfn), where, size, val);
}

static int orion5x_pci_wr_conf(struct pci_bus *bus, u32 devfn,
				int where, int size, u32 val)
{
	if (!orion5x_pci_valid_config(bus->number, devfn))
		return PCIBIOS_DEVICE_NOT_FOUND;

	return orion5x_pci_hw_wr_conf(bus->number, PCI_SLOT(devfn),
					PCI_FUNC(devfn), where, size, val);
}

static struct pci_ops pci_ops = {
	.read = orion5x_pci_rd_conf,
	.write = orion5x_pci_wr_conf,
};

static void __init orion5x_pci_set_bus_nr(int nr)
{
	u32 p2p = readl(PCI_P2P_CONF);

	if (readl(PCI_MODE) & PCI_MODE_PCIX) {
		/*
		 * PCI-X mode
		 */
		u32 pcix_status, bus, dev;
		bus = (p2p & PCI_P2P_BUS_MASK) >> PCI_P2P_BUS_OFFS;
		dev = (p2p & PCI_P2P_DEV_MASK) >> PCI_P2P_DEV_OFFS;
		orion5x_pci_hw_rd_conf(bus, dev, 0, PCIX_STAT, 4, &pcix_status);
		pcix_status &= ~PCIX_STAT_BUS_MASK;
		pcix_status |= (nr << PCIX_STAT_BUS_OFFS);
		orion5x_pci_hw_wr_conf(bus, dev, 0, PCIX_STAT, 4, pcix_status);
	} else {
		/*
		 * PCI Conventional mode
		 */
		p2p &= ~PCI_P2P_BUS_MASK;
		p2p |= (nr << PCI_P2P_BUS_OFFS);
		writel(p2p, PCI_P2P_CONF);
	}
}

static void __init orion5x_pci_master_slave_enable(void)
{
	int bus_nr, func, reg;
	u32 val;

	bus_nr = orion5x_pci_local_bus_nr();
	func = PCI_CONF_FUNC_STAT_CMD;
	reg = PCI_CONF_REG_STAT_CMD;
	orion5x_pci_hw_rd_conf(bus_nr, 0, func, reg, 4, &val);
	val |= (PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	orion5x_pci_hw_wr_conf(bus_nr, 0, func, reg, 4, val | 0x7);
}

static void __init orion5x_setup_pci_wins(void)
{
	const struct mbus_dram_target_info *dram = mv_mbus_dram_info();
	u32 win_enable;
	int bus;
	int i;

	/*
	 * First, disable windows.
	 */
	win_enable = 0xffffffff;
	writel(win_enable, PCI_BAR_ENABLE);

	/*
	 * Setup windows for DDR banks.
	 */
	bus = orion5x_pci_local_bus_nr();

	for (i = 0; i < dram->num_cs; i++) {
		const struct mbus_dram_window *cs = dram->cs + i;
		u32 func = PCI_CONF_FUNC_BAR_CS(cs->cs_index);
		u32 reg;
		u32 val;

		/*
		 * Write DRAM bank base address register.
		 */
		reg = PCI_CONF_REG_BAR_LO_CS(cs->cs_index);
		orion5x_pci_hw_rd_conf(bus, 0, func, reg, 4, &val);
		val = (cs->base & 0xfffff000) | (val & 0xfff);
		orion5x_pci_hw_wr_conf(bus, 0, func, reg, 4, val);

		/*
		 * Write DRAM bank size register.
		 */
		reg = PCI_CONF_REG_BAR_HI_CS(cs->cs_index);
		orion5x_pci_hw_wr_conf(bus, 0, func, reg, 4, 0);
		writel((cs->size - 1) & 0xfffff000,
			PCI_BAR_SIZE_DDR_CS(cs->cs_index));
		writel(cs->base & 0xfffff000,
			PCI_BAR_REMAP_DDR_CS(cs->cs_index));

		/*
		 * Enable decode window for this chip select.
		 */
		win_enable &= ~(1 << cs->cs_index);
	}

	/*
	 * Re-enable decode windows.
	 */
	writel(win_enable, PCI_BAR_ENABLE);

	/*
	 * Disable automatic update of address remapping when writing to BARs.
	 */
	orion5x_setbits(PCI_ADDR_DECODE_CTRL, 1);
}

static int __init pci_setup(struct pci_sys_data *sys)
{
	struct resource *res;
	struct resource realio;

	/*
	 * Point PCI unit MBUS decode windows to DRAM space.
	 */
	orion5x_setup_pci_wins();

	/*
	 * Master + Slave enable
	 */
	orion5x_pci_master_slave_enable();

	/*
	 * Force ordering
	 */
	orion5x_setbits(PCI_CMD, PCI_CMD_HOST_REORDER);

	realio.start = sys->busnr * SZ_64K;
	realio.end = realio.start + SZ_64K - 1;
	pci_remap_iospace(&realio, ORION5X_PCI_IO_PHYS_BASE);

	/*
	 * Request resources
	 */
	res = kzalloc_obj(struct resource);
	if (!res)
		panic("pci_setup unable to alloc resources");

	/*
	 * IORESOURCE_MEM
	 */
	res->name = "PCI Memory Space";
	res->flags = IORESOURCE_MEM;
	res->start = ORION5X_PCI_MEM_PHYS_BASE;
	res->end = res->start + ORION5X_PCI_MEM_SIZE - 1;
	if (request_resource(&iomem_resource, res))
		panic("Request PCI Memory resource failed\n");
	pci_add_resource_offset(&sys->resources, res, sys->mem_offset);

	return 1;
}


/*****************************************************************************
 * General PCIe + PCI
 ****************************************************************************/

/*
 * The root complex has a hardwired class of PCI_CLASS_MEMORY_OTHER, when it
 * is operating as a root complex this needs to be switched to
 * PCI_CLASS_BRIDGE_HOST or Linux will errantly try to process the BAR's on
 * the device. Decoding setup is handled by the orion code.
 */
static void rc_pci_fixup(struct pci_dev *dev)
{
	if (dev->bus->parent == NULL && dev->devfn == 0) {
		struct resource *r;

		dev->class &= 0xff;
		dev->class |= PCI_CLASS_BRIDGE_HOST << 8;
		pci_dev_for_each_resource(dev, r) {
			r->start	= 0;
			r->end		= 0;
			r->flags	= 0;
		}
	}
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MARVELL, PCI_ANY_ID, rc_pci_fixup);

static int orion5x_pci_disabled __initdata;

void __init orion5x_pci_disable(void)
{
	orion5x_pci_disabled = 1;
}

void __init orion5x_pci_set_cardbus_mode(void)
{
	orion5x_pci_cardbus_mode = 1;
}

int __init orion5x_pci_sys_setup(int nr, struct pci_sys_data *sys)
{
	vga_base = ORION5X_PCIE_MEM_PHYS_BASE;

	if (nr == 0) {
		orion_pcie_set_local_bus_nr(PCIE_BASE, sys->busnr);
		return pcie_setup(sys);
	}

	if (nr == 1 && !orion5x_pci_disabled) {
		orion5x_pci_set_bus_nr(sys->busnr);
		return pci_setup(sys);
	}

	return 0;
}

int __init orion5x_pci_sys_scan_bus(int nr, struct pci_host_bridge *bridge)
{
	struct pci_sys_data *sys = pci_host_bridge_priv(bridge);

	list_splice_init(&sys->resources, &bridge->windows);
	bridge->dev.parent = NULL;
	bridge->sysdata = sys;
	bridge->busnr = sys->busnr;

	if (nr == 0) {
		bridge->ops = &pcie_ops;
		return pci_scan_root_bus_bridge(bridge);
	}

	if (nr == 1 && !orion5x_pci_disabled) {
		bridge->ops = &pci_ops;
		return pci_scan_root_bus_bridge(bridge);
	}

	BUG();
	return -ENODEV;
}

int __init orion5x_pci_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	int bus = dev->bus->number;

	/*
	 * PCIe endpoint?
	 */
	if (orion5x_pci_disabled || bus < orion5x_pci_local_bus_nr())
		return IRQ_ORION5X_PCIE0_INT;

	return -1;
}

static int debug_pci;

char * __init pcibios_setup(char *str)
{
	if (!strcmp(str, "debug")) {
		debug_pci = 1;
		return NULL;
	}
	return str;
}

/*
 * Swizzle the device pin each time we cross a bridge.  If a platform does
 * not provide a swizzle function, we perform the standard PCI swizzling.
 *
 * The default swizzling walks up the bus tree one level at a time, applying
 * the standard swizzle function at each step, stopping when it finds the PCI
 * root bus.  This will return the slot number of the bridge device on the
 * root bus and the interrupt pin on that device which should correspond
 * with the downstream device interrupt.
 *
 * Platforms may override this, in which case the slot and pin returned
 * depend entirely on the platform code.  However, please note that the
 * PCI standard swizzle is implemented on plug-in cards and Cardbus based
 * PCI extenders, so it can not be ignored.
 */
static u8 pcibios_swizzle(struct pci_dev *dev, u8 *pin)
{
	struct pci_sys_data *sys = dev->sysdata;
	int slot, oldpin = *pin;

	if (sys->swizzle)
		slot = sys->swizzle(dev, pin);
	else
		slot = pci_common_swizzle(dev, pin);

	if (debug_pci)
		printk("PCI: %s swizzling pin %d => pin %d slot %d\n",
			pci_name(dev), oldpin, *pin, slot);

	return slot;
}

/*
 * Map a slot/pin to an IRQ.
 */
static int pcibios_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct pci_sys_data *sys = dev->sysdata;
	int irq = -1;

	if (sys->map_irq)
		irq = sys->map_irq(dev, slot, pin);

	if (debug_pci)
		printk("PCI: %s mapping slot %d pin %d => irq %d\n",
			pci_name(dev), slot, pin, irq);

	return irq;
}

static int pcibios_init_resource(int busnr, struct pci_sys_data *sys)
{
	int ret;
	struct resource_entry *window;

	if (list_empty(&sys->resources)) {
		pci_add_resource_offset(&sys->resources,
			 &iomem_resource, sys->mem_offset);
	}

	resource_list_for_each_entry(window, &sys->resources)
		if (resource_type(window->res) == IORESOURCE_IO)
			return 0;

	sys->io_res.start = (busnr * SZ_64K) ?  : pcibios_min_io;
	sys->io_res.end = (busnr + 1) * SZ_64K - 1;
	sys->io_res.flags = IORESOURCE_IO;
	sys->io_res.name = sys->io_res_name;
	sprintf(sys->io_res_name, "PCI%d I/O", busnr);

	ret = request_resource(&ioport_resource, &sys->io_res);
	if (ret) {
		pr_err("PCI: unable to allocate I/O port region (%d)\n", ret);
		return ret;
	}
	pci_add_resource_offset(&sys->resources, &sys->io_res,
				sys->io_offset);

	return 0;
}

static void pcibios_init_hw(struct device *parent, struct hw_pci *hw,
			    struct list_head *head)
{
	struct pci_sys_data *sys = NULL;
	int ret;
	int nr, busnr;

	for (nr = busnr = 0; nr < hw->nr_controllers; nr++) {
		struct pci_host_bridge *bridge;

		bridge = pci_alloc_host_bridge(sizeof(struct pci_sys_data));
		if (WARN(!bridge, "PCI: unable to allocate bridge!"))
			break;

		sys = pci_host_bridge_priv(bridge);

		sys->busnr   = busnr;
		sys->swizzle = hw->swizzle;
		sys->map_irq = hw->map_irq;
		INIT_LIST_HEAD(&sys->resources);

		if (hw->private_data)
			sys->private_data = hw->private_data[nr];

		ret = hw->setup(nr, sys);

		if (ret > 0) {

			ret = pcibios_init_resource(nr, sys);
			if (ret)  {
				pci_free_host_bridge(bridge);
				break;
			}

			bridge->map_irq = pcibios_map_irq;
			bridge->swizzle_irq = pcibios_swizzle;

			if (hw->scan)
				ret = hw->scan(nr, bridge);
			else {
				list_splice_init(&sys->resources,
						 &bridge->windows);
				bridge->dev.parent = parent;
				bridge->sysdata = sys;
				bridge->busnr = sys->busnr;
				bridge->ops = hw->ops;

				ret = pci_scan_root_bus_bridge(bridge);
			}

			if (WARN(ret < 0, "PCI: unable to scan bus!")) {
				pci_free_host_bridge(bridge);
				break;
			}

			sys->bus = bridge->bus;

			busnr = sys->bus->busn_res.end + 1;

			list_add(&sys->node, head);
		} else {
			pci_free_host_bridge(bridge);
			if (ret < 0)
				break;
		}
	}
}

void pci_common_init(struct hw_pci *hw)
{
	struct pci_sys_data *sys;
	LIST_HEAD(head);

	pci_add_flags(PCI_REASSIGN_ALL_BUS);
	if (hw->preinit)
		hw->preinit();
	pcibios_init_hw(NULL, hw, &head);
	if (hw->postinit)
		hw->postinit();

	list_for_each_entry(sys, &head, node) {
		struct pci_bus *bus = sys->bus;

		/*
		 * We insert PCI resources into the iomem_resource and
		 * ioport_resource trees in either pci_bus_claim_resources()
		 * or pci_bus_assign_resources().
		 */
		if (pci_has_flag(PCI_PROBE_ONLY)) {
			pci_bus_claim_resources(bus);
		} else {
			struct pci_bus *child;

			pci_bus_size_bridges(bus);
			pci_bus_assign_resources(bus);

			list_for_each_entry(child, &bus->children, node)
				pcie_bus_configure_settings(child);
		}

		pci_bus_add_devices(bus);
	}
}
