// SPDX-License-Identifier: GPL-2.0-only
/*
 *  Atheros AR71xx/AR724x/AR913x specific interrupt handling
 *
 *  Copyright (C) 2015 Alban Bedel <albeu@free.fr>
 *  Copyright (C) 2010-2011 Jaiganesh Narayanan <jnarayanan@atheros.com>
 *  Copyright (C) 2008-2011 Gabor Juhos <juhosg@openwrt.org>
 *  Copyright (C) 2008 Imre Kaloz <kaloz@openwrt.org>
 *
 *  Parts of this file are based on Atheros' 2.6.15/2.6.31 BSP
 */

#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/of.h>

#include <asm/irq_cpu.h>
#include <asm/mach-ath79/ath79.h>

/*
 * The MIPS core has 8 interrupt lines: IP0/IP1 are software interrupts,
 * IP7 is the CP0 timer, and IP2-IP6 are wired by the SoC to its devices.
 * The wiring is fixed in hardware. Several devices can share a line, like
 * the WMAC and the PCIe root complex on IP2 of AR934x, and their drivers
 * then request the interrupt with IRQF_SHARED.
 *
 * Each DMA master writes to DDR through its own write buffer in the DDR
 * controller, and each write buffer has its own flush register. When a
 * device raises its interrupt, its last DMA writes may still sit in its
 * write buffer, so the handler could read stale descriptors or data.
 *
 * The CPU interrupt says nothing about which device on a shared line
 * raised it. So before running the handlers of a line, flush the write
 * buffers of every device wired to it. Each handler then sees its
 * device's data, checks its own status, and returns IRQ_NONE if it was
 * not the source.
 *
 * irq_wb_chans maps each CPU interrupt line to the mask of the write
 * buffer channels to flush, from the qca,ddr-wb-channel-interrupts and
 * qca,ddr-wb-channels properties.
 */
static u32 irq_wb_chans[8];

asmlinkage void plat_irq_dispatch(void)
{
	unsigned long pending, chans;
	int irq, chan;

	pending = read_c0_status() & read_c0_cause() & ST0_IM;

	if (!pending) {
		spurious_interrupt();
		return;
	}

	pending >>= CAUSEB_IP;
	while (pending) {
		irq = fls(pending) - 1;
		if (irq < ARRAY_SIZE(irq_wb_chans)) {
			chans = irq_wb_chans[irq];
			for_each_set_bit(chan, &chans, 32)
				ath79_ddr_wb_flush(chan);
		}
		do_IRQ(MIPS_CPU_IRQ_BASE + irq);
		pending &= ~BIT(irq);
	}
}

static int __init ar79_cpu_intc_of_init(
	struct device_node *node, struct device_node *parent)
{
	int err, i, count;

	/* Fill the irq_wb_chans table */
	count = of_count_phandle_with_args(
		node, "qca,ddr-wb-channels", "#qca,ddr-wb-channel-cells");

	for (i = 0; i < count; i++) {
		struct of_phandle_args args;
		u32 irq = i;

		of_property_read_u32_index(
			node, "qca,ddr-wb-channel-interrupts", i, &irq);
		if (irq >= ARRAY_SIZE(irq_wb_chans))
			continue;

		err = of_parse_phandle_with_args(
			node, "qca,ddr-wb-channels",
			"#qca,ddr-wb-channel-cells",
			i, &args);
		if (err)
			return err;

		if (args.args[0] >= 32)
			return -EINVAL;

		irq_wb_chans[irq] |= BIT(args.args[0]);
	}

	return mips_cpu_irq_of_init(node, parent);
}
IRQCHIP_DECLARE(ar79_cpu_intc, "qca,ar7100-cpu-intc",
		ar79_cpu_intc_of_init);
