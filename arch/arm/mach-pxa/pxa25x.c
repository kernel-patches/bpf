// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/arch/arm/mach-pxa/pxa25x.c
 *
 *  Author:	Nicolas Pitre
 *  Created:	Jun 15, 2001
 *  Copyright:	MontaVista Software Inc.
 *
 * Code specific to PXA21x/25x/26x variants.
 *
 * Since this file should be linked before any other machine specific file,
 * the __initcall() here will be executed first.  This serves as default
 * initialization stuff for PXA machines which can be overridden later if
 * need be.
 */
#include <linux/dmaengine.h>
#include <linux/dma/pxa-dma.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio-pxa.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/suspend.h>
#include <linux/syscore_ops.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/soc/pxa/cpu.h>
#include <linux/soc/pxa/smemc.h>

#include <asm/mach/map.h>
#include <asm/suspend.h>
#include "irqs.h"
#include "pxa25x.h"
#include "reset.h"
#include "pm.h"
#include "addr-map.h"
#include "smemc.h"

#include "generic.h"

/*
 * Various clock factors driven by the CCCR register.
 */

#ifdef CONFIG_PM

#define SAVE(x)		sleep_save[SLEEP_SAVE_##x] = x
#define RESTORE(x)	x = sleep_save[SLEEP_SAVE_##x]

/*
 * List of global PXA peripheral registers to preserve.
 * More ones like CP and general purpose register values are preserved
 * with the stack pointer in sleep.S.
 */
enum {
	SLEEP_SAVE_PSTR,
	SLEEP_SAVE_COUNT
};


static void pxa25x_cpu_pm_save(unsigned long *sleep_save)
{
	SAVE(PSTR);
}

static void pxa25x_cpu_pm_restore(unsigned long *sleep_save)
{
	RESTORE(PSTR);
}

static void pxa25x_cpu_pm_enter(suspend_state_t state)
{
	/* Clear reset status */
	RCSR = RCSR_HWR | RCSR_WDR | RCSR_SMR | RCSR_GPR;

	switch (state) {
	case PM_SUSPEND_MEM:
		cpu_suspend(PWRMODE_SLEEP, pxa25x_finish_suspend);
		break;
	}
}

static int pxa25x_cpu_pm_prepare(void)
{
	/* set resume return address */
	PSPR = __pa_symbol(cpu_resume);
	return 0;
}

static void pxa25x_cpu_pm_finish(void)
{
	/* ensure not to come back here if it wasn't intended */
	PSPR = 0;
}

static struct pxa_cpu_pm_fns pxa25x_cpu_pm_fns = {
	.save_count	= SLEEP_SAVE_COUNT,
	.valid		= suspend_valid_only_mem,
	.save		= pxa25x_cpu_pm_save,
	.restore	= pxa25x_cpu_pm_restore,
	.enter		= pxa25x_cpu_pm_enter,
	.prepare	= pxa25x_cpu_pm_prepare,
	.finish		= pxa25x_cpu_pm_finish,
};

static void __init pxa25x_init_pm(void)
{
	pxa_cpu_pm_fns = &pxa25x_cpu_pm_fns;
}
#else
static inline void pxa25x_init_pm(void) {}
#endif

/* PXA25x: supports wakeup from GPIO0..GPIO15 and RTC alarm
 */

static int pxa25x_set_wake(struct irq_data *d, unsigned int on)
{
	int gpio = pxa_irq_to_gpio(d->irq);
	uint32_t mask = 0;

	if (gpio >= 0 && gpio < 85)
		return gpio_set_wake(gpio, on);

	if (d->irq == IRQ_RTCAlrm) {
		mask = PWER_RTC;
		goto set_pwer;
	}

	return -EINVAL;

set_pwer:
	if (on)
		PWER |= mask;
	else
		PWER &=~mask;

	return 0;
}

void __init pxa25x_init_irq(void)
{
	pxa_init_irq(32, pxa25x_set_wake);
	set_handle_irq(pxa25x_handle_irq);
}

static int __init __init
pxa25x_dt_init_irq(struct device_node *node, struct device_node *parent)
{
	pxa_dt_irq_init(pxa25x_set_wake);
	set_handle_irq(icip_handle_irq);

	return 0;
}
IRQCHIP_DECLARE(pxa25x_intc, "marvell,pxa-intc", pxa25x_dt_init_irq);

static struct map_desc pxa25x_io_desc[] __initdata = {
	{	/* Mem Ctl */
		.virtual	= (unsigned long)SMEMC_VIRT,
		.pfn		= __phys_to_pfn(PXA2XX_SMEMC_BASE),
		.length		= SMEMC_SIZE,
		.type		= MT_DEVICE
	}, {	/* UNCACHED_PHYS_0 */
		.virtual	= UNCACHED_PHYS_0,
		.pfn		= __phys_to_pfn(0x00000000),
		.length		= UNCACHED_PHYS_0_SIZE,
		.type		= MT_DEVICE
	},
};

void __init pxa25x_map_io(void)
{
	pxa_map_io();
	iotable_init(ARRAY_AND_SIZE(pxa25x_io_desc));
	pxa25x_get_clk_frequency_khz(1);
}

static int __init pxa25x_init(void)
{
	int ret = 0;

	if (cpu_is_pxa25x()) {

		pxa_register_wdt(RCSR);

		pxa25x_init_pm();

		register_syscore(&pxa_irq_syscore);
		register_syscore(&pxa2xx_mfp_syscore);
	}

	return ret;
}

postcore_initcall(pxa25x_init);
