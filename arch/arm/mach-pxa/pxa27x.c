// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/arch/arm/mach-pxa/pxa27x.c
 *
 *  Author:	Nicolas Pitre
 *  Created:	Nov 05, 2002
 *  Copyright:	MontaVista Software Inc.
 *
 * Code specific to PXA27x aka Bulverde.
 */
#include <linux/dmaengine.h>
#include <linux/dma/pxa-dma.h>
#include <linux/gpio/consumer.h>
#include <linux/gpio-pxa.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/irqchip.h>
#include <linux/suspend.h>
#include <linux/platform_device.h>
#include <linux/syscore_ops.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/soc/pxa/cpu.h>
#include <linux/soc/pxa/smemc.h>

#include <asm/mach/map.h>
#include <asm/irq.h>
#include <asm/suspend.h>
#include "irqs.h"
#include "pxa27x.h"
#include "reset.h"
#include <linux/platform_data/pxa2xx_udc.h>
#include <linux/platform_data/asoc-pxa.h>
#include "pm.h"
#include "addr-map.h"
#include "smemc.h"

#include "generic.h"
#include <linux/clk-provider.h>
#include <linux/clkdev.h>

void pxa27x_clear_otgph(void)
{
	if (cpu_is_pxa27x() && (PSSR & PSSR_OTGPH))
		PSSR |= PSSR_OTGPH;
}
EXPORT_SYMBOL(pxa27x_clear_otgph);

static unsigned long ac97_reset_config[] = {
	GPIO113_AC97_nRESET_GPIO_HIGH,
	GPIO113_AC97_nRESET,
	GPIO95_AC97_nRESET_GPIO_HIGH,
	GPIO95_AC97_nRESET,
};

void pxa27x_configure_ac97reset(struct gpio_desc *gpiod, bool to_gpio)
{
	int reset_gpio;

	if (!gpiod)
		return;

	reset_gpio = desc_to_gpio(gpiod);

	/*
	 * This helper function is used to work around a bug in the pxa27x's
	 * ac97 controller during a warm reset.  The configuration of the
	 * reset_gpio is changed as follows:
	 * to_gpio == true: configured to generic output gpio and driven high
	 * to_gpio == false: configured to ac97 controller alt fn AC97_nRESET
	 */

	if (reset_gpio == 113)
		pxa2xx_mfp_config(to_gpio ? &ac97_reset_config[0] :
				  &ac97_reset_config[1], 1);

	if (reset_gpio == 95)
		pxa2xx_mfp_config(to_gpio ? &ac97_reset_config[2] :
				  &ac97_reset_config[3], 1);
}
EXPORT_SYMBOL_GPL(pxa27x_configure_ac97reset);

#ifdef CONFIG_PM

#define SAVE(x)		sleep_save[SLEEP_SAVE_##x] = x
#define RESTORE(x)	x = sleep_save[SLEEP_SAVE_##x]

/*
 * allow platforms to override default PWRMODE setting used for PM_SUSPEND_MEM
 */
static unsigned int pwrmode = PWRMODE_SLEEP;

/*
 * List of global PXA peripheral registers to preserve.
 * More ones like CP and general purpose register values are preserved
 * with the stack pointer in sleep.S.
 */
enum {
	SLEEP_SAVE_PSTR,
	SLEEP_SAVE_MDREFR,
	SLEEP_SAVE_PCFR,
	SLEEP_SAVE_COUNT
};

static void pxa27x_cpu_pm_save(unsigned long *sleep_save)
{
	sleep_save[SLEEP_SAVE_MDREFR] = __raw_readl(MDREFR);
	SAVE(PCFR);

	SAVE(PSTR);
}

static void pxa27x_cpu_pm_restore(unsigned long *sleep_save)
{
	__raw_writel(sleep_save[SLEEP_SAVE_MDREFR], MDREFR);
	RESTORE(PCFR);

	PSSR = PSSR_RDH | PSSR_PH;

	RESTORE(PSTR);
}

static void pxa27x_cpu_pm_enter(suspend_state_t state)
{
	extern void pxa_cpu_standby(void);
#ifndef CONFIG_IWMMXT
	u64 acc0;

#ifndef CONFIG_AS_IS_LLVM
	asm volatile(".arch_extension xscale\n\t"
		     "mra %Q0, %R0, acc0" : "=r" (acc0));
#else
	asm volatile("mrrc p0, 0, %Q0, %R0, c0" : "=r" (acc0));
#endif
#endif

	/* ensure voltage-change sequencer not initiated, which hangs */
	PCFR &= ~PCFR_FVC;

	/* Clear edge-detect status register. */
	PEDR = 0xDF12FE1B;

	/* Clear reset status */
	RCSR = RCSR_HWR | RCSR_WDR | RCSR_SMR | RCSR_GPR;

	switch (state) {
	case PM_SUSPEND_STANDBY:
		pxa_cpu_standby();
		break;
	case PM_SUSPEND_MEM:
		cpu_suspend(pwrmode, pxa27x_finish_suspend);
#ifndef CONFIG_IWMMXT
#ifndef CONFIG_AS_IS_LLVM
		asm volatile(".arch_extension xscale\n\t"
			     "mar acc0, %Q0, %R0" : "=r" (acc0));
#else
		asm volatile("mcrr p0, 0, %Q0, %R0, c0" :: "r" (acc0));
#endif
#endif
		break;
	}
}

static int pxa27x_cpu_pm_valid(suspend_state_t state)
{
	return state == PM_SUSPEND_MEM || state == PM_SUSPEND_STANDBY;
}

static int pxa27x_cpu_pm_prepare(void)
{
	/* set resume return address */
	PSPR = __pa_symbol(cpu_resume);
	return 0;
}

static void pxa27x_cpu_pm_finish(void)
{
	/* ensure not to come back here if it wasn't intended */
	PSPR = 0;
}

static struct pxa_cpu_pm_fns pxa27x_cpu_pm_fns = {
	.save_count	= SLEEP_SAVE_COUNT,
	.save		= pxa27x_cpu_pm_save,
	.restore	= pxa27x_cpu_pm_restore,
	.valid		= pxa27x_cpu_pm_valid,
	.enter		= pxa27x_cpu_pm_enter,
	.prepare	= pxa27x_cpu_pm_prepare,
	.finish		= pxa27x_cpu_pm_finish,
};

static void __init pxa27x_init_pm(void)
{
	pxa_cpu_pm_fns = &pxa27x_cpu_pm_fns;
}
#else
static inline void pxa27x_init_pm(void) {}
#endif

/* PXA27x:  Various gpios can issue wakeup events.  This logic only
 * handles the simple cases, not the WEMUX2 and WEMUX3 options
 */
static int pxa27x_set_wake(struct irq_data *d, unsigned int on)
{
	int gpio = pxa_irq_to_gpio(d->irq);
	uint32_t mask;

	if (gpio >= 0 && gpio < 128)
		return gpio_set_wake(gpio, on);

	if (d->irq == IRQ_KEYPAD)
		return keypad_set_wake(on);

	switch (d->irq) {
	case IRQ_RTCAlrm:
		mask = PWER_RTC;
		break;
	case IRQ_USB:
		mask = 1u << 26;
		break;
	default:
		return -EINVAL;
	}

	if (on)
		PWER |= mask;
	else
		PWER &=~mask;

	return 0;
}

void __init pxa27x_init_irq(void)
{
	pxa_init_irq(34, pxa27x_set_wake);
	set_handle_irq(pxa27x_handle_irq);
}

static int __init
pxa27x_dt_init_irq(struct device_node *node, struct device_node *parent)
{
	pxa_dt_irq_init(pxa27x_set_wake);
	set_handle_irq(ichp_handle_irq);

	return 0;
}
IRQCHIP_DECLARE(pxa27x_intc, "marvell,pxa-intc", pxa27x_dt_init_irq);

static struct map_desc pxa27x_io_desc[] __initdata = {
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

void __init pxa27x_map_io(void)
{
	pxa_map_io();
	iotable_init(ARRAY_AND_SIZE(pxa27x_io_desc));
	pxa27x_get_clk_frequency_khz(1);
}

static int __init pxa27x_init(void)
{
	int ret = 0;

	if (cpu_is_pxa27x()) {
		pxa_register_wdt(RCSR);

		pxa27x_init_pm();

		register_syscore(&pxa_irq_syscore);
		register_syscore(&pxa2xx_mfp_syscore);
	}

	return ret;
}

postcore_initcall(pxa27x_init);
