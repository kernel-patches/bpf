// SPDX-License-Identifier: GPL-2.0-only
/*
 * Delay loops based on the OpenRISC implementation.
 *
 * Copyright (C) 2012 ARM Limited
 *
 * Author: Will Deacon <will.deacon@arm.com>
 */

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/timex.h>
#include <asm/delay-const.h>

#include <clocksource/arm_arch_timer.h>

void __delay(unsigned long cycles)
{
	cycles_t start = get_cycles();

	if (alternative_has_cap_unlikely(ARM64_HAS_WFXT)) {
		u64 end = start + cycles;

		/*
		 * Start with WFIT. If an interrupt makes us resume
		 * early, use a WFET loop to complete the delay.
		 */
		wfit(end);
		while ((get_cycles() - start) < cycles)
			wfet(end);
	} else 	if (arch_timer_evtstrm_available()) {
		const cycles_t timer_evt_period =
			USECS_TO_CYCLES(ARCH_TIMER_EVT_STREAM_PERIOD_US);

		while ((get_cycles() - start + timer_evt_period) < cycles)
			wfe();
	}

	while ((get_cycles() - start) < cycles)
		cpu_relax();
}
EXPORT_SYMBOL(__delay);

inline void __const_udelay(unsigned long xloops)
{
	__delay(xloops_to_cycles(xloops));
}
EXPORT_SYMBOL(__const_udelay);

void __udelay(unsigned long usecs)
{
	__const_udelay(usecs * __usecs_to_xloops_mult);
}
EXPORT_SYMBOL(__udelay);

void __ndelay(unsigned long nsecs)
{
	__const_udelay(nsecs * __nsecs_to_xloops_mult);
}
EXPORT_SYMBOL(__ndelay);
