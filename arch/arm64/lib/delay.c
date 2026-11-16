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
#include <linux/math64.h>
#include <linux/types.h>
#include <asm/param.h>

#include <clocksource/arm_arch_timer.h>

/* 2**32 / 1000000 (rounded up) */
#define __usecs_to_xloops_mult	0x10C7UL

/* 2**32 / 1000000000 (rounded up) */
#define __nsecs_to_xloops_mult	0x5UL

static inline u64 xloops_to_cycles(u64 xloops)
{
	u64 loops_per_sec = (u64)loops_per_jiffy * HZ;

	return mul_u64_u64_shr(xloops, loops_per_sec, 32);
}

static inline u64 usecs_to_cycles(u64 time_usecs)
{
	return xloops_to_cycles(time_usecs * __usecs_to_xloops_mult);
}

static inline u64 nsecs_to_cycles(u64 time_nsecs)
{
	return xloops_to_cycles(time_nsecs * __nsecs_to_xloops_mult);
}

/*
 * Force the use of CNTVCT_EL0 in order to have the same base as WFxT.
 * This avoids some annoying issues when CNTVOFF_EL2 is not reset 0 on a
 * KVM host running at EL1 until we do a vcpu_put() on the vcpu. When
 * running at EL2, the effective offset is always 0.
 *
 * Note that userspace cannot change the offset behind our back either,
 * as the vcpu mutex is held as long as KVM_RUN is in progress.
 */
static cycles_t notrace __delay_cycles(void)
{
	guard(preempt_notrace)();
	return __arch_counter_get_cntvct_stable();
}

void __delay(unsigned long cycles)
{
	cycles_t start = __delay_cycles();

	if (alternative_has_cap_unlikely(ARM64_HAS_WFXT)) {
		u64 end = start + cycles;

		/*
		 * Start with WFIT. If an interrupt makes us resume
		 * early, use a WFET loop to complete the delay.
		 */
		wfit(end);
		while ((__delay_cycles() - start) < cycles)
			wfet(end);
	} else 	if (arch_timer_evtstrm_available()) {
		const cycles_t timer_evt_period =
			usecs_to_cycles(ARCH_TIMER_EVT_STREAM_PERIOD_US);

		while ((__delay_cycles() - start + timer_evt_period) < cycles)
			wfe();
	}

	while ((__delay_cycles() - start) < cycles)
		cpu_relax();
}
EXPORT_SYMBOL(__delay);

u64 arm64_wfet_deadline(u64 timeout_ns)
{
	return __delay_cycles() + nsecs_to_cycles(timeout_ns);
}
EXPORT_SYMBOL_GPL(arm64_wfet_deadline);

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
