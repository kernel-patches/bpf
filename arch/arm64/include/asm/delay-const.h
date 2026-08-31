/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASM_DELAY_CONST_H
#define _ASM_DELAY_CONST_H

#include <linux/math64.h>
#include <linux/types.h>
#include <asm/param.h>	/* For HZ */

/* 2**32 / 1000000 (rounded up) */
#define __usecs_to_xloops_mult	0x10C7UL

/* 2**32 / 1000000000 (rounded up) */
#define __nsecs_to_xloops_mult	0x5UL

extern unsigned long loops_per_jiffy;
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
	return xloops_to_cycles((time_nsecs) * __nsecs_to_xloops_mult);
}

u64 notrace __delay_cycles(void);

#endif	/* _ASM_DELAY_CONST_H */
