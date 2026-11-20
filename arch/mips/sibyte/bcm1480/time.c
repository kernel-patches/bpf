// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2000,2001,2004 Broadcom Corporation
 */
#include <linux/init.h>

#include <asm/time.h>
#include <asm/sibyte/sb1250.h>

void __init plat_time_init(void)
{
	sb1480_clocksource_init();
	sb1480_clockevent_init();
}
