// SPDX-License-Identifier: GPL-2.0
#include <linux/init.h>
#include <linux/platform_device.h>

#include "irqs.h"
#include "regs-ost.h"
#include "reset.h"

void __init pxa_register_wdt(unsigned int reset_status)
{
	struct resource res = DEFINE_RES_MEM(OST_PHYS, OST_LEN);

	reset_status &= RESET_STATUS_WATCHDOG;
	platform_device_register_resndata(NULL, "sa1100_wdt", -1, &res, 1,
					  &reset_status, sizeof(reset_status));
}
