// SPDX-License-Identifier: GPL-2.0

/*
 * Include usdt.h with the extra info in usdt probe and
 * nop/nop5 combo for usdt attach point.
 */
#include "usdt.h"

__attribute__((aligned(16)))
void usdt_2(void)
{
	USDT(optimized_attach, usdt_2);
}
