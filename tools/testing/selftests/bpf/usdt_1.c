// SPDX-License-Identifier: GPL-2.0

/*
 * Include usdt.h with defined USDT_NOP macro will switch
 * off the extra info in usdt probe.
 */
#define USDT_NOP .byte 0x90, 0x0f, 0x1f, 0x44, 0x00, 0x00
#include "usdt.h"

__attribute__((aligned(16)))
void usdt_1(void)
{
	USDT(optimized_attach, usdt_1);
}
