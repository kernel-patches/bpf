// SPDX-License-Identifier: GPL-2.0-only
/* Copyright Altera Corporation (C) 2026. All rights reserved.
 */

#include <linux/libgcc.h>
#include <linux/export.h>
#include <linux/types.h>

static u32 udivmodsi4(u32 num, u32 den, int modwanted)
{
	u32 bit = 1;
	u32 res = 0;

	while (den < num && bit && !(den & (1U << 31))) {
		den <<= 1;
		bit <<= 1;
	}

	while (bit) {
		if (num >= den) {
			num -= den;
			res |= bit;
		}
		bit >>= 1;
		den >>= 1;
	}

	return modwanted ? num : res;
}


#ifdef CONFIG_GENERIC_LIB_DIVSI3
s32 __divsi3(s32 a, s32 b)
{
	int neg = 0;
	s32 res;

	if (a < 0) {
		a = -a;
		neg = !neg;
	}

	if (b < 0) {
		b = -b;
		neg = !neg;
	}

	res = udivmodsi4(a, b, 0);
	if (neg)
		res = -res;

	return res;
}
EXPORT_SYMBOL(__divsi3);
#endif

#ifdef CONFIG_GENERIC_LIB_MODSI3
s32 __modsi3(s32 a, s32 b)
{
	int neg = 0;
	s32 res;

	if (a < 0) {
		a = -a;
		neg = 1;
	}

	if (b < 0)
		b = -b;

	res = udivmodsi4(a, b, 1);
	if (neg)
		res = -res;

	return res;
}
EXPORT_SYMBOL(__modsi3);
#endif

#ifdef CONFIG_GENERIC_LIB_UDIVSI3
u32 __udivsi3(u32 a, u32 b)
{
	return udivmodsi4(a, b, 0);
}
EXPORT_SYMBOL(__udivsi3);
#endif

#ifdef CONFIG_GENERIC_LIB_UMODSI3
u32 __umodsi3(u32 a, u32 b)
{
	return udivmodsi4(a, b, 1);
}
EXPORT_SYMBOL(__umodsi3);
#endif
