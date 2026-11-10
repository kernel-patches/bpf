// SPDX-License-Identifier: GPL-2.0-only
/* Copyright Altera Corporation (C) 2026. All rights reserved.
 */

#include <linux/libgcc.h>
#include <linux/export.h>
#include <linux/types.h>

s32 __mulsi3(s32 a, s32 b)
{
	s32 res = 0;
	u32 cnt = a;

	while (cnt) {
		if (cnt & 1)
			res += b;

		b <<= 1;
		cnt >>= 1;
	}

	return res;
}
EXPORT_SYMBOL(__mulsi3);
