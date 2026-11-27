/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright(c) 2026  Realtek Corporation
 * Copyright(c) Michael Straube <straube.linux@gmail.com>
 * Copyright(c) 2024-2026 Luka Gejak <luka.gejak@linux.dev>
 */

#ifndef __RTW8723B_H__
#define __RTW8723B_H__

#include "rtw8723x.h"

enum rtw8723b_package_type {
	RTW8723B_PACKAGE_DEFAULT,
	RTW8723B_PACKAGE_QFN68,
	RTW8723B_PACKAGE_TFBGA90,
	RTW8723B_PACKAGE_TFBGA80,
	RTW8723B_PACKAGE_TFBGA79,
};

#define RTW8723B_EFUSE_PACKAGE_TYPE	0x1fb
#define RTW8723B_PACKAGE_TYPE_MASK	GENMASK(2, 0)
#define RTW8723B_VARIANT_MASK		GENMASK(5, 4)
#define RTW8723B_VARIANT_8723BS		0x3
#define RTW8723B_VARIANT_8703AS		0x2

extern const struct rtw_chip_info rtw8723b_hw_spec;

#endif
