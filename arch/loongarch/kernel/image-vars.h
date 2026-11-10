/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef __LOONGARCH_KERNEL_IMAGE_VARS_H
#define __LOONGARCH_KERNEL_IMAGE_VARS_H

#ifdef CONFIG_EFI_STUB

__efistub_strcmp		= strcmp;

#endif

#endif /* __LOONGARCH_KERNEL_IMAGE_VARS_H */
