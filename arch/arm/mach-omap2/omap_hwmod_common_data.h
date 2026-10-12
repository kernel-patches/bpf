/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * omap_hwmod_common_data.h - OMAP hwmod common macros and declarations
 *
 * Copyright (C) 2010-2011 Nokia Corporation
 * Copyright (C) 2010-2012 Texas Instruments, Inc.
 * Paul Walmsley
 * Benoît Cousson
 */
#ifndef __ARCH_ARM_MACH_OMAP2_OMAP_HWMOD_COMMON_DATA_H
#define __ARCH_ARM_MACH_OMAP2_OMAP_HWMOD_COMMON_DATA_H

#include "omap_hwmod.h"

#include "common.h"
#include "display.h"

/* OMAP hwmod classes - forward declarations */
extern struct omap_hwmod_class l3_hwmod_class;
extern struct omap_hwmod_class l4_hwmod_class;
extern struct omap_hwmod_class mpu_hwmod_class;
extern struct omap_hwmod_class iva_hwmod_class;
extern struct omap_hwmod_class omap2_uart_class;
extern struct omap_hwmod_class omap2_dss_hwmod_class;
extern struct omap_hwmod_class omap2_rfbi_hwmod_class;
extern struct omap_hwmod_class omap2_venc_hwmod_class;
extern struct omap_hwmod_class omap2_hdq1w_class;

extern struct omap_dss_dispc_dev_attr omap2_3_dss_dispc_dev_attr;

#endif
