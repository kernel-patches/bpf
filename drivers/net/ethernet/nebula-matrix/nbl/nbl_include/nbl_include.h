/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Nebula Matrix Limited.
 */

#ifndef _NBL_INCLUDE_H_
#define _NBL_INCLUDE_H_

#include <linux/types.h>

/*  ------  Basic definitions  -------  */
#define NBL_DRIVER_NAME					"nbl"
#define NBL_MAX_PF					8
/* Chip-wide VF budget shared across all PFs */
#define NBL_MAX_VF					512
#define NBL_NEXT_ID(id, max) (((id) + 1) % ((max) + 1))

/* Total PCI functions: PFs plus the chip-wide VF budget */
#define NBL_MAX_FUNC			(NBL_MAX_PF + NBL_MAX_VF)
#define NBL_MAX_ETHERNET				4

enum {
	NBL_VSI_DATA = 0,
};

struct nbl_func_caps {
	u32 has_ctrl:1;
	u32 has_net:1;
	u32 rsv:30;
};

struct nbl_init_param {
	struct nbl_func_caps caps;
};

/*
 * Firmware ABI defines port speed enum fixed, value 0 represents 10G, cannot
 * reassign 0 to INVALID for compatibility
 */
enum nbl_fw_port_speed {
	NBL_FW_PORT_SPEED_10G,
	NBL_FW_PORT_SPEED_25G,
	NBL_FW_PORT_SPEED_50G,
	NBL_FW_PORT_SPEED_100G,
};

/*
 * Firmware quirk word @ NBL_LEONIS_QUIRKS_OFFSET (0x140)
 * Sentinel value: ~0U (0xFFFFFFFF) = firmware reports no active quirks
 * BIT(1): NBL_QUIRK_UVN_PREFETCH_ALIGN – control UVN descriptor prefetch
 * selection
 */
#define NBL_QUIRK_UVN_PREFETCH_ALIGN	BIT(1)

#endif
